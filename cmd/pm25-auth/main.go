// Command pm25-auth is the authentication service of the PM2.5 platform
// (ADR 0009 of pm25-platform).
//
//	pm25-auth serve                     HTTP endpoints (contracts/openapi.yaml)
//	pm25-auth purge                     delete refresh tokens expired for 7 days (daily task)
//	pm25-auth create-admin --email ...  create an admin account (over SSH, never through the API)
//	pm25-auth signing-key generate      print a new Ed25519 signing key
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"pm25/auth/internal/controller"
	"pm25/auth/internal/model"
	"pm25/auth/internal/platform/config"
	"pm25/auth/internal/platform/database"
	"pm25/auth/internal/platform/middleware"
	"pm25/auth/internal/service"
)

const usage = `Usage:
  pm25-auth serve
  pm25-auth purge
  pm25-auth create-admin --email <e-mail> --display-name <name>   (password read from the terminal or stdin)
  pm25-auth signing-key generate
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "serve":
		err = serve()
	case "purge":
		err = purge()
	case "create-admin":
		err = createAdmin(args)
	case "signing-key":
		if len(args) != 1 || args[0] != "generate" {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		err = generateKey(os.Stdout)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		slog.Error(os.Args[1]+" failed", "err", err)
		os.Exit(1)
	}
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	setupLogger(cfg.LogLevel)

	keys, err := loadKeys(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.Open(ctx, cfg.DatabaseURL, cfg.DBMaxConns)
	if err != nil {
		return err
	}
	defer pool.Close()

	issuer := service.NewTokenIssuer(keys, cfg.Issuer, cfg.Audience, cfg.AccessTTL)
	svc := service.New(model.NewUsers(pool), model.NewRefreshTokens(pool), issuer, service.DefaultHasher, cfg.RefreshTTL)
	limiter := middleware.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst, cfg.TrustProxy)
	ctrl := controller.New(svc, issuer, keys, pool.Ping, limiter.Wrap)

	mux := http.NewServeMux()
	ctrl.Routes(mux)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           middleware.Chain(mux, middleware.RequestLog, middleware.Recover, middleware.CORS(cfg.CORSOrigins)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", cfg.HTTPAddr, "kid", keys.KID(), "issuer", cfg.Issuer)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
	return nil
}

// loadKeys decodes the signing keys. Without JWT_SIGNING_KEY a random key is
// used: fine for local development, but every restart then invalidates the
// access tokens already issued.
func loadKeys(cfg config.Config) (*service.KeySet, error) {
	if cfg.SigningKey != "" {
		return service.NewKeySet(cfg.SigningKey, cfg.SigningKID, cfg.PreviousPublicKeys)
	}
	keys, err := service.EphemeralKeySet()
	if err != nil {
		return nil, err
	}
	slog.Warn("JWT_SIGNING_KEY is not set: using a random development key, lost at restart (never do this in production)",
		"kid", keys.KID())
	return keys, nil
}

func purge() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	setupLogger(cfg.LogLevel)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	pool, err := database.Open(ctx, cfg.DatabaseURL, 1)
	if err != nil {
		return err
	}
	defer pool.Close()

	n, err := model.NewRefreshTokens(pool).Purge(ctx)
	if err != nil {
		return err
	}
	slog.Info("purge finished", "deleted_refresh_tokens", n)
	return nil
}

func createAdmin(args []string) error {
	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	email := fs.String("email", "", "e-mail of the admin (required)")
	name := fs.String("display-name", "Admin", "name shown in the back-office")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("--email is required")
	}

	password, err := readPassword(os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	if err := service.ValidatePassword(password); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	setupLogger(cfg.LogLevel)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	pool, err := database.Open(ctx, cfg.DatabaseURL, 1)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Creating an account needs no signing key.
	svc := service.New(model.NewUsers(pool), model.NewRefreshTokens(pool), nil, service.DefaultHasher, cfg.RefreshTTL)
	u, err := svc.CreateAdmin(ctx, *email, password, *name)
	if errors.Is(err, service.ErrEmailTaken) {
		return fmt.Errorf("an account already uses %s", service.NormalizeEmail(*email))
	}
	if err != nil {
		return err
	}
	fmt.Printf("admin created: id=%s email=%s\n", u.ID, u.Email)
	return nil
}

// readPassword asks twice without echo on a terminal, or reads the first line
// of stdin otherwise (for scripts: printf '%s\n' "$PASSWORD" | pm25-auth create-admin ...).
func readPassword(in *os.File, prompt io.Writer) (string, error) {
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(prompt, "Password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(prompt)
	if err != nil {
		return "", err
	}
	fmt.Fprint(prompt, "Repeat password: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(prompt)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("the passwords do not match")
	}
	return string(first), nil
}

func generateKey(out io.Writer) error {
	k, err := service.GenerateSigningKey(time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, `# New Ed25519 signing key (ADR 0008). Keep JWT_SIGNING_KEY secret.
JWT_SIGNING_KEY=%s
JWT_SIGNING_KID=%s

# Public key, for JWT_PREVIOUS_PUBLIC_KEYS at the next rotation:
#   %s:%s
`, k.Seed, k.KID, k.KID, k.PublicKey)
	return nil
}

func setupLogger(level string) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l})))
}
