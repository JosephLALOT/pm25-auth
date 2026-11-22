# pm25-auth

Authentication service of the PM2.5 platform. It owns the user accounts (schema `auth` of the database `pm25`), issues the access and refresh tokens, and publishes the public keys that `pm25-api` uses to verify access tokens.

- Contract: [`contracts/openapi.yaml`](contracts/openapi.yaml)
- Decisions: ADR 0004, 0008 and 0009, and section 7 of `docs/architecture/ARCHITECTURE.md` in `pm25-platform`

## Endpoints

Base URL `https://pm25-auth.alwaysdata.net/api/v1`, locally `http://localhost:8001/api/v1`.

| Method | Path | Access | |
|---|---|---|---|
| GET | `/health` | public | `200 ok` or `503 down`, database reachable, active `kid` |
| POST | `/auth/register` | public | Create an account (role `user`) |
| POST | `/auth/login` | public | Access token (EdDSA JWT, 15 min) + refresh token (7 days) |
| POST | `/auth/refresh` | public | Rotate the refresh token, new pair |
| POST | `/auth/logout` | public | Revoke the refresh token, always `204` |
| GET | `/me` | user | Current user |
| GET | `/admin/users` | admin | Paginated list, filter `?ids=` |
| PATCH | `/admin/users/{id}` | admin | Change `role` / `is_active`, audited in `public.audit_event` |
| GET | `/.well-known/jwks.json` | public | Public keys, outside `/api/v1`, `Cache-Control: public, max-age=300` |

Every route except `/health` and the JWKS is rate limited per client IP.

## Commands

```bash
pm25-auth serve                                   # HTTP service
pm25-auth purge                                   # deletes refresh tokens expired for 7 days (task, 03:10 UTC)
pm25-auth create-admin --email admin@example.com --display-name "Admin"
pm25-auth signing-key generate                    # new Ed25519 key, its public key and a suggested kid
```

`create-admin` asks the password twice on a terminal, or reads the first line of stdin (`printf '%s\n' "$PASSWORD" | pm25-auth create-admin ...`). Admins are never created through the API.

## Configuration

Environment variables, see [`.env.example`](.env.example).

| Variable | Default | |
|---|---|---|
| `HTTP_ADDR` | `:8001` | Without it, `$IP:$PORT` of the alwaysdata site |
| `DATABASE_URL` | required | User `pm25_auth` |
| `DB_MAX_CONNS` | `3` | |
| `JWT_SIGNING_KEY` | random key | Base64 of the 32-byte Ed25519 seed. Without it a development key is generated at each start (tokens become invalid at restart) |
| `JWT_SIGNING_KID` | | Required with `JWT_SIGNING_KEY` |
| `JWT_PREVIOUS_PUBLIC_KEYS` | | `kid:base64,...`, earlier keys still published during a rotation |
| `JWT_ISSUER` | `http://localhost:8001` | `iss` claim, the same value as `JWT_ISSUER` of the API |
| `JWT_AUDIENCE` | `pm25-api` | `aud` claim |
| `ACCESS_TOKEN_TTL` / `REFRESH_TOKEN_TTL` | `15m` / `168h` | |
| `CORS_ORIGINS` | `http://localhost:4200` | Comma-separated |
| `RATE_LIMIT_RPS` / `RATE_LIMIT_BURST` | `2` / `10` | Per client IP |
| `TRUST_PROXY` | `false` | `true` behind the alwaysdata proxy: client IP from `X-Forwarded-For` |
| `LOG_LEVEL` | `info` | |

## Run locally

With Docker, from `pm25-platform/deploy` (the three repositories cloned side by side):

```bash
docker compose --profile auth up --build -d
curl http://localhost:8001/api/v1/health
docker compose run --rm auth create-admin --email admin@example.com < password.txt
```

The `migrate-auth` service applies `db/migrations` with the history table `auth_schema_migrations`, then `roles.sql` grants the privileges of `pm25_auth`.

Without Docker, against an existing database that has the `auth` schema:

```bash
set -a; . ./.env; set +a
go run ./cmd/pm25-auth serve
```

## Database migrations

`db/migrations` holds the `auth` schema only, for [golang-migrate](https://github.com/golang-migrate/migrate), applied as the owner user with its own history table:

```bash
migrate -path db/migrations -database "$OWNER_DATABASE_URL&x-migrations-table=auth_schema_migrations" up
```

Then run `db/roles.sql` of `pm25-platform` again. A migration on `main` is never edited: a change is a new file.

## Signing key rotation

1. `pm25-auth signing-key generate`.
2. Set the new `JWT_SIGNING_KEY` / `JWT_SIGNING_KID`, move the old public key to `JWT_PREVIOUS_PUBLIC_KEYS` (`oldkid:base64`), restart. The API refetches the JWKS when it sees the new `kid`.
3. After 15 minutes, remove the old key from `JWT_PREVIOUS_PUBLIC_KEYS` and restart.

After a leak: remove the old key at once and restart the API as well.

## Tests

```bash
go test ./...                                     # unit and HTTP tests, in memory
TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/pm25_test?sslmode=disable go test ./...
```

With `TEST_DATABASE_URL`, the repositories of `internal/model` are also tested against PostgreSQL. Use an empty, throw-away database: the tests drop and recreate the `auth` schema. Without Go installed:

```bash
docker run --rm -v "$PWD:/src" -w /src golang:1.26-alpine go test ./...
```

## Layout

```
cmd/pm25-auth/        serve, purge, create-admin, signing-key
internal/
  platform/           config, database, httpx (JSON, errors), middleware (request id, log, CORS, rate limit)
  model/              M: users and refresh tokens, PostgreSQL repositories (auth schema only)
  view/               V: JSON representations of the contract
  controller/         C: HTTP handlers, token checks, error mapping
  service/            registration, login, refresh rotation, user admin, argon2id, signing keys, JWKS
  audit/              append-only writer to public.audit_event
  memstore/           in-memory stores with the same rules, for tests
db/migrations/        auth schema
contracts/            OpenAPI contract
```
