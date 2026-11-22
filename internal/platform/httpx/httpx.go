// Package httpx writes JSON responses and the single error format
// { "error": { "code": "...", "message": "..." } } of the contract, and reads
// JSON request bodies.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
)

// MaxBodyBytes bounds every JSON request body.
const MaxBodyBytes = 16 << 10

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("write json", "err", err)
	}
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func Error(w http.ResponseWriter, status int, code, message string) {
	var b errorBody
	b.Error.Code = code
	b.Error.Message = message
	JSON(w, status, b)
}

// Validation answers 400 VALIDATION_ERROR.
func Validation(w http.ResponseWriter, message string) {
	Error(w, http.StatusBadRequest, "VALIDATION_ERROR", message)
}

// Internal logs err and answers 500 without leaking details to the client.
func Internal(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "internal error",
		"request_id", RequestID(r.Context()), "path", r.URL.Path, "err", err)
	Error(w, http.StatusInternalServerError, "INTERNAL", "Internal error")
}

// Decode reads one JSON object into dst. ok is false (and a 400 already
// written) when the body is missing, too large or not valid JSON.
func Decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	err := dec.Decode(dst)
	if err == nil {
		// Only one JSON value is allowed in the body.
		if _, extra := dec.Token(); !errors.Is(extra, io.EOF) {
			err = errors.New("trailing data")
		}
	}
	if err == nil {
		return true
	}

	var tooLarge *http.MaxBytesError
	var badType *json.UnmarshalTypeError
	switch {
	case errors.As(err, &tooLarge):
		Validation(w, "request body too large")
	case errors.As(err, &badType) && badType.Field != "":
		Validation(w, "invalid type for field "+badType.Field)
	case errors.Is(err, io.EOF):
		Validation(w, "request body is required")
	default:
		Validation(w, "request body must be a JSON object")
	}
	return false
}

// IntQuery reads an integer query parameter, with a default and bounds.
// ok is false (and a 400 already written) when the value is invalid.
func IntQuery(w http.ResponseWriter, r *http.Request, name string, def, min, max int) (int, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		Validation(w, name+" must be an integer between "+strconv.Itoa(min)+" and "+strconv.Itoa(max))
		return 0, false
	}
	return n, true
}

type requestIDKey struct{}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID is the X-Request-Id of the current request, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
