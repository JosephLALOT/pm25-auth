# pm25-auth: one static binary, "serve" by default.
#   docker run pm25-auth                 HTTP service on :8001
#   docker run pm25-auth purge           daily purge of expired refresh tokens
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pm25-auth ./cmd/pm25-auth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pm25-auth /app/pm25-auth
ENV HTTP_ADDR=:8001
EXPOSE 8001
ENTRYPOINT ["/app/pm25-auth"]
CMD ["serve"]
