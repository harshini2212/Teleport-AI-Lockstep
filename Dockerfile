# syntax=docker/dockerfile:1
#
# Production image for the Lifecycle Guard console (the /go server + /dashboard).
# The Go module is rooted at ./go and depends only on the standard library, so
# there is nothing to download — we just compile ./cmd/server and ship a tiny
# Alpine runtime with CA certs (the access-review copilot calls the Anthropic
# API over TLS). Railway auto-detects this Dockerfile at the repo root.

# ---- build stage ----
FROM golang:1.22-alpine AS build
WORKDIR /src/go
COPY go/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /server ./cmd/server

# ---- run stage ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /server ./server
COPY dashboard/ ./dashboard/
# No -addr: the server reads $PORT (injected by Railway) and binds 0.0.0.0:$PORT.
# ANTHROPIC_API_KEY, if set in the platform's Variables, enables the AI copilot.
CMD ["./server", "-dashboard", "./dashboard"]
