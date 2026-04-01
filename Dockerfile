# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Build scanner binaries
#   Builds both the CLI scanner and the web UI server.
#   Uses CGO_ENABLED=0 for fully static binaries (no libc deps in runtime image).
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Download dependencies first (layer-cached unless go.mod changes).
COPY go.mod ./
RUN go mod download || true

# Copy full source and build.
# go mod tidy generates go.sum if absent (needed for modules with unresolved deps).
COPY . .
RUN go mod tidy 2>/dev/null || true && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/scanner        ./cmd/cli     && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/scanner-server  ./cmd/server

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Pull pinned Trivy binary
#   Use the official Aqua Security image so the version is pinnable via
#   build-arg.  Override at build time:
#     docker build --build-arg TRIVY_VERSION=0.70.0 -t scanner:latest .
# ─────────────────────────────────────────────────────────────────────────────
ARG TRIVY_VERSION=0.69.1
FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 — Minimal runtime image
# ─────────────────────────────────────────────────────────────────────────────
FROM alpine:3.20

# OCI image labels
LABEL org.opencontainers.image.title="Docker Container Scanner" \
      org.opencontainers.image.description="Production-grade container scanner: Trivy + CISA KEV + OSV.dev + runc advisory + Web UI" \
      org.opencontainers.image.source="https://github.com/beejak/docker-scanner" \
      org.opencontainers.image.documentation="https://github.com/beejak/docker-scanner/tree/main/docs" \
      org.opencontainers.image.licenses="MIT"

# CA certificates for HTTPS (CISA KEV, OSV.dev, registry pulls).
RUN apk add --no-cache ca-certificates

# Trivy binary from the official image (avoids curl + sh pipe in runtime layer).
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# Scanner binaries.
COPY --from=builder /out/scanner        /usr/local/bin/scanner
COPY --from=builder /out/scanner-server /usr/local/bin/scanner-server

# Web UI assets — the server reads web/index.html relative to its working dir.
WORKDIR /app
COPY web/ ./web/

# Port used by scanner-server (web UI).
EXPOSE 8080

# Liveness check for server mode.
# Only meaningful when running as scanner-server; harmless when running as CLI.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O- http://localhost:8080/health 2>/dev/null || exit 1

# ─────────────────────────────────────────────────────────────────────────────
# Default entrypoint: CLI scanner
#   To run the web UI server instead:
#     docker run -p 8080:8080 --entrypoint scanner-server scanner:latest
#   Or via docker compose (see docker-compose.yml).
# ─────────────────────────────────────────────────────────────────────────────
ENTRYPOINT ["scanner"]
CMD ["scan", "--help"]
