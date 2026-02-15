# Build stage: compile the scanner CLI
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /scanner ./cmd/cli

# Runtime: minimal image with Trivy + scanner
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
# Install Trivy (official install script or binary)
RUN apk add --no-cache curl && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    apk del curl
COPY --from=builder /scanner /usr/local/bin/scanner
ENTRYPOINT ["scanner"]
CMD ["scan", "--help"]
