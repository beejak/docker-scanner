# ── Local dev ─────────────────────────────────────────────────────────────────

# Build the scanner CLI binary
build:
	go build -o scanner ./cmd/cli

# Build the web UI server binary
build-server:
	go build -o scanner-server ./cmd/server

# Build both binaries
build-all: build build-server

# Run a quick scan against alpine:latest (requires Trivy in PATH)
scan:
	./scanner scan --image alpine:latest \
	  --output-dir ./reports \
	  --format sarif,markdown,html,csv \
	  --check-runtime \
	  --sbom

# Download deps and tidy
deps:
	go mod tidy
	go mod download

# Start the web UI server (default port 8080; override with PORT=9090)
serve:
	go run ./cmd/server -port $(or $(PORT),8080)

# ── Unit & integration tests ─────────────────────────────────────────────────

# Unit tests with race detector (no Trivy required)
test-unit:
	go test ./pkg/... -v -count=1 -race

# Integration tests (Trivy in PATH required)
test-integration:
	go test -tags=integration ./tests/integration/... -v -count=1

# All tests
test: test-unit test-integration

# Full setup (install Go + Trivy if missing) and run all tests (Windows PowerShell)
setup-and-test:
	powershell -ExecutionPolicy Bypass -File scripts/setup-and-test.ps1

# ── Docker ────────────────────────────────────────────────────────────────────

# Pin the Trivy version baked into the scanner image.
# Override: make docker-build TRIVY_VERSION=0.70.0
TRIVY_VERSION ?= 0.69.1

# Build the scanner Docker image (CLI + web UI server + pinned Trivy).
docker-build:
	docker build \
	  --build-arg TRIVY_VERSION=$(TRIVY_VERSION) \
	  -t scanner:latest .

# Run a full scan via Docker (no local Go/Trivy needed).
# Mounts the Docker socket so the scanner can pull images.
# Results land in ./reports/ on the host.
docker-scan:
	mkdir -p reports
	docker run --rm \
	  -v /var/run/docker.sock:/var/run/docker.sock \
	  -v $$(pwd)/reports:/reports \
	  scanner:latest scan \
	    --image alpine:latest \
	    --output-dir /reports \
	    --format sarif,markdown,html,csv \
	    --check-runtime \
	    --sbom \
	    --fail-on-severity CRITICAL,HIGH

# Start the web UI server via Docker (persistent; http://localhost:8080).
# Override port: make docker-serve PORT=9090
docker-serve:
	docker run --rm -it \
	  -v /var/run/docker.sock:/var/run/docker.sock \
	  -p $(or $(PORT),8080):8080 \
	  --entrypoint scanner-server \
	  scanner:latest -port 8080

# Start the web UI server in the background via Docker Compose.
docker-serve-bg:
	docker compose up -d scanner-server

# Stop the background server.
docker-serve-stop:
	docker compose down

.PHONY: build build-server build-all scan deps serve \
        test-unit test-integration test setup-and-test \
        docker-build docker-scan docker-serve docker-serve-bg docker-serve-stop
