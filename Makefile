# Build the scanner CLI binary
build:
	go build -o scanner ./cmd/cli

# Run first scan (requires Docker + Trivy)
scan:
	./scanner scan --image alpine:latest --output-dir ./reports --format sarif,markdown

# Download deps and tidy
deps:
	go mod tidy
	go mod download

# Build scanner Docker image (includes Trivy)
docker-build:
	docker build -t scanner:latest .

# Run scanner via Docker (no local Go/Trivy needed)
docker-scan:
	docker run --rm -v $$(pwd)/reports:/reports scanner:latest scan --image alpine:latest --output-dir /reports --format sarif,markdown

# Unit tests (no Trivy required)
test-unit:
	go test ./pkg/... -v -count=1

# Integration tests (Trivy in PATH required)
test-integration:
	go test -tags=integration ./tests/integration/... -v -count=1

# All tests
test: test-unit test-integration

# Full setup (install Go + Trivy if missing) and run all tests (Windows PowerShell)
setup-and-test:
	powershell -ExecutionPolicy Bypass -File scripts/setup-and-test.ps1

.PHONY: build scan deps docker-build docker-scan test-unit test-integration test setup-and-test
