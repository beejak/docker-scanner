#!/bin/sh
# Run scanner via Docker (no local Go/Trivy needed)
IMAGE="${1:-alpine:latest}"
REPORTS="$(cd "$(dirname "$0")/.." && pwd)/reports"
mkdir -p "$REPORTS"
docker run --rm -v "$REPORTS":/reports scanner:latest scan --image "$IMAGE" --output-dir /reports --format sarif,markdown
echo "Reports in $REPORTS"
