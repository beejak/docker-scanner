#!/usr/bin/env bash
# Update Trivy vulnerability database (run daily for fresh CVE data).
# Run from repo root: ./scripts/update-trivy-db.sh
# Schedule daily: add to crontab -e: 0 3 * * * /path/to/docker-scanner/scripts/update-trivy-db.sh

set -e
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
CACHE_DIR="${TRIVY_CACHE_DIR:-$REPO_ROOT/.trivy/cache}"
export TRIVY_CACHE_DIR="$CACHE_DIR"
mkdir -p "$CACHE_DIR"

if ! command -v trivy &>/dev/null; then
  echo "Trivy not in PATH. Run scripts/install-deps.sh first or set PATH to include Trivy."
  exit 1
fi

echo "$(date -Iseconds) Updating Trivy DB..."
trivy image --download-db-only --cache-dir "$CACHE_DIR"
echo "$(date -Iseconds) Trivy DB update done."
