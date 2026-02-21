#!/usr/bin/env bash
# Workflow test: pull a few old and new images from different registries, then scan each with config.
# Uses tests/baseline/images-workflow-test.txt and scanner.yaml (created from scanner.yaml.example if missing).
# From repo root: ./scripts/run-workflow-test.sh [--pull-first]
# Optional: --pull-first to docker pull each image before scanning.

set -e
LIST_PATH="tests/baseline/images-workflow-test.txt"
CONFIG_EXAMPLE="scanner.yaml.example"
CONFIG_PATH="scanner.yaml"
PULL_FIRST=false

for arg in "$@"; do
  case "$arg" in
    --pull-first) PULL_FIRST=true ;;
  esac
done

if [[ ! -f "$LIST_PATH" ]]; then
  echo "Image list not found: $LIST_PATH. Run from repo root." >&2
  exit 1
fi

mapfile -t images < <(grep -v '^\s*#' "$LIST_PATH" | grep -v '^\s*$' || true)

# Ensure scanner.yaml exists
if [[ ! -f "$CONFIG_PATH" && -f "$CONFIG_EXAMPLE" ]]; then
  cp "$CONFIG_EXAMPLE" "$CONFIG_PATH"
  echo "Created $CONFIG_PATH from $CONFIG_EXAMPLE"
fi

# Prefer ./scanner then PATH
SCANNER="./scanner"
if [[ ! -x "$SCANNER" ]]; then
  if command -v scanner &>/dev/null; then
    SCANNER="scanner"
  elif command -v go &>/dev/null; then
    echo "Building scanner..."
    go build -o scanner ./cmd/cli
  else
    echo "No scanner binary and go not in PATH. Build with: go build -o scanner ./cmd/cli" >&2
    exit 1
  fi
fi

REPORTS_DIR="reports"
mkdir -p "$REPORTS_DIR"

echo "Workflow test: ${#images[@]} images from multiple registries (config + scan)"
if $PULL_FIRST; then
  echo "Pulling images first..."
  for img in "${images[@]}"; do
    docker pull "$img" || true
  done
fi

ok=0
fail=0
total=${#images[@]}
i=0
for img in "${images[@]}"; do
  ((i++)) || true
  safe="${img//\//-}"
  safe="${safe//:/-}"
  out_name="wf-$safe"
  # Progress TUI: one updating line per image
  printf "\r[ %d/%d ] Scanning %s ...   " "$i" "$total" "$img"
  out=$($SCANNER scan --image "$img" --output-dir "$REPORTS_DIR" --output-name "$out_name" --format markdown,html 2>&1)
  if [[ $? -eq 0 ]]; then
    ((ok++)) || true
    findings=$(echo "$out" | grep -oE '[0-9]+ findings' | head -1 | grep -oE '[0-9]+' || echo "?")
    printf "\r[ %d/%d ] %s done (%s findings)   \n" "$i" "$total" "$img" "$findings"
  else
    ((fail++)) || true
    printf "\r[ %d/%d ] %s FAILED   \n" "$i" "$total" "$img"
  fi
done

echo ""
echo "Done. OK=$ok FAIL=$fail. Reports in $REPORTS_DIR (wf-*.md, wf-*.html)"
