#!/usr/bin/env bash
# Install dependencies for Docker Container Scanner on Linux and macOS.
# Run from repo root: ./scripts/install-deps.sh
# Installs: Go 1.21+, Trivy. Optional: Docker (install separately if you want to use the scanner image).

set -e
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
GO_MIN_VERSION=1.21
TRIVY_VERSION="${TRIVY_VERSION:-v0.69.1}"

echo "=== Install dependencies (repo: $REPO_ROOT) ==="

# --- Detect OS ---
OS=""
if [[ "$(uname -s)" == "Darwin" ]]; then
  OS="macos"
elif [[ -f /etc/os-release ]]; then
  . /etc/os-release
  case "$ID" in
    ubuntu|debian|pop) OS="debian" ;;
    fedora|rhel|centos|rocky) OS="redhat" ;;
    *) OS="linux" ;;
  esac
else
  OS="linux"
fi
echo "Detected OS: $OS"

# --- Go ---
need_go=1
if command -v go &>/dev/null; then
  ver=$(go version | sed -n 's/.*go\([0-9]*\.[0-9]*\).*/\1/p')
  if [[ -n "$ver" ]]; then
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)
    need_major=$(echo "$GO_MIN_VERSION" | cut -d. -f1)
    need_minor=$(echo "$GO_MIN_VERSION" | cut -d. -f2)
    if [[ "$major" -gt "$need_major" ]] || { [[ "$major" -eq "$need_major" ]] && [[ "$minor" -ge "$need_minor" ]]; }; then
      echo "Go found: $(go version)"
      need_go=0
    fi
  fi
fi

if [[ $need_go -eq 1 ]]; then
  echo "Installing Go..."
  if [[ "$OS" == "macos" ]]; then
    if command -v brew &>/dev/null; then
      brew install go
    else
      echo "Install Homebrew (https://brew.sh) and run: brew install go"
      exit 1
    fi
  elif [[ "$OS" == "debian" ]]; then
    sudo apt-get update -qq
    sudo apt-get install -y golang-go 2>/dev/null || {
      echo "Install Go manually: https://go.dev/dl/"
      exit 1
    }
  elif [[ "$OS" == "redhat" ]]; then
    sudo dnf install -y golang 2>/dev/null || sudo yum install -y golang 2>/dev/null || {
      echo "Install Go manually: https://go.dev/dl/"
      exit 1
    }
  else
    # Generic: download Go
    arch=$(uname -m)
    case "$arch" in amd64|x86_64) goarch="amd64" ;; arm64|aarch64) goarch="arm64" ;; *) goarch="$arch" ;; esac
    gov="1.21.13"
    tarball="go${gov}.linux-${goarch}.tar.gz"
    if [[ "$OS" == "macos" ]]; then
      tarball="go${gov}.darwin-${goarch}.tar.gz"
    fi
    url="https://go.dev/dl/${tarball}"
    echo "Downloading Go from $url"
    mkdir -p "$REPO_ROOT/.go"
    curl -sL "$url" | tar -C "$REPO_ROOT/.go" -xzf -
    export PATH="$REPO_ROOT/.go/go/bin:$PATH"
    echo "Go installed under $REPO_ROOT/.go/go"
  fi
  if command -v go &>/dev/null; then
    echo "Go: $(go version)"
  else
    echo "Add Go to your PATH and re-run, or install from https://go.dev/dl/"
    exit 1
  fi
fi

# --- Trivy ---
need_trivy=1
if command -v trivy &>/dev/null; then
  echo "Trivy found: $(command -v trivy)"
  need_trivy=0
fi

if [[ $need_trivy -eq 1 ]]; then
  echo "Installing Trivy..."
  if [[ "$OS" == "macos" ]] && command -v brew &>/dev/null; then
    brew install aquasecurity/trivy/trivy
    need_trivy=0
  elif [[ "$OS" == "debian" ]]; then
    sudo apt-get install -y wget apt-transport-https gnupg lsb-release -qq
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
    sudo apt-get update -qq && sudo apt-get install -y trivy
    need_trivy=0
  fi
  if [[ $need_trivy -eq 1 ]] && command -v go &>/dev/null; then
    echo "Installing Trivy via go install (may take a few minutes)..."
    go install github.com/aquasecurity/trivy/cmd/trivy@latest
    export PATH="${GOPATH:-$HOME/go}/bin:$PATH"
    echo "Trivy installed to \${GOPATH}/bin (add to PATH if needed)"
    need_trivy=0
  fi
  if [[ $need_trivy -eq 1 ]]; then
    # Binary download (asset names: trivy_0.69.1_Linux-64bit.tar.gz or trivy_0.69.1_macOS-64bit.tar.gz)
    arch=$(uname -m)
    case "$arch" in x86_64|amd64) trivy_arch="64bit" ;; aarch64|arm64) trivy_arch="ARM64" ;; *) trivy_arch="64bit" ;; esac
    if [[ "$(uname -s)" == "Darwin" ]]; then
      os_part="macOS"
    else
      os_part="Linux"
    fi
    ver_num=$(echo "$TRIVY_VERSION" | tr -d v)
    zipname="trivy_${ver_num}_${os_part}-${trivy_arch}.tar.gz"
    url="https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/${zipname}"
    echo "Downloading Trivy from $url"
    mkdir -p "$REPO_ROOT/.trivy"
    curl -sL "$url" | tar -C "$REPO_ROOT/.trivy" -xzf -
    bindir=$(find "$REPO_ROOT/.trivy" -name trivy -type f 2>/dev/null | head -1)
    bindir=$(dirname "$bindir")
    if [[ -n "$bindir" ]] && [[ -x "$bindir/trivy" ]]; then
      export PATH="$bindir:$PATH"
      echo "Trivy installed under $bindir (add to PATH: export PATH=\"$bindir:\$PATH\")"
      need_trivy=0
    fi
  fi
  if [[ $need_trivy -eq 1 ]]; then
    echo "Could not install Trivy. Install manually: https://github.com/aquasecurity/trivy#installation"
    exit 1
  fi
fi

# --- go mod ---
echo ""
echo "Running go mod tidy..."
go mod tidy

echo ""
echo "=== Done. You can now build and run: go build -o scanner ./cmd/cli && ./scanner scan --image alpine:latest --output-dir ./reports ==="
echo "Optional: Install Docker to use the scanner as a container (docker build -t scanner:latest .)."
