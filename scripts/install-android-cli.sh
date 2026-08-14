#!/usr/bin/env bash
#
# Install Android CLI (Google's agent-first Android dev tool) on Linux/macOS,
# plus a JDK 17 (the CLI requires JDK 17+).
#
# Lightweight: installs a ~20 MB launcher binary; the ~78 MB runtime is
# downloaded on first run. Nothing is built here — heavy Gradle builds belong
# in CI (see .github/workflows/android-build.yml), not on a RAM-starved box.
#
# Usage:  bash install-android-cli.sh
# Env:    INSTALL_DIR=/path/to/bin   (default: $HOME/.local/bin)
#
set -euo pipefail

BINARY_NAME="android"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

log()  { printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS $ARCH" in
    "Linux x86_64")   URL_OS="linux_x86_64"   ;;
    "Darwin arm64")   URL_OS="darwin_arm64"   ;;
    "Darwin x86_64")  URL_OS="darwin_x86_64"  ;;
    *) warn "Unsupported OS/CPU: $OS $ARCH"; exit 1 ;;
esac

# --- 1. JDK 17 (required by the CLI) -----------------------------------------
# java -version prints e.g. openjdk version "17.0.10" — take the major number.
if command -v java &>/dev/null \
   && java -version 2>&1 | awk -F'"' '/version/{split($2,a,"."); exit !(a[1]>=17)}'; then
    log "JDK 17+ already present."
else
    log "No JDK 17 found — installing…"
    case "$OS" in
        Linux)
            if command -v apt-get &>/dev/null; then
                sudo apt-get update -qq
                sudo apt-get install -y -qq openjdk-17-jdk
            elif command -v dnf &>/dev/null; then
                sudo dnf install -y -q java-17-openjdk
            else
                warn "No apt/dnf available — install a JDK 17 manually, then re-run."
                exit 1
            fi
            ;;
        Darwin)
            command -v brew &>/dev/null || { warn "Homebrew required on macOS."; exit 1; }
            brew install openjdk@17
            sudo ln -sfn "$(brew --prefix)/opt/openjdk@17/libexec/openjdk.jdk" \
                /Library/Java/JavaVirtualMachines/openjdk-17.jdk
            ;;
    esac
fi

# --- 2. android CLI launcher -------------------------------------------------
mkdir -p "$INSTALL_DIR"

if [[ -x "$INSTALL_DIR/$BINARY_NAME" ]]; then
    log "$BINARY_NAME already installed — updating."
    ANDROID_CLI_FRESH_INSTALL=1 "$INSTALL_DIR/$BINARY_NAME" update
else
    log "Downloading Android CLI launcher…"
    curl -fsSL "https://dl.google.com/android/cli/latest/${URL_OS}/${BINARY_NAME}" \
        -o "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    # First run downloads the runtime (~78 MB).
    ANDROID_CLI_FRESH_INSTALL=1 "$INSTALL_DIR/$BINARY_NAME"
fi

# --- 3. PATH -----------------------------------------------------------------
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    log "Adding $INSTALL_DIR to PATH in ~/.bashrc"
    {
        printf '\n# Added by Android CLI installer\n'
        printf 'export PATH="%s:$PATH"\n' "$INSTALL_DIR"
    } >> "$HOME/.bashrc"
    export PATH="$INSTALL_DIR:$PATH"
fi

"$INSTALL_DIR/$BINARY_NAME" --version
log "Done. Run  source ~/.bashrc  (or open a new shell), then  android --help"
