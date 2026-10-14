#!/usr/bin/env bash
# scripts/build-android-aar.sh
# Intelligently builds the SmartProxy Android Go AAR library with automatic
# error detection, HTTP/1.1 downgrade, module cache warming, and network retries.

set -eo pipefail

export PATH="$PATH:$(go env GOPATH)/bin"

# Ensure gomobile tools are ready
gomobile init || true

MAX_ATTEMPTS=3
ATTEMPT=1
SUCCESS=0
BUILD_LOG=$(mktemp)
trap 'rm -f "$BUILD_LOG"' EXIT

build_aar() {
    # Stream output to terminal and capture log for pattern matching
    make android 2>&1 | tee "$BUILD_LOG"
    return "${PIPESTATUS[0]}"
}

is_transient_network_error() {
    local log_file="$1"
    grep -Eiq "(INTERNAL_ERROR|stream error|stream ID|sum\.golang\.org|proxy\.golang\.org|go mod tidy failed|connection reset|i/o timeout|TLS handshake timeout|received from peer)" "$log_file"
}

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    echo "========================================================"
    echo "=> [AAR Build] Attempt $ATTEMPT of $MAX_ATTEMPTS"
    echo "========================================================"

    if build_aar; then
        echo "=> [AAR Build] Succeeded on attempt $ATTEMPT"
        SUCCESS=1
        break
    fi

    EXIT_CODE=$?
    echo "::warning::[AAR Build] Attempt $ATTEMPT failed with exit code $EXIT_CODE"

    if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
        if is_transient_network_error "$BUILD_LOG"; then
            echo "::warning::[AAR Build] Transient Go module / sumdb network stream error detected."
            case $ATTEMPT in
                1)
                    echo "::notice::[AAR Build] Remediation #1: Downgrading to HTTP/1.1 (GODEBUG=http2client=0) and warming module cache..."
                    export GODEBUG="http2client=0"
                    go mod download -x || go mod download || true
                    ;;
                2)
                    echo "::notice::[AAR Build] Remediation #2: Enabling fallback GOPROXY mirrors with exponential backoff..."
                    export GODEBUG="http2client=0"
                    export GOPROXY="https://proxy.golang.org,https://goproxy.io,direct"
                    sleep 5
                    go mod download || true
                    ;;
            esac
        else
            echo "::warning::[AAR Build] Non-network failure detected. Backing off before retry..."
            sleep 3
        fi
    fi

    ATTEMPT=$((ATTEMPT + 1))
done

if [ $SUCCESS -ne 1 ]; then
    echo "::error::[AAR Build] All $MAX_ATTEMPTS attempts failed to build smartproxy.aar."
    exit 1
fi

mkdir -p android/app/libs
cp build/smartproxy.aar android/app/libs/smartproxy.aar
echo "=> Successfully copied build/smartproxy.aar to android/app/libs/smartproxy.aar"
