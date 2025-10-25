#!/bin/bash
# Build arca-tap-forwarder for Linux ARM64 (cross-compile from macOS)
# This binary runs inside container VMs to forward TAP traffic over vsock

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR}"

echo "=== Building TAP Forwarder for Linux ARM64 ==="
echo

cd "$SCRIPT_DIR"

# Download dependencies
echo "→ Downloading Go dependencies..."
go mod download

# Cross-compile for Linux ARM64
echo "→ Building arca-tap-forwarder for Linux (arm64)..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
    -o "$OUTPUT_DIR/arca-tap-forwarder" \
    -ldflags="-s -w" \
    ./cmd/arca-tap-forwarder

if [ ! -f "$OUTPUT_DIR/arca-tap-forwarder" ]; then
    echo "ERROR: Build completed but binary not found"
    exit 1
fi

# Show binary info
echo "  ✓ Built: $OUTPUT_DIR/arca-tap-forwarder"
file "$OUTPUT_DIR/arca-tap-forwarder" 2>/dev/null || echo "  (file command not available)"
ls -lh "$OUTPUT_DIR/arca-tap-forwarder"

echo
echo "=== Build Complete ==="
echo
echo "The arca-tap-forwarder binary is ready to be embedded in vminit."
