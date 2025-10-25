#!/bin/bash
# Build vlan-service for Linux ARM64 (cross-compile from macOS)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR}"

echo "=== Building VLAN service for Linux ARM64 ==="
echo

cd "$SCRIPT_DIR"

# Download dependencies
echo "→ Downloading Go dependencies..."
go mod download

# Cross-compile for Linux ARM64
echo "→ Building vlan-service for Linux (arm64)..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
    -o "$OUTPUT_DIR/vlan-service" \
    -ldflags="-s -w" \
    .

if [ ! -f "$OUTPUT_DIR/vlan-service" ]; then
    echo "ERROR: Build completed but binary not found"
    exit 1
fi

# Show binary info
echo "  ✓ Built: $OUTPUT_DIR/vlan-service"
file "$OUTPUT_DIR/vlan-service" 2>/dev/null || echo "  (file command not available)"
ls -lh "$OUTPUT_DIR/vlan-service"

echo
echo "=== Build Complete ==="
echo
echo "The vlan-service binary is ready to be embedded in vminit."
