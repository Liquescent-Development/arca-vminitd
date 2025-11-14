#!/bin/bash
# Build OverlayFS service for Linux ARM64

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building arca-overlayfs-service for Linux ARM64..."

# Cross-compile for Linux ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
    -o arca-overlayfs-service \
    -ldflags="-s -w" \
    ./cmd/arca-overlayfs-service

if [ ! -f arca-overlayfs-service ]; then
    echo "ERROR: Build failed - arca-overlayfs-service binary not created"
    exit 1
fi

echo "✓ Built arca-overlayfs-service ($(du -h arca-overlayfs-service | awk '{print $1}'))"