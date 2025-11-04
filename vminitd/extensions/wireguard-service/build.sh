#!/bin/bash
# Build WireGuard service for Linux ARM64

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building arca-wireguard-service for Linux ARM64..."

# Cross-compile for Linux ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
    -o arca-wireguard-service \
    -ldflags="-s -w" \
    ./cmd/arca-wireguard-service

if [ ! -f arca-wireguard-service ]; then
    echo "ERROR: Build failed - arca-wireguard-service binary not created"
    exit 1
fi

echo "✓ Built arca-wireguard-service ($(du -h arca-wireguard-service | awk '{print $1}'))"
