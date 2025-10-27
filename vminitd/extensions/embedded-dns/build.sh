#!/bin/bash
set -e

echo "Building arca-embedded-dns for Linux ARM64..."

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Clean previous build
rm -f arca-embedded-dns

# Download dependencies
echo "→ Downloading Go dependencies..."
go mod download

# Build for Linux ARM64
echo "→ Cross-compiling to Linux ARM64..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
    -ldflags="-s -w" \
    -o arca-embedded-dns \
    ./cmd/arca-embedded-dns

if [ -f arca-embedded-dns ]; then
    echo "✓ Build successful: arca-embedded-dns ($(du -h arca-embedded-dns | cut -f1))"
    file arca-embedded-dns
else
    echo "ERROR: Build failed"
    exit 1
fi
