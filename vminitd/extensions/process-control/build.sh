#!/bin/bash
# Build Process Control service for Linux ARM64

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building arca-process-service for Linux ARM64..."

# Generate protobuf code first
echo "Generating protobuf code..."
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/process.proto

# Cross-compile for Linux ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
    -o arca-process-service \
    -ldflags="-s -w" \
    ./cmd/arca-process-service

if [ ! -f arca-process-service ]; then
    echo "ERROR: Build failed - arca-process-service binary not created"
    exit 1
fi

echo "✓ Built arca-process-service ($(du -h arca-process-service | awk '{print $1}'))"
