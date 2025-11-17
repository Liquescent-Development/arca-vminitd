#!/bin/bash
# Build Arca Filesystem Service binary
set -e

cd "$(dirname "$0")"

echo "Building arca-filesystem-service..."
go build -o arca-filesystem-service ./cmd/arca-filesystem-service

echo "✓ Build complete: arca-filesystem-service"
ls -lh arca-filesystem-service
