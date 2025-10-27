#!/bin/bash
set -e

echo "Generating Go protobuf code from network.proto..."

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check for protoc
if ! command -v protoc &> /dev/null; then
    echo "ERROR: protoc not found. Install it with: brew install protobuf"
    exit 1
fi

# Check for protoc-gen-go and protoc-gen-go-grpc
if ! command -v protoc-gen-go &> /dev/null; then
    echo "ERROR: protoc-gen-go not found. Install it with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
    exit 1
fi

if ! command -v protoc-gen-go-grpc &> /dev/null; then
    echo "ERROR: protoc-gen-go-grpc not found. Install it with: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
    exit 1
fi

# Generate Go code
mkdir -p proto
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    proto/network.proto

echo "✓ Protobuf code generated successfully"
