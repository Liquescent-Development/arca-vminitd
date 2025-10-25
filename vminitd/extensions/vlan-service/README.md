# VLAN Network Configuration Service

A gRPC service that runs inside container VMs (as part of vminitd) to provide VLAN network configuration without requiring shell or utilities.

## Purpose

This service enables Arca to configure VLAN-based bridge networking in containers, including distroless containers that lack `/bin/sh`, `ip`, or other networking utilities.

## Features

- **CreateVLAN**: Create VLAN subinterfaces (e.g., `eth0.100` from `eth0`)
- **DeleteVLAN**: Remove VLAN subinterfaces
- **ConfigureIP**: Add/update IP addresses on interfaces
- **AddRoute**: Add routes to the routing table
- **DeleteRoute**: Remove routes from the routing table
- **ListInterfaces**: List all network interfaces with details

## Implementation

- Uses `vishvananda/netlink` for direct kernel netlink communication
- No subprocess calls (`ip`, `ifconfig`, etc.) - pure Go netlink API
- Works in distroless containers (no dependencies on system utilities)
- gRPC service accessible via vsock from Arca daemon using `Container.dial()`

## Building

```bash
# Generate protobuf code
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/network.proto

# Build for Linux ARM64 (cross-compile from macOS)
GOOS=linux GOARCH=arm64 go build -o vlan-service .
```

## Usage

The service is started automatically by vminitd and listens on a TCP port (default: 50051) accessible via vsock.

From Arca daemon:
```swift
try await container.dial { connection in
    let client = NetworkConfigClient(connection)
    try await client.createVLAN(
        parentInterface: "eth0",
        vlanID: 100,
        ipAddress: "172.18.0.5/16",
        gateway: "172.18.0.1"
    )
}
```

## Protocol Buffer Definition

See `proto/network.proto` for the complete gRPC service definition.

## Dependencies

- Go 1.24+
- github.com/vishvananda/netlink v1.3.1
- google.golang.org/grpc v1.76.0
- google.golang.org/protobuf v1.36.10
