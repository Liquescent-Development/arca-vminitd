package dns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mdlayher/vsock"
)

// vsockDialer is a custom dialer for gRPC to connect via vsock
func vsockDialer(ctx context.Context, addr string) (net.Conn, error) {
	// Parse vsock address: "vsock://CID:PORT"
	if !strings.HasPrefix(addr, "vsock://") {
		return nil, fmt.Errorf("invalid vsock address: %s", addr)
	}

	addr = strings.TrimPrefix(addr, "vsock://")
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid vsock address format: %s", addr)
	}

	cid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid CID: %v", err)
	}

	port, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}

	// Dial vsock connection
	conn, err := vsock.Dial(uint32(cid), uint32(port), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to dial vsock: %v", err)
	}

	return conn, nil
}
