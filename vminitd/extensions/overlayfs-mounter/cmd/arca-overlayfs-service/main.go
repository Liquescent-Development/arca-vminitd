// Arca OverlayFS Service
// gRPC server for managing OverlayFS mounts in containers
// Runs over vsock for communication with the host

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"

	"github.com/apple/containerization/vminitd/extensions/overlayfs-mounter"
	pb "github.com/apple/containerization/vminitd/extensions/overlayfs-mounter/proto"
)

const (
	OVERLAYFS_PORT = 51821 // vsock port for OverlayFS control API
	VERSION        = "0.1.0"
)

func main() {
	log.SetPrefix("[arca-overlayfs] ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	log.Printf("Arca OverlayFS Service v%s starting...", VERSION)

	// Create vsock listener
	listener, err := vsock.Listen(OVERLAYFS_PORT, nil)
	if err != nil {
		log.Fatalf("Failed to listen on vsock port %d: %v", OVERLAYFS_PORT, err)
	}
	defer listener.Close()

	log.Printf("Listening on vsock port %d", OVERLAYFS_PORT)

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Register OverlayFS service
	overlayfsServer := &overlayfs.Server{}
	pb.RegisterOverlayFSServiceServer(grpcServer, overlayfsServer)

	log.Printf("OverlayFS service registered")

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down...", sig)
		grpcServer.GracefulStop()
	}()

	// Start serving
	log.Printf("OverlayFS service ready")
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}

	log.Printf("OverlayFS service stopped")
}

// vsockListener adapts vsock.Listener to net.Listener
type vsockListener struct {
	*vsock.Listener
}

func (l *vsockListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &vsockConn{Conn: conn}, nil
}

// vsockConn adapts vsock.Conn to net.Conn
type vsockConn struct {
	*vsock.Conn
}

func (c *vsockConn) RemoteAddr() net.Addr {
	return &vsockAddr{c.Conn.RemoteAddr()}
}

func (c *vsockConn) LocalAddr() net.Addr {
	return &vsockAddr{c.Conn.LocalAddr()}
}

// vsockAddr adapts vsock.Addr to net.Addr
type vsockAddr struct {
	vsock.Addr
}

func (a *vsockAddr) Network() string {
	return "vsock"
}

func (a *vsockAddr) String() string {
	return fmt.Sprintf("%d:%d", a.ContextID, a.Port)
}