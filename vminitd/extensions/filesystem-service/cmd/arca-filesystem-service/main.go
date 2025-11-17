// Arca Filesystem Service
// gRPC server for container filesystem operations
// Runs over vsock for communication with the host
//
// Provides:
// - Filesystem sync (flush buffers)
// - OverlayFS upperdir enumeration (for docker diff)
// - Archive operations (tar creation/extraction for buildx)

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"

	filesystem "github.com/vas-solutus/arca-filesystem-service"
	pb "github.com/vas-solutus/arca-filesystem-service/proto"
)

const (
	FILESYSTEM_PORT = 51821 // vsock port for Filesystem service API
	VERSION         = "0.2.0"
)

func main() {
	log.SetPrefix("[arca-filesystem] ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	log.Printf("Arca Filesystem Service v%s starting...", VERSION)

	// Create vsock listener
	listener, err := vsock.Listen(FILESYSTEM_PORT, nil)
	if err != nil {
		log.Fatalf("Failed to listen on vsock port %d: %v", FILESYSTEM_PORT, err)
	}
	defer listener.Close()

	log.Printf("Listening on vsock port %d", FILESYSTEM_PORT)

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Register Filesystem service
	filesystemServer := &filesystem.Server{}
	pb.RegisterFilesystemServiceServer(grpcServer, filesystemServer)

	log.Printf("Filesystem service registered")

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down...", sig)
		grpcServer.GracefulStop()
	}()

	// Start serving
	log.Printf("Filesystem service ready")
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}

	log.Printf("Filesystem service stopped")
}
