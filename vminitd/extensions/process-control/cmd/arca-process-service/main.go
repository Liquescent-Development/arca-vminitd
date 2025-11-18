package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	pb "github.com/apple/containerization/vminitd/extensions/process-control/proto"
	"github.com/apple/containerization/vminitd/extensions/process-control"
)

func main() {
	// Get vsock port from environment (default: 51822)
	port := os.Getenv("PROCESS_SERVICE_PORT")
	if port == "" {
		port = "51822"
	}

	// Listen on vsock
	addr := fmt.Sprintf("vsock://:%%d/%%s", port)
	lis, err := net.Listen("vsock", addr)
	if err != nil {
		log.Fatalf("Failed to listen on vsock port %s: %v", port, err)
	}

	log.Printf("Process service listening on vsock port %s", port)

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// This is a placeholder - actual process start function will be provided by vminitd
	// In the real implementation, vminitd will call processcontrol.NewServer() with
	// its own startProcessFn that actually starts the container process.
	startProcessFn := func() (int32, error) {
		return 0, fmt.Errorf("process service running standalone - no process start function configured")
	}

	// Register ProcessService
	processService := processcontrol.NewServer(startProcessFn)
	pb.RegisterProcessServiceServer(grpcServer, processService)

	log.Printf("ProcessService registered and ready")

	// Serve
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
