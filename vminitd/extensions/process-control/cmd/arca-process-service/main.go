package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"
	pb "github.com/apple/containerization/vminitd/extensions/process-control/proto"
	"github.com/apple/containerization/vminitd/extensions/process-control"
)

const (
	PROCESS_SERVICE_PORT = 51822 // vsock port for Process Control API
)

func main() {
	// Get vsock port from environment (default: 51822)
	portStr := os.Getenv("PROCESS_SERVICE_PORT")
	port := PROCESS_SERVICE_PORT
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	// Listen on vsock using mdlayher/vsock library (required for vsock support)
	lis, err := vsock.Listen(uint32(port), nil)
	if err != nil {
		log.Fatalf("Failed to listen on vsock port %d: %v", port, err)
	}

	log.Printf("Process service listening on vsock port %d", port)

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
