// Package processcontrol provides process lifecycle control for container init processes
//
// This service runs inside each container's Linux VM and allows external orchestration
// of the container's init process, enabling pre-start setup (rootfs, networking, etc.)
// before the container process begins execution.
package processcontrol

import (
	"context"
	"fmt"
	"log"
	"sync"

	pb "github.com/apple/containerization/vminitd/extensions/process-control/proto"
)

// Server implements the ProcessService
type Server struct {
	pb.UnimplementedProcessServiceServer

	mu             sync.Mutex
	state          string // "waiting", "running", "exited"
	pid            int32
	exitCode       int32
	processStarted chan struct{}
	startProcessFn func() (int32, error) // Function to actually start the process
}

// NewServer creates a new ProcessService server
//
// The startProcessFn is called when the StartProcess RPC is received.
// It should start the container's init process and return the PID.
func NewServer(startProcessFn func() (int32, error)) *Server {
	return &Server{
		state:          "waiting",
		processStarted: make(chan struct{}),
		startProcessFn: startProcessFn,
	}
}

// StartProcess starts the container's init process
//
// This RPC is called by the external orchestrator after all boot-time setup
// (OverlayFS mounting, network configuration, etc.) is complete.
func (s *Server) StartProcess(ctx context.Context, req *pb.StartProcessRequest) (*pb.StartProcessResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already started
	if s.state != "waiting" {
		return &pb.StartProcessResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("process already in state: %s", s.state),
		}, nil
	}

	log.Printf("StartProcess RPC received - starting container init process...")

	// Call the start function
	pid, err := s.startProcessFn()
	if err != nil {
		log.Printf("Failed to start process: %v", err)
		return &pb.StartProcessResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to start process: %v", err),
		}, nil
	}

	s.state = "running"
	s.pid = pid
	close(s.processStarted)

	log.Printf("Container init process started with PID %d", pid)

	return &pb.StartProcessResponse{
		Success: true,
		Pid:     pid,
	}, nil
}

// GetProcessStatus returns the current process status
func (s *Server) GetProcessStatus(ctx context.Context, req *pb.GetProcessStatusRequest) (*pb.GetProcessStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &pb.GetProcessStatusResponse{
		State:    s.state,
		Pid:      s.pid,
		ExitCode: s.exitCode,
	}, nil
}

// WaitForStart blocks until StartProcess RPC is called
//
// This is used by vminitd to block the boot process until the external
// orchestrator signals that boot-time setup is complete.
func (s *Server) WaitForStart() {
	<-s.processStarted
}

// MarkExited updates state when process exits
//
// This should be called by vminitd when the container process exits.
func (s *Server) MarkExited(exitCode int32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = "exited"
	s.exitCode = exitCode
	log.Printf("Container process exited with code %d", exitCode)
}
