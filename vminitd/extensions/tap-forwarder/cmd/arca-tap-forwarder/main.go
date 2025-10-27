// Arca TAP Forwarder Daemon
// gRPC server for managing TAP network devices in containers
// Runs over vsock for communication with the host

package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
	pb "github.com/vas-solutus/arca-tap-forwarder/proto"
	"github.com/vas-solutus/arca-tap-forwarder/internal/forwarder"
	"google.golang.org/grpc"
)

const (
	CONTROL_PORT = 5555
	VERSION      = "0.1.0"
)

var startTime = time.Now()

// server implements the TAPForwarder gRPC service
type server struct {
	pb.UnimplementedTAPForwarderServer
	forwarder *forwarder.Forwarder
}

// AttachNetwork creates a TAP device and starts packet forwarding
func (s *server) AttachNetwork(ctx context.Context, req *pb.AttachNetworkRequest) (*pb.AttachNetworkResponse, error) {
	log.Printf("AttachNetwork: device=%s vsock_port=%d ip=%s gateway=%s netmask=%d",
		req.Device, req.VsockPort, req.IpAddress, req.Gateway, req.Netmask)

	// Default netmask to /24 if not specified
	netmask := req.Netmask
	if netmask == 0 {
		netmask = 24
	}

	// Attach network
	attachment, err := s.forwarder.AttachNetwork(
		req.Device,
		req.VsockPort,
		req.IpAddress,
		req.Gateway,
		netmask,
	)
	if err != nil {
		log.Printf("AttachNetwork failed: %v", err)
		return &pb.AttachNetworkResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.AttachNetworkResponse{
		Success:    true,
		MacAddress: attachment.MAC,
	}, nil
}

// DetachNetwork stops forwarding and destroys the TAP device
func (s *server) DetachNetwork(ctx context.Context, req *pb.DetachNetworkRequest) (*pb.DetachNetworkResponse, error) {
	log.Printf("DetachNetwork: device=%s", req.Device)

	err := s.forwarder.DetachNetwork(req.Device)
	if err != nil {
		log.Printf("DetachNetwork failed: %v", err)
		return &pb.DetachNetworkResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.DetachNetworkResponse{
		Success: true,
	}, nil
}

// ListNetworks returns all active network attachments
func (s *server) ListNetworks(ctx context.Context, req *pb.ListNetworksRequest) (*pb.ListNetworksResponse, error) {
	attachments := s.forwarder.ListAttachments()

	networks := make([]*pb.NetworkInfo, 0, len(attachments))
	for _, a := range attachments {
		stats := a.GetStats()
		networks = append(networks, &pb.NetworkInfo{
			Device:    a.Device,
			IpAddress: a.IPAddress,
			Gateway:   a.Gateway,
			VsockPort: a.VsockPort,
			MacAddress: a.MAC,
			Stats: &pb.PacketStats{
				PacketsSent:     stats.PacketsSent.Load(),
				PacketsReceived: stats.PacketsReceived.Load(),
				BytesSent:       stats.BytesSent.Load(),
				BytesReceived:   stats.BytesReceived.Load(),
				SendErrors:      stats.SendErrors.Load(),
				ReceiveErrors:   stats.ReceiveErrors.Load(),
			},
		})
	}

	log.Printf("ListNetworks: returning %d networks", len(networks))

	return &pb.ListNetworksResponse{
		Networks: networks,
	}, nil
}

// GetStatus returns daemon status and statistics
func (s *server) GetStatus(ctx context.Context, req *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	attachments := s.forwarder.ListAttachments()
	totalStats := s.forwarder.GetTotalStats()

	uptime := uint64(time.Since(startTime).Seconds())

	return &pb.GetStatusResponse{
		Version:        VERSION,
		ActiveNetworks: uint32(len(attachments)),
		UptimeSeconds:  uptime,
		TotalStats: &pb.PacketStats{
			PacketsSent:     totalStats.PacketsSent.Load(),
			PacketsReceived: totalStats.PacketsReceived.Load(),
			BytesSent:       totalStats.BytesSent.Load(),
			BytesReceived:   totalStats.BytesReceived.Load(),
			SendErrors:      totalStats.SendErrors.Load(),
			ReceiveErrors:   totalStats.ReceiveErrors.Load(),
		},
	}, nil
}

// UpdateDNSMappings forwards DNS topology updates to embedded-DNS via Unix socket
func (s *server) UpdateDNSMappings(ctx context.Context, req *pb.UpdateDNSMappingsRequest) (*pb.UpdateDNSMappingsResponse, error) {
	log.Printf("UpdateDNSMappings: updating DNS mappings for %d networks", len(req.Networks))

	// Convert protobuf to JSON format for embedded-DNS
	mappings := map[string]interface{}{
		"networks": make(map[string]interface{}),
	}

	recordCount := uint32(0)
	for networkName, peers := range req.Networks {
		containers := make([]map[string]interface{}, 0, len(peers.Containers))
		for _, container := range peers.Containers {
			containers = append(containers, map[string]interface{}{
				"name":       container.Name,
				"id":         container.Id,
				"ip_address": container.IpAddress,
				"aliases":    container.Aliases,
			})
			recordCount++
		}
		mappings["networks"].(map[string]interface{})[networkName] = map[string]interface{}{
			"containers": containers,
		}
	}

	// Connect to embedded-DNS control socket
	conn, err := net.Dial("unix", "/tmp/arca-dns-control.sock")
	if err != nil {
		log.Printf("UpdateDNSMappings failed to connect to embedded-DNS: %v", err)
		return &pb.UpdateDNSMappingsResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}
	defer conn.Close()

	// Send mappings as JSON
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(mappings); err != nil {
		log.Printf("UpdateDNSMappings failed to send mappings: %v", err)
		return &pb.UpdateDNSMappingsResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// Read response
	var response map[string]interface{}
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&response); err != nil {
		log.Printf("UpdateDNSMappings failed to read response: %v", err)
		return &pb.UpdateDNSMappingsResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	log.Printf("UpdateDNSMappings: successfully updated %d DNS records", recordCount)

	return &pb.UpdateDNSMappingsResponse{
		Success:        true,
		RecordsUpdated: recordCount,
	}, nil
}

func main() {
	log.Printf("Arca TAP Forwarder Daemon starting... version=%s control_port=%d", VERSION, CONTROL_PORT)

	// Create forwarder
	fwd := forwarder.New()

	// Create gRPC server
	grpcServer := grpc.NewServer()
	pb.RegisterTAPForwarderServer(grpcServer, &server{
		forwarder: fwd,
	})

	// Listen on vsock
	listener, err := vsock.Listen(CONTROL_PORT, nil)
	if err != nil {
		log.Fatalf("Failed to listen on vsock port %d: %v", CONTROL_PORT, err)
	}
	defer listener.Close()

	log.Printf("gRPC server listening on vsock port %d", CONTROL_PORT)

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start gRPC server in goroutine
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("gRPC server failed: %v", err)
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)

	// Graceful shutdown
	grpcServer.GracefulStop()

	log.Println("Arca TAP Forwarder Daemon stopped")
}