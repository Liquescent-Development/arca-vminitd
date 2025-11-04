// Arca WireGuard Network Service
// gRPC server for managing WireGuard network interfaces in containers
// Runs over vsock for communication with the host

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
	pb "github.com/vas-solutus/arca-wireguard-service/proto"
	"github.com/vas-solutus/arca-wireguard-service/internal/wireguard"
	"google.golang.org/grpc"
)

const (
	WIREGUARD_PORT = 51820 // vsock port for WireGuard control API
	VERSION        = "0.1.0"
)

var startTime = time.Now()

// server implements the WireGuardService gRPC service
type server struct {
	pb.UnimplementedWireGuardServiceServer
	hub *wireguard.Hub
}

// CreateHub creates a new WireGuard hub interface (wg0)
func (s *server) CreateHub(ctx context.Context, req *pb.CreateHubRequest) (*pb.CreateHubResponse, error) {
	log.Printf("CreateHub: private_key=<redacted> listen_port=%d ip=%s network=%s",
		req.ListenPort, req.IpAddress, req.NetworkCidr)

	if s.hub != nil {
		return &pb.CreateHubResponse{
			Success: false,
			Error:   "hub already exists",
		}, nil
	}

	// Create WireGuard hub
	hub, err := wireguard.NewHub(req.PrivateKey, req.ListenPort, req.IpAddress, req.NetworkCidr)
	if err != nil {
		log.Printf("CreateHub failed: %v", err)
		return &pb.CreateHubResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	s.hub = hub

	return &pb.CreateHubResponse{
		Success:   true,
		PublicKey: hub.PublicKey(),
		Interface: "wg0",
	}, nil
}

// AddNetwork adds a network to the container's WireGuard hub
func (s *server) AddNetwork(ctx context.Context, req *pb.AddNetworkRequest) (*pb.AddNetworkResponse, error) {
	log.Printf("AddNetwork: network_id=%s peer_endpoint=%s ip=%s network=%s",
		req.NetworkId, req.PeerEndpoint, req.IpAddress, req.NetworkCidr)

	if s.hub == nil {
		return &pb.AddNetworkResponse{
			Success: false,
			Error:   "hub not created",
		}, nil
	}

	err := s.hub.AddNetwork(
		req.NetworkId,
		req.PeerEndpoint,
		req.PeerPublicKey,
		req.IpAddress,
		req.NetworkCidr,
		req.Gateway,
	)
	if err != nil {
		log.Printf("AddNetwork failed: %v", err)
		return &pb.AddNetworkResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.AddNetworkResponse{
		Success:       true,
		TotalNetworks: uint32(s.hub.NetworkCount()),
	}, nil
}

// RemoveNetwork removes a network from the container's WireGuard hub
func (s *server) RemoveNetwork(ctx context.Context, req *pb.RemoveNetworkRequest) (*pb.RemoveNetworkResponse, error) {
	log.Printf("RemoveNetwork: network_id=%s", req.NetworkId)

	if s.hub == nil {
		return &pb.RemoveNetworkResponse{
			Success: false,
			Error:   "hub not created",
		}, nil
	}

	err := s.hub.RemoveNetwork(req.NetworkId)
	if err != nil {
		log.Printf("RemoveNetwork failed: %v", err)
		return &pb.RemoveNetworkResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.RemoveNetworkResponse{
		Success:           true,
		RemainingNetworks: uint32(s.hub.NetworkCount()),
	}, nil
}

// UpdateAllowedIPs updates allowed IP ranges for multi-network routing
func (s *server) UpdateAllowedIPs(ctx context.Context, req *pb.UpdateAllowedIPsRequest) (*pb.UpdateAllowedIPsResponse, error) {
	log.Printf("UpdateAllowedIPs: peer=%s cidrs=%v", req.PeerPublicKey, req.AllowedCidrs)

	if s.hub == nil {
		return &pb.UpdateAllowedIPsResponse{
			Success: false,
			Error:   "hub not created",
		}, nil
	}

	err := s.hub.UpdateAllowedIPs(req.PeerPublicKey, req.AllowedCidrs)
	if err != nil {
		log.Printf("UpdateAllowedIPs failed: %v", err)
		return &pb.UpdateAllowedIPsResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.UpdateAllowedIPsResponse{
		Success:      true,
		TotalAllowed: uint32(len(req.AllowedCidrs)),
	}, nil
}

// DeleteHub destroys the WireGuard hub interface
func (s *server) DeleteHub(ctx context.Context, req *pb.DeleteHubRequest) (*pb.DeleteHubResponse, error) {
	log.Printf("DeleteHub: force=%v", req.Force)

	if s.hub == nil {
		return &pb.DeleteHubResponse{
			Success: false,
			Error:   "hub not created",
		}, nil
	}

	err := s.hub.Delete(req.Force)
	if err != nil {
		log.Printf("DeleteHub failed: %v", err)
		return &pb.DeleteHubResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	s.hub = nil

	return &pb.DeleteHubResponse{
		Success: true,
	}, nil
}

// GetStatus returns WireGuard hub status and statistics
func (s *server) GetStatus(ctx context.Context, req *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	if s.hub == nil {
		return &pb.GetStatusResponse{
			Version:      VERSION,
			NetworkCount: 0,
			Interface:    nil,
			Peers:        nil,
		}, nil
	}

	status := s.hub.GetStatus()

	return &pb.GetStatusResponse{
		Version:      VERSION,
		NetworkCount: uint32(len(status.Networks)),
		Interface: &pb.InterfaceStatus{
			Name:        status.InterfaceName,
			PublicKey:   status.PublicKey,
			ListenPort:  uint32(status.ListenPort),
			IpAddresses: status.IPAddresses,
		},
		Peers: convertPeerStatus(status.Peers),
	}, nil
}

func convertPeerStatus(peers []wireguard.PeerStatus) []*pb.PeerStatus {
	result := make([]*pb.PeerStatus, 0, len(peers))
	for _, p := range peers {
		result = append(result, &pb.PeerStatus{
			NetworkId:       p.NetworkID,
			PublicKey:       p.PublicKey,
			Endpoint:        p.Endpoint,
			AllowedIps:      p.AllowedIPs,
			LatestHandshake: p.LatestHandshake,
			Stats: &pb.TransferStats{
				BytesReceived:       p.BytesReceived,
				BytesSent:           p.BytesSent,
				PersistentKeepalive: p.PersistentKeepalive,
			},
		})
	}
	return result
}

func main() {
	log.Printf("Arca WireGuard Service v%s starting...", VERSION)

	// Listen on vsock
	listener, err := vsock.Listen(WIREGUARD_PORT, nil)
	if err != nil {
		log.Fatalf("Failed to listen on vsock port %d: %v", WIREGUARD_PORT, err)
	}
	defer listener.Close()

	log.Printf("Listening on vsock port %d", WIREGUARD_PORT)

	// Create gRPC server
	grpcServer := grpc.NewServer()
	pb.RegisterWireGuardServiceServer(grpcServer, &server{})

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		grpcServer.GracefulStop()
	}()

	// Start serving
	log.Println("WireGuard service ready")
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
