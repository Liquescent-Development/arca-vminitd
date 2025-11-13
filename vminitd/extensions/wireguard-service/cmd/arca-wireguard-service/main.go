// Arca WireGuard Network Service
// gRPC server for managing WireGuard network interfaces in containers
// Runs over vsock for communication with the host

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
	pb "github.com/vas-solutus/arca-wireguard-service/proto"
	"github.com/vas-solutus/arca-wireguard-service/internal/wireguard"
	"github.com/vas-solutus/arca-wireguard-service/internal/dns"
	"google.golang.org/grpc"
)

const (
	WIREGUARD_PORT = 51820 // vsock port for WireGuard control API
	VERSION        = "0.1.0"
)

var startTime = time.Now()

// firewallOnce ensures firewall initialization happens exactly once
var firewallOnce sync.Once

// initializeFirewall sets up vmnet security and NAT rules
// Called lazily on first AddNetwork RPC (not at startup)
// This allows host network containers to skip firewall setup entirely
func initializeFirewall() {
	log.Printf("Initializing firewall rules (lazy init on first network)...")

	// Configure default vmnet security (Phase 4.1)
	// This blocks all vmnet INPUT except WireGuard UDP traffic
	if err := wireguard.ConfigureDefaultVmnetSecurity(); err != nil {
		log.Fatalf("Failed to configure vmnet security: %v", err)
	}
	log.Printf("vmnet security configured (underlay secured, only WireGuard UDP allowed)")

	// Configure NAT for internet access (Phase 3)
	// Creates MASQUERADE rule for eth0 → internet traffic
	if err := wireguard.ConfigureNATForInternet(); err != nil {
		log.Fatalf("Failed to configure NAT for internet: %v", err)
	}
	log.Printf("NAT configured (internet access enabled via eth0 MASQUERADE)")
}

// server implements the WireGuardService gRPC service
type server struct {
	pb.UnimplementedWireGuardServiceServer
	hub         *wireguard.Hub
	dnsResolver *dns.Resolver
	dnsServer   *dns.Server
	mu          sync.RWMutex
}

// AddNetwork adds a network to the container's WireGuard hub
// Creates hub lazily on first network addition
func (s *server) AddNetwork(ctx context.Context, req *pb.AddNetworkRequest) (*pb.AddNetworkResponse, error) {
	log.Printf("AddNetwork: network_id=%s index=%d peer_endpoint=%s ip=%s network=%s",
		req.NetworkId, req.NetworkIndex, req.PeerEndpoint, req.IpAddress, req.NetworkCidr)

	// Initialize firewall on first network addition (thread-safe, runs exactly once)
	// This allows host network containers (no AddNetwork calls) to skip firewall setup
	firewallOnce.Do(initializeFirewall)

	s.mu.Lock()

	// Create hub if it doesn't exist (lazy initialization)
	if s.hub == nil {
		// Pass callback to update DNS server's upstream when gateway is discovered
		hub, err := wireguard.NewHub(func(gatewayIP string) {
			// Update DNS server to use vmnet gateway for upstream DNS
			s.dnsServer.UpdateUpstreamDNS([]string{gatewayIP + ":53"})
		})
		if err != nil {
			s.mu.Unlock()
			log.Printf("Failed to create hub: %v", err)
			return &pb.AddNetworkResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to create hub: %v", err),
			}, nil
		}
		s.hub = hub
		log.Printf("Hub created successfully")
	}
	s.mu.Unlock()

	// Add network
	wgIface, ethIface, pubKey, err := s.hub.AddNetwork(
		req.NetworkId,
		req.NetworkIndex,
		req.PrivateKey,
		req.ListenPort,
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

	s.mu.RLock()
	totalNetworks := uint32(len(s.hub.GetInterfaces()))
	s.mu.RUnlock()

	return &pb.AddNetworkResponse{
		Success:       true,
		TotalNetworks: totalNetworks,
		WgInterface:   wgIface,
		EthInterface:  ethIface,
		PublicKey:     pubKey,
	}, nil
}

// RemoveNetwork removes a network from the container's WireGuard hub
func (s *server) RemoveNetwork(ctx context.Context, req *pb.RemoveNetworkRequest) (*pb.RemoveNetworkResponse, error) {
	log.Printf("RemoveNetwork: network_id=%s index=%d", req.NetworkId, req.NetworkIndex)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.RemoveNetworkResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	if err := hub.RemoveNetwork(req.NetworkId, req.NetworkIndex); err != nil {
		log.Printf("RemoveNetwork failed: %v", err)
		return &pb.RemoveNetworkResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	s.mu.RLock()
	remaining := uint32(len(hub.GetInterfaces()))
	s.mu.RUnlock()

	return &pb.RemoveNetworkResponse{
		Success:           true,
		RemainingNetworks: remaining,
	}, nil
}

// GetStatus returns WireGuard hub status and statistics
func (s *server) GetStatus(ctx context.Context, req *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.GetStatusResponse{
			Version:      VERSION,
			NetworkCount: 0,
			Interfaces:   nil,
			Peers:        nil,
		}, nil
	}

	interfaces := hub.GetStatus()

	// Convert to protobuf format
	pbInterfaces := make([]*pb.InterfaceStatus, 0, len(interfaces))
	allPeers := make([]*pb.PeerStatus, 0)

	for _, iface := range interfaces {
		pbInterfaces = append(pbInterfaces, &pb.InterfaceStatus{
			NetworkId:   iface.NetworkID,
			Name:        iface.InterfaceName,
			PublicKey:   iface.PublicKey,
			ListenPort:  uint32(iface.ListenPort),
			IpAddresses: []string{iface.IPAddress},
		})

		// Collect all peers from all interfaces
		for _, peer := range iface.Peers {
			allPeers = append(allPeers, &pb.PeerStatus{
				NetworkId:       iface.NetworkID,
				InterfaceName:   peer.InterfaceName,
				PublicKey:       peer.PublicKey,
				Endpoint:        peer.Endpoint,
				AllowedIps:      peer.AllowedIPs,
				LatestHandshake: peer.LatestHandshake,
				Stats: &pb.TransferStats{
					BytesReceived:       peer.BytesReceived,
					BytesSent:           peer.BytesSent,
					PersistentKeepalive: peer.PersistentKeepalive,
				},
			})
		}
	}

	return &pb.GetStatusResponse{
		Version:      VERSION,
		NetworkCount: uint32(len(interfaces)),
		Interfaces:   pbInterfaces,
		Peers:        allPeers,
	}, nil
}

// GetVmnetEndpoint returns the container's vmnet endpoint (eth0 IP:port)
func (s *server) GetVmnetEndpoint(ctx context.Context, req *pb.GetVmnetEndpointRequest) (*pb.GetVmnetEndpointResponse, error) {
	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.GetVmnetEndpointResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	endpoint, err := hub.GetVmnetEndpoint()
	if err != nil {
		log.Printf("GetVmnetEndpoint failed: %v", err)
		return &pb.GetVmnetEndpointResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.GetVmnetEndpointResponse{
		Success:  true,
		Endpoint: endpoint,
	}, nil
}

// AddPeer adds a peer to a WireGuard interface (for full mesh networking)
func (s *server) AddPeer(ctx context.Context, req *pb.AddPeerRequest) (*pb.AddPeerResponse, error) {
	log.Printf("AddPeer: network_id=%s index=%d peer_endpoint=%s peer_ip=%s",
		req.NetworkId, req.NetworkIndex, req.PeerEndpoint, req.PeerIpAddress)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.AddPeerResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	totalPeers, err := hub.AddPeer(
		req.NetworkId,
		req.NetworkIndex,
		req.PeerPublicKey,
		req.PeerEndpoint,
		req.PeerIpAddress,
	)

	if err != nil {
		log.Printf("AddPeer failed: %v", err)
		return &pb.AddPeerResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// Add DNS entry for this peer (Phase 3.1)
	s.dnsResolver.AddEntry(
		req.NetworkId,
		req.PeerName,
		req.PeerContainerId,
		req.PeerIpAddress,
		req.PeerAliases,
	)

	return &pb.AddPeerResponse{
		Success:    true,
		TotalPeers: uint32(totalPeers),
	}, nil
}

// RemovePeer removes a peer from a WireGuard interface
func (s *server) RemovePeer(ctx context.Context, req *pb.RemovePeerRequest) (*pb.RemovePeerResponse, error) {
	log.Printf("RemovePeer: network_id=%s index=%d peer_public_key=%s",
		req.NetworkId, req.NetworkIndex, req.PeerPublicKey)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.RemovePeerResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	remainingPeers, err := hub.RemovePeer(
		req.NetworkId,
		req.NetworkIndex,
		req.PeerPublicKey,
	)

	if err != nil {
		log.Printf("RemovePeer failed: %v", err)
		return &pb.RemovePeerResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// Remove DNS entry for this peer (Phase 3.1)
	s.dnsResolver.RemoveEntry(req.NetworkId, req.PeerName)

	return &pb.RemovePeerResponse{
		Success:        true,
		RemainingPeers: uint32(remainingPeers),
	}, nil
}

// PublishPort publishes a container port on the vmnet interface (Phase 4.1)
// Creates DNAT and INPUT rules to expose container_ip:container_port on vmnet_ip:host_port
func (s *server) PublishPort(ctx context.Context, req *pb.PublishPortRequest) (*pb.PublishPortResponse, error) {
	log.Printf("PublishPort: protocol=%s host_port=%d container_ip=%s container_port=%d",
		req.Protocol, req.HostPort, req.ContainerIp, req.ContainerPort)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.PublishPortResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	if err := wireguard.PublishPort(req.Protocol, req.HostPort, req.ContainerIp, req.ContainerPort); err != nil {
		log.Printf("PublishPort failed: %v", err)
		return &pb.PublishPortResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.PublishPortResponse{
		Success: true,
	}, nil
}

// UnpublishPort removes port mapping rules from vmnet interface (Phase 4.1)
func (s *server) UnpublishPort(ctx context.Context, req *pb.UnpublishPortRequest) (*pb.UnpublishPortResponse, error) {
	log.Printf("UnpublishPort: protocol=%s host_port=%d", req.Protocol, req.HostPort)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.UnpublishPortResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	if err := wireguard.UnpublishPort(req.Protocol, req.HostPort); err != nil {
		log.Printf("UnpublishPort failed: %v", err)
		return &pb.UnpublishPortResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.UnpublishPortResponse{
		Success: true,
	}, nil
}

// DumpNftables returns the full nftables ruleset for debugging
func (s *server) DumpNftables(ctx context.Context, req *pb.DumpNftablesRequest) (*pb.DumpNftablesResponse, error) {
	log.Printf("DumpNftables: dumping full nftables ruleset")

	ruleset, err := wireguard.DumpNftables()
	if err != nil {
		log.Printf("DumpNftables failed: %v", err)
		return &pb.DumpNftablesResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.DumpNftablesResponse{
		Success: true,
		Ruleset: ruleset,
	}, nil
}

// SyncFilesystem flushes all filesystem buffers to disk
// Calls the sync() syscall to ensure all cached writes are persisted
// Used before reading container filesystem for accurate diff results
func (s *server) SyncFilesystem(ctx context.Context, req *pb.SyncFilesystemRequest) (*pb.SyncFilesystemResponse, error) {
	log.Printf("SyncFilesystem: flushing filesystem buffers")

	// Call sync() syscall to flush all filesystem buffers
	// This ensures all cached writes (from exec, container processes, etc.) are written to disk
	syscall.Sync()

	log.Printf("SyncFilesystem: filesystem buffers flushed successfully")

	return &pb.SyncFilesystemResponse{
		Success: true,
	}, nil
}

// ReadArchive creates a tar archive of the requested filesystem path
// Works universally without requiring tar in the container
// Used for GET /containers/{id}/archive endpoint
func (s *server) ReadArchive(ctx context.Context, req *pb.ReadArchiveRequest) (*pb.ReadArchiveResponse, error) {
	// Validate containerID and path
	if req.ContainerId == "" {
		return &pb.ReadArchiveResponse{
			Success: false,
			Error:   "container_id parameter cannot be empty",
		}, nil
	}
	if req.Path == "" {
		return &pb.ReadArchiveResponse{
			Success: false,
			Error:   "path parameter cannot be empty",
		}, nil
	}

	// Resolve path relative to container rootfs
	// Container filesystem is mounted at /run/container/{id}/rootfs from init system's perspective
	fullPath := fmt.Sprintf("/run/container/%s/rootfs%s", req.ContainerId, req.Path)
	log.Printf("ReadArchive: creating tar archive of %s (container path: %s)", fullPath, req.Path)

	// Check if path exists
	fileInfo, err := os.Stat(fullPath)
	if err != nil {
		log.Printf("ReadArchive: path does not exist: %v", err)
		return &pb.ReadArchiveResponse{
			Success: false,
			Error:   fmt.Sprintf("path does not exist: %v", err),
		}, nil
	}

	// Create tar archive in memory
	var buf bytes.Buffer
	tarWriter := tar.NewWriter(&buf)
	defer tarWriter.Close()

	// Add file(s) to archive
	if err := addToTar(tarWriter, fullPath, fileInfo); err != nil {
		log.Printf("ReadArchive: failed to create tar: %v", err)
		return &pb.ReadArchiveResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to create tar: %v", err),
		}, nil
	}

	// Close tar writer to flush
	if err := tarWriter.Close(); err != nil {
		log.Printf("ReadArchive: failed to close tar writer: %v", err)
		return &pb.ReadArchiveResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to close tar writer: %v", err),
		}, nil
	}

	tarData := buf.Bytes()
	log.Printf("ReadArchive: created tar archive (%d bytes)", len(tarData))

	// Get symlink target if applicable
	linkTarget := ""
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(fullPath); err == nil {
			linkTarget = target
		}
	}

	// Create PathStat for X-Docker-Container-Path-Stat header
	stat := &pb.PathStat{
		Name:       filepath.Base(fullPath),
		Size:       fileInfo.Size(),
		Mode:       uint32(fileInfo.Mode()),
		Mtime:      fileInfo.ModTime().Format(time.RFC3339),
		LinkTarget: linkTarget,
	}

	return &pb.ReadArchiveResponse{
		Success: true,
		TarData: tarData,
		Stat:    stat,
	}, nil
}

// addToTar recursively adds files/directories to a tar archive
func addToTar(tarWriter *tar.Writer, path string, info os.FileInfo) error {
	// Get base name for tar header
	baseName := filepath.Base(path)

	// Create tar header from file info
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("failed to create tar header: %v", err)
	}
	header.Name = baseName

	// Write header
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header: %v", err)
	}

	// If it's a file, write contents
	if info.Mode().IsRegular() {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file: %v", err)
		}
		defer file.Close()

		if _, err := io.Copy(tarWriter, file); err != nil {
			return fmt.Errorf("failed to copy file data: %v", err)
		}
	}

	// If it's a directory, recursively add contents
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return fmt.Errorf("failed to read directory: %v", err)
		}

		for _, entry := range entries {
			entryPath := filepath.Join(path, entry.Name())
			entryInfo, err := entry.Info()
			if err != nil {
				log.Printf("Warning: failed to stat %s: %v", entryPath, err)
				continue
			}

			// Create header with relative path
			entryHeader, err := tar.FileInfoHeader(entryInfo, "")
			if err != nil {
				log.Printf("Warning: failed to create header for %s: %v", entryPath, err)
				continue
			}
			entryHeader.Name = filepath.Join(baseName, entry.Name())

			if err := tarWriter.WriteHeader(entryHeader); err != nil {
				log.Printf("Warning: failed to write header for %s: %v", entryPath, err)
				continue
			}

			// Write file contents if regular file
			if entryInfo.Mode().IsRegular() {
				file, err := os.Open(entryPath)
				if err != nil {
					log.Printf("Warning: failed to open %s: %v", entryPath, err)
					continue
				}
				_, err = io.Copy(tarWriter, file)
				file.Close()
				if err != nil {
					log.Printf("Warning: failed to copy %s: %v", entryPath, err)
					continue
				}
			}

			// Recursively add subdirectories
			if entryInfo.IsDir() {
				if err := addDirectoryContents(tarWriter, entryPath, filepath.Join(baseName, entry.Name())); err != nil {
					log.Printf("Warning: failed to add directory %s: %v", entryPath, err)
				}
			}
		}
	}

	return nil
}

// addDirectoryContents recursively adds directory contents to tar
func addDirectoryContents(tarWriter *tar.Writer, dirPath string, baseDir string) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		fullPath := filepath.Join(dirPath, entry.Name())
		info, err := entry.Info()
		if err != nil {
			log.Printf("Warning: failed to stat %s: %v", fullPath, err)
			continue
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			log.Printf("Warning: failed to create header for %s: %v", fullPath, err)
			continue
		}
		header.Name = filepath.Join(baseDir, entry.Name())

		if err := tarWriter.WriteHeader(header); err != nil {
			log.Printf("Warning: failed to write header for %s: %v", fullPath, err)
			continue
		}

		if info.Mode().IsRegular() {
			file, err := os.Open(fullPath)
			if err != nil {
				log.Printf("Warning: failed to open %s: %v", fullPath, err)
				continue
			}
			_, err = io.Copy(tarWriter, file)
			file.Close()
			if err != nil {
				log.Printf("Warning: failed to copy %s: %v", fullPath, err)
				continue
			}
		}

		if info.IsDir() {
			if err := addDirectoryContents(tarWriter, fullPath, header.Name); err != nil {
				log.Printf("Warning: failed to add directory %s: %v", fullPath, err)
			}
		}
	}

	return nil
}

// WriteArchive extracts a tar archive to the specified filesystem path
// Works universally without requiring tar in the container
// Used for PUT /containers/{id}/archive endpoint
func (s *server) WriteArchive(ctx context.Context, req *pb.WriteArchiveRequest) (*pb.WriteArchiveResponse, error) {
	// Validate containerID and path
	if req.ContainerId == "" {
		return &pb.WriteArchiveResponse{
			Success: false,
			Error:   "container_id parameter cannot be empty",
		}, nil
	}
	if req.Path == "" {
		return &pb.WriteArchiveResponse{
			Success: false,
			Error:   "path parameter cannot be empty",
		}, nil
	}

	// Resolve path relative to container rootfs
	// Container filesystem is mounted at /run/container/{id}/rootfs from init system's perspective
	fullPath := fmt.Sprintf("/run/container/%s/rootfs%s", req.ContainerId, req.Path)
	log.Printf("WriteArchive: extracting tar archive to %s (%d bytes) (container path: %s)", fullPath, len(req.TarData), req.Path)

	// Check that destination exists and is a directory
	destInfo, err := os.Stat(fullPath)
	if err != nil {
		return &pb.WriteArchiveResponse{
			Success: false,
			Error:   fmt.Sprintf("destination path does not exist: %v", err),
		}, nil
	}
	if !destInfo.IsDir() {
		return &pb.WriteArchiveResponse{
			Success: false,
			Error:   "destination path must be a directory",
		}, nil
	}

	// Create tar reader
	tarReader := tar.NewReader(bytes.NewReader(req.TarData))

	// Extract archive
	filesExtracted := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("WriteArchive: failed to read tar header: %v", err)
			return &pb.WriteArchiveResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to read tar header: %v", err),
			}, nil
		}

		// Build target path (using fullPath which includes container rootfs prefix)
		target := filepath.Join(fullPath, header.Name)

		// Handle different file types
		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				log.Printf("WriteArchive: failed to create directory %s: %v", target, err)
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to create directory: %v", err),
				}, nil
			}
			filesExtracted++

		case tar.TypeReg:
			// Create parent directory if needed
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				log.Printf("WriteArchive: failed to create parent directory for %s: %v", target, err)
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to create parent directory: %v", err),
				}, nil
			}

			// Create file
			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				log.Printf("WriteArchive: failed to create file %s: %v", target, err)
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to create file: %v", err),
				}, nil
			}

			// Copy file contents
			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				log.Printf("WriteArchive: failed to write file %s: %v", target, err)
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to write file: %v", err),
				}, nil
			}
			file.Close()
			filesExtracted++

		case tar.TypeSymlink:
			// Create symlink
			if err := os.Symlink(header.Linkname, target); err != nil {
				log.Printf("WriteArchive: failed to create symlink %s: %v", target, err)
				// Don't fail on symlink errors, just log warning
				log.Printf("Warning: skipping symlink %s", target)
			} else {
				filesExtracted++
			}

		default:
			log.Printf("WriteArchive: unsupported file type %c for %s", header.Typeflag, header.Name)
		}
	}

	log.Printf("WriteArchive: extracted %d files successfully", filesExtracted)

	return &pb.WriteArchiveResponse{
		Success: true,
	}, nil
}

func main() {
	log.Printf("Arca WireGuard Service v%s starting...", VERSION)

	// Create DNS resolver (shared across all containers)
	dnsResolver := dns.NewResolver()
	log.Printf("DNS resolver initialized")

	// Create DNS server listening on all interfaces (0.0.0.0:53)
	// This allows it to receive queries on gateway IPs (172.18.0.1, 172.19.0.1, etc.)
	// Security: INPUT chain blocks DNS queries from eth0 (control plane) - see configureNATForInternet
	// Containers query gateway IP directly (e.g., 172.18.0.1:53) - no DNAT needed
	dnsServer := dns.NewServer("0.0.0.0:53", dnsResolver)

	// Start DNS server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := dnsServer.ListenAndServe(ctx); err != nil {
			log.Printf("DNS server error: %v", err)
		}
	}()

	log.Printf("DNS server started on 0.0.0.0:53 (accessible on gateway IPs, blocked from control plane)")

	// Firewall initialization is now lazy (see initializeFirewall function)
	// It will be called on the first AddNetwork RPC, allowing host network containers
	// to skip firewall setup entirely (they never call AddNetwork)

	// Listen on vsock for WireGuard gRPC API
	listener, err := vsock.Listen(WIREGUARD_PORT, nil)
	if err != nil {
		log.Fatalf("Failed to listen on vsock port %d: %v", WIREGUARD_PORT, err)
	}
	defer listener.Close()

	log.Printf("Listening on vsock port %d", WIREGUARD_PORT)

	// Create gRPC server with DNS resolver and DNS server
	grpcServer := grpc.NewServer()
	pb.RegisterWireGuardServiceServer(grpcServer, &server{
		dnsResolver: dnsResolver,
		dnsServer:   dnsServer,
	})

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel() // Stop DNS server
		grpcServer.GracefulStop()
	}()

	// Start serving
	log.Println("WireGuard service ready (with integrated DNS)")
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
