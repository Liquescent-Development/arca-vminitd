package dns

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"sync"
)

// DNSMappings represents the complete DNS topology for this container
type DNSMappings struct {
	Networks map[string]*NetworkPeers `json:"networks"`
}

// NetworkPeers contains all containers on a specific network
type NetworkPeers struct {
	Containers []*ContainerDNSInfo `json:"containers"`
}

// ContainerDNSInfo contains DNS resolution info for a single container
type ContainerDNSInfo struct {
	Name      string   `json:"name"`
	ID        string   `json:"id"`
	IPAddress string   `json:"ip_address"`
	Aliases   []string `json:"aliases,omitempty"`
}

// ControlServer handles DNS mapping updates from the Arca daemon
type ControlServer struct {
	socketPath string
	mappings   *DNSMappings
	mu         sync.RWMutex
	listener   net.Listener
}

// NewControlServer creates a new DNS control server
func NewControlServer(socketPath string) (*ControlServer, error) {
	// Remove existing socket if present
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	return &ControlServer{
		socketPath: socketPath,
		mappings: &DNSMappings{
			Networks: make(map[string]*NetworkPeers),
		},
		listener: listener,
	}, nil
}

// Start begins accepting DNS mapping updates
func (s *ControlServer) Start(ctx context.Context) error {
	log.Printf("DNS control server listening on %s", s.socketPath)

	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("Error accepting connection: %v", err)
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

// handleConnection processes a single DNS mapping update
func (s *ControlServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	var mappings DNSMappings
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&mappings); err != nil {
		log.Printf("Error decoding DNS mappings: %v", err)
		return
	}

	// Update mappings atomically
	s.mu.Lock()
	s.mappings = &mappings
	s.mu.Unlock()

	recordCount := 0
	for _, peers := range mappings.Networks {
		recordCount += len(peers.Containers)
	}

	log.Printf("DNS mappings updated: %d containers across %d networks", recordCount, len(mappings.Networks))

	// Send success response
	response := map[string]interface{}{
		"success":         true,
		"records_updated": recordCount,
	}
	encoder := json.NewEncoder(conn)
	encoder.Encode(response)
}

// Resolve looks up a container name and returns its IP address
// Returns empty string if not found
func (s *ControlServer) Resolve(name string, network string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If network specified, search only that network
	if network != "" {
		peers, ok := s.mappings.Networks[network]
		if !ok {
			return ""
		}

		for _, container := range peers.Containers {
			if container.Name == name {
				return container.IPAddress
			}
			for _, alias := range container.Aliases {
				if alias == name {
					return container.IPAddress
				}
			}
		}
		return ""
	}

	// Search all networks
	for _, peers := range s.mappings.Networks {
		for _, container := range peers.Containers {
			if container.Name == name {
				return container.IPAddress
			}
			for _, alias := range container.Aliases {
				if alias == name {
					return container.IPAddress
				}
			}
		}
	}

	return ""
}

// GetNetworks returns a list of all networks this container is on
func (s *ControlServer) GetNetworks() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	networks := make([]string, 0, len(s.mappings.Networks))
	for network := range s.mappings.Networks {
		networks = append(networks, network)
	}
	return networks
}

// Close shuts down the control server
func (s *ControlServer) Close() error {
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
	return nil
}
