// WireGuard Hub Management
// Manages a WireGuard interface (wg0) for container networking

package wireguard

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
)

// Hub represents a WireGuard hub interface for a container
type Hub struct {
	privateKey   string
	publicKey    string
	listenPort   uint32
	interfaceName string
	networks     map[string]*Network // networkID -> Network
	mu           sync.RWMutex
}

// Network represents a network this container is connected to
type Network struct {
	ID            string
	PeerEndpoint  string
	PeerPublicKey string
	IPAddress     string
	NetworkCIDR   string
	Gateway       string
}

// HubStatus represents the status of the WireGuard hub
type HubStatus struct {
	InterfaceName string
	PublicKey     string
	ListenPort    int
	IPAddresses   []string
	Networks      []string
	Peers         []PeerStatus
}

// PeerStatus represents peer statistics
type PeerStatus struct {
	NetworkID           string
	PublicKey           string
	Endpoint            string
	AllowedIPs          []string
	LatestHandshake     uint64
	BytesReceived       uint64
	BytesSent           uint64
	PersistentKeepalive uint32
}

// NewHub creates a new WireGuard hub interface
func NewHub(privateKey string, listenPort uint32, ipAddress, networkCIDR string) (*Hub, error) {
	log.Printf("Creating WireGuard hub: listen_port=%d ip=%s network=%s", listenPort, ipAddress, networkCIDR)

	// Generate public key from private key
	publicKey, err := derivePublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	hub := &Hub{
		privateKey:    privateKey,
		publicKey:     publicKey,
		listenPort:    listenPort,
		interfaceName: "wg0",
		networks:      make(map[string]*Network),
	}

	// Create WireGuard interface
	if err := hub.createInterface(); err != nil {
		return nil, fmt.Errorf("failed to create interface: %w", err)
	}

	// Configure private key and listen port
	if err := hub.configureInterface(); err != nil {
		hub.destroyInterface()
		return nil, fmt.Errorf("failed to configure interface: %w", err)
	}

	// Assign IP address
	if err := hub.assignIPAddress(ipAddress, networkCIDR); err != nil {
		hub.destroyInterface()
		return nil, fmt.Errorf("failed to assign IP address: %w", err)
	}

	// Bring interface up
	if err := hub.bringInterfaceUp(); err != nil {
		hub.destroyInterface()
		return nil, fmt.Errorf("failed to bring interface up: %w", err)
	}

	log.Printf("WireGuard hub created successfully: interface=%s public_key=%s", hub.interfaceName, hub.publicKey)

	return hub, nil
}

// PublicKey returns the hub's public key
func (h *Hub) PublicKey() string {
	return h.publicKey
}

// NetworkCount returns the number of networks configured
func (h *Hub) NetworkCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.networks)
}

// AddNetwork adds a network to the hub
func (h *Hub) AddNetwork(networkID, peerEndpoint, peerPublicKey, ipAddress, networkCIDR, gateway string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.networks[networkID]; exists {
		return fmt.Errorf("network %s already exists", networkID)
	}

	network := &Network{
		ID:            networkID,
		PeerEndpoint:  peerEndpoint,
		PeerPublicKey: peerPublicKey,
		IPAddress:     ipAddress,
		NetworkCIDR:   networkCIDR,
		Gateway:       gateway,
	}

	// Add peer to WireGuard interface with allowed-ips
	if err := h.addPeer(peerEndpoint, peerPublicKey, []string{networkCIDR}); err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}

	// Add IP address to interface (multiple IPs for multi-network)
	if err := h.addIPAddress(ipAddress, networkCIDR); err != nil {
		h.removePeer(peerPublicKey)
		return fmt.Errorf("failed to add IP address: %w", err)
	}

	h.networks[networkID] = network

	log.Printf("Network added: network_id=%s peer=%s ip=%s cidr=%s", networkID, peerEndpoint, ipAddress, networkCIDR)

	return nil
}

// RemoveNetwork removes a network from the hub
func (h *Hub) RemoveNetwork(networkID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	network, exists := h.networks[networkID]
	if !exists {
		return fmt.Errorf("network %s not found", networkID)
	}

	// Remove IP address from interface
	if err := h.removeIPAddress(network.IPAddress, network.NetworkCIDR); err != nil {
		log.Printf("Warning: failed to remove IP address: %v", err)
	}

	// Remove peer from WireGuard interface
	if err := h.removePeer(network.PeerPublicKey); err != nil {
		log.Printf("Warning: failed to remove peer: %v", err)
	}

	delete(h.networks, networkID)

	log.Printf("Network removed: network_id=%s", networkID)

	return nil
}

// UpdateAllowedIPs updates allowed IP ranges for a peer
func (h *Hub) UpdateAllowedIPs(peerPublicKey string, allowedCIDRs []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Find network by peer public key
	var network *Network
	for _, n := range h.networks {
		if n.PeerPublicKey == peerPublicKey {
			network = n
			break
		}
	}

	if network == nil {
		return fmt.Errorf("peer %s not found", peerPublicKey)
	}

	// Update peer with new allowed IPs
	if err := h.updatePeerAllowedIPs(peerPublicKey, allowedCIDRs); err != nil {
		return fmt.Errorf("failed to update allowed IPs: %w", err)
	}

	log.Printf("Updated allowed IPs for peer %s: %v", peerPublicKey, allowedCIDRs)

	return nil
}

// Delete destroys the WireGuard hub interface
func (h *Hub) Delete(force bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !force && len(h.networks) > 0 {
		return fmt.Errorf("hub has %d active networks (use force=true to delete anyway)", len(h.networks))
	}

	if err := h.destroyInterface(); err != nil {
		return fmt.Errorf("failed to destroy interface: %w", err)
	}

	h.networks = make(map[string]*Network)

	log.Printf("WireGuard hub deleted")

	return nil
}

// GetStatus returns the current hub status
func (h *Hub) GetStatus() HubStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	ipAddresses := make([]string, 0, len(h.networks))
	networkIDs := make([]string, 0, len(h.networks))

	for _, network := range h.networks {
		ipAddresses = append(ipAddresses, network.IPAddress)
		networkIDs = append(networkIDs, network.ID)
	}

	peers := h.getPeerStats()

	return HubStatus{
		InterfaceName: h.interfaceName,
		PublicKey:     h.publicKey,
		ListenPort:    int(h.listenPort),
		IPAddresses:   ipAddresses,
		Networks:      networkIDs,
		Peers:         peers,
	}
}

// createInterface creates the WireGuard network interface
func (h *Hub) createInterface() error {
	// ip link add dev wg0 type wireguard
	cmd := exec.Command("ip", "link", "add", "dev", h.interfaceName, "type", "wireguard")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create interface: %w (output: %s)", err, string(output))
	}
	return nil
}

// configureInterface sets private key and listen port
func (h *Hub) configureInterface() error {
	// wg set wg0 private-key /dev/stdin listen-port $LISTEN_PORT
	// Pass private key via stdin (no shell needed)
	cmd := exec.Command("wg", "set", h.interfaceName, "private-key", "/dev/stdin", "listen-port", fmt.Sprintf("%d", h.listenPort))
	cmd.Stdin = strings.NewReader(h.privateKey)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to configure interface: %w (output: %s)", err, string(output))
	}
	return nil
}

// assignIPAddress adds an IP address to the interface
func (h *Hub) assignIPAddress(ipAddress, networkCIDR string) error {
	// Extract network mask from CIDR (e.g., "172.18.0.0/16" -> 16)
	parts := strings.Split(networkCIDR, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid CIDR: %s", networkCIDR)
	}
	netmask := parts[1]

	// ip addr add <ip>/<netmask> dev wg0
	cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", ipAddress, netmask), "dev", h.interfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to assign IP address: %w (output: %s)", err, string(output))
	}
	return nil
}

// addIPAddress adds an additional IP address to the interface (for multi-network)
func (h *Hub) addIPAddress(ipAddress, networkCIDR string) error {
	return h.assignIPAddress(ipAddress, networkCIDR)
}

// removeIPAddress removes an IP address from the interface
func (h *Hub) removeIPAddress(ipAddress, networkCIDR string) error {
	parts := strings.Split(networkCIDR, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid CIDR: %s", networkCIDR)
	}
	netmask := parts[1]

	// ip addr del <ip>/<netmask> dev wg0
	cmd := exec.Command("ip", "addr", "del", fmt.Sprintf("%s/%s", ipAddress, netmask), "dev", h.interfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove IP address: %w (output: %s)", err, string(output))
	}
	return nil
}

// bringInterfaceUp brings the interface up
func (h *Hub) bringInterfaceUp() error {
	// ip link set wg0 up
	cmd := exec.Command("ip", "link", "set", h.interfaceName, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w (output: %s)", err, string(output))
	}
	return nil
}

// destroyInterface destroys the WireGuard interface
func (h *Hub) destroyInterface() error {
	// ip link del dev wg0
	cmd := exec.Command("ip", "link", "del", "dev", h.interfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to destroy interface: %w (output: %s)", err, string(output))
	}
	return nil
}

// addPeer adds a peer to the WireGuard interface
func (h *Hub) addPeer(endpoint, publicKey string, allowedIPs []string) error {
	allowedIPsStr := strings.Join(allowedIPs, ",")

	// wg set wg0 peer <public-key> endpoint <endpoint> allowed-ips <cidrs> persistent-keepalive 25
	cmd := exec.Command("wg", "set", h.interfaceName,
		"peer", publicKey,
		"endpoint", endpoint,
		"allowed-ips", allowedIPsStr,
		"persistent-keepalive", "25")

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add peer: %w (output: %s)", err, string(output))
	}
	return nil
}

// updatePeerAllowedIPs updates allowed IPs for a peer
func (h *Hub) updatePeerAllowedIPs(publicKey string, allowedCIDRs []string) error {
	allowedIPsStr := strings.Join(allowedCIDRs, ",")

	// wg set wg0 peer <public-key> allowed-ips <cidrs>
	cmd := exec.Command("wg", "set", h.interfaceName,
		"peer", publicKey,
		"allowed-ips", allowedIPsStr)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to update peer allowed IPs: %w (output: %s)", err, string(output))
	}
	return nil
}

// removePeer removes a peer from the WireGuard interface
func (h *Hub) removePeer(publicKey string) error {
	// wg set wg0 peer <public-key> remove
	cmd := exec.Command("wg", "set", h.interfaceName, "peer", publicKey, "remove")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove peer: %w (output: %s)", err, string(output))
	}
	return nil
}

// getPeerStats retrieves peer statistics from wg show
func (h *Hub) getPeerStats() []PeerStatus {
	// For now, return empty stats - we can implement wg show parsing later
	// wg show wg0 dump
	peers := make([]PeerStatus, 0, len(h.networks))

	for _, network := range h.networks {
		peers = append(peers, PeerStatus{
			NetworkID:           network.ID,
			PublicKey:           network.PeerPublicKey,
			Endpoint:            network.PeerEndpoint,
			AllowedIPs:          []string{network.NetworkCIDR},
			LatestHandshake:     0, // TODO: parse from wg show
			BytesReceived:       0, // TODO: parse from wg show
			BytesSent:           0, // TODO: parse from wg show
			PersistentKeepalive: 25,
		})
	}

	return peers
}

// derivePublicKey generates a public key from a private key
func derivePublicKey(privateKey string) (string, error) {
	// Pass private key to wg pubkey via stdin (no shell needed)
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to derive public key: %w (output: %s)", err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}
