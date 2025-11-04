// WireGuard Hub Management
// Manages a WireGuard interface (wg0) for container networking

package wireguard

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

// configureInterface sets private key and listen port using wgctrl
func (h *Hub) configureInterface() error {
	// Parse private key
	privateKey, err := wgtypes.ParseKey(h.privateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Create wgctrl client
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	defer client.Close()

	// Configure device with private key and listen port
	listenPort := int(h.listenPort)
	config := wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &listenPort,
	}

	if err := client.ConfigureDevice(h.interfaceName, config); err != nil {
		return fmt.Errorf("failed to configure interface: %w", err)
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

// addPeer adds a peer to the WireGuard interface using wgctrl
func (h *Hub) addPeer(endpoint, publicKeyStr string, allowedIPs []string) error {
	// Parse peer public key
	peerKey, err := wgtypes.ParseKey(publicKeyStr)
	if err != nil {
		return fmt.Errorf("failed to parse peer public key: %w", err)
	}

	// Parse endpoint
	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("failed to parse endpoint: %w", err)
	}

	// Parse allowed IPs
	allowedIPNets := make([]net.IPNet, 0, len(allowedIPs))
	for _, cidr := range allowedIPs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse allowed IP %s: %w", cidr, err)
		}
		allowedIPNets = append(allowedIPNets, *ipnet)
	}

	// Persistent keepalive
	keepalive := 25 * time.Second

	// Create peer config
	peerConfig := wgtypes.PeerConfig{
		PublicKey:                   peerKey,
		Endpoint:                    udpAddr,
		AllowedIPs:                  allowedIPNets,
		PersistentKeepaliveInterval: &keepalive,
	}

	// Create wgctrl client
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	defer client.Close()

	// Configure device to add peer
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := client.ConfigureDevice(h.interfaceName, config); err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}

	return nil
}

// updatePeerAllowedIPs updates allowed IPs for a peer using wgctrl
func (h *Hub) updatePeerAllowedIPs(publicKeyStr string, allowedCIDRs []string) error {
	// Parse peer public key
	peerKey, err := wgtypes.ParseKey(publicKeyStr)
	if err != nil {
		return fmt.Errorf("failed to parse peer public key: %w", err)
	}

	// Parse allowed IPs
	allowedIPNets := make([]net.IPNet, 0, len(allowedCIDRs))
	for _, cidr := range allowedCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse allowed IP %s: %w", cidr, err)
		}
		allowedIPNets = append(allowedIPNets, *ipnet)
	}

	// Update peer config (UpdateOnly=true means only update existing peer)
	updateOnly := true
	peerConfig := wgtypes.PeerConfig{
		PublicKey:  peerKey,
		UpdateOnly: updateOnly,
		AllowedIPs: allowedIPNets,
	}

	// Create wgctrl client
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	defer client.Close()

	// Configure device to update peer
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := client.ConfigureDevice(h.interfaceName, config); err != nil {
		return fmt.Errorf("failed to update peer allowed IPs: %w", err)
	}

	return nil
}

// removePeer removes a peer from the WireGuard interface using wgctrl
func (h *Hub) removePeer(publicKeyStr string) error {
	// Parse peer public key
	peerKey, err := wgtypes.ParseKey(publicKeyStr)
	if err != nil {
		return fmt.Errorf("failed to parse peer public key: %w", err)
	}

	// Remove peer config (Remove=true)
	remove := true
	peerConfig := wgtypes.PeerConfig{
		PublicKey: peerKey,
		Remove:    remove,
	}

	// Create wgctrl client
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	defer client.Close()

	// Configure device to remove peer
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := client.ConfigureDevice(h.interfaceName, config); err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}

	return nil
}

// getPeerStats retrieves peer statistics using wgctrl
func (h *Hub) getPeerStats() []PeerStatus {
	peers := make([]PeerStatus, 0, len(h.networks))

	// Create wgctrl client
	client, err := wgctrl.New()
	if err != nil {
		log.Printf("Failed to create wgctrl client for stats: %v", err)
		return peers
	}
	defer client.Close()

	// Get device info
	device, err := client.Device(h.interfaceName)
	if err != nil {
		log.Printf("Failed to get device info: %v", err)
		return peers
	}

	// Build map of peer public key -> peer stats
	peerMap := make(map[string]*wgtypes.Peer)
	for i := range device.Peers {
		peer := &device.Peers[i]
		peerMap[peer.PublicKey.String()] = peer
	}

	// Match peers to networks and extract stats
	for _, network := range h.networks {
		peer, found := peerMap[network.PeerPublicKey]

		var latestHandshake uint64
		var bytesReceived, bytesSent uint64
		var persistentKeepalive uint32
		var endpoint string
		var allowedIPs []string

		if found {
			// Convert handshake time to Unix timestamp
			if !peer.LastHandshakeTime.IsZero() {
				latestHandshake = uint64(peer.LastHandshakeTime.Unix())
			}

			bytesReceived = uint64(peer.ReceiveBytes)
			bytesSent = uint64(peer.TransmitBytes)

			if peer.PersistentKeepaliveInterval > 0 {
				persistentKeepalive = uint32(peer.PersistentKeepaliveInterval.Seconds())
			}

			if peer.Endpoint != nil {
				endpoint = peer.Endpoint.String()
			}

			// Convert allowed IPs to strings
			allowedIPs = make([]string, 0, len(peer.AllowedIPs))
			for _, ipnet := range peer.AllowedIPs {
				allowedIPs = append(allowedIPs, ipnet.String())
			}
		} else {
			// Peer not found, use network metadata
			endpoint = network.PeerEndpoint
			allowedIPs = []string{network.NetworkCIDR}
			persistentKeepalive = 25
		}

		peers = append(peers, PeerStatus{
			NetworkID:           network.ID,
			PublicKey:           network.PeerPublicKey,
			Endpoint:            endpoint,
			AllowedIPs:          allowedIPs,
			LatestHandshake:     latestHandshake,
			BytesReceived:       bytesReceived,
			BytesSent:           bytesSent,
			PersistentKeepalive: persistentKeepalive,
		})
	}

	return peers
}

// derivePublicKey generates a public key from a private key using curve25519
func derivePublicKey(privateKeyStr string) (string, error) {
	// Decode base64 private key
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(privateKeyBytes) != 32 {
		return "", fmt.Errorf("invalid private key length: %d (expected 32)", len(privateKeyBytes))
	}

	// Derive public key using curve25519
	var privateKey, publicKey [32]byte
	copy(privateKey[:], privateKeyBytes)
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	// Encode public key as base64
	return base64.StdEncoding.EncodeToString(publicKey[:]), nil
}
