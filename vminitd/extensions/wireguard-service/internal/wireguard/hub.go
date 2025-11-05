// WireGuard Hub Management
// Manages a WireGuard interface (wg0) for container networking

package wireguard

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
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
	netnsPath    string                  // Path to container network namespace
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

// NewHub creates a new WireGuard hub interface with proper namespace isolation
// Architecture:
//   Root Namespace (vminitd):     eth0 (vmnet) ←→ veth-root
//   Container Namespace (OCI):    veth-cont ←→ wg0
func NewHub(privateKey string, listenPort uint32, ipAddress, networkCIDR string) (*Hub, error) {
	log.Printf("Creating WireGuard hub with namespace isolation: listen_port=%d ip=%s network=%s", listenPort, ipAddress, networkCIDR)

	// Generate public key from private key
	publicKey, err := derivePublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Step 1: Find the container's network namespace
	log.Printf("Step 1: Finding container network namespace...")
	netnsPath, err := findContainerNetNs()
	if err != nil {
		return nil, fmt.Errorf("failed to find container namespace: %w", err)
	}
	log.Printf("Found container namespace: %s", netnsPath)

	hub := &Hub{
		privateKey:    privateKey,
		publicKey:     publicKey,
		listenPort:    listenPort,
		interfaceName: "wg0",
		netnsPath:     netnsPath,
		networks:      make(map[string]*Network),
	}

	// Step 2: Create veth pair in root namespace
	log.Printf("Step 2: Creating veth pair in root namespace...")
	if err := createVethPair(); err != nil {
		return nil, fmt.Errorf("failed to create veth pair: %w", err)
	}

	// Step 3: Move veth-cont to container namespace
	log.Printf("Step 3: Moving veth-cont to container namespace...")
	if err := moveInterfaceToNetNs("veth-cont", netnsPath); err != nil {
		// Cleanup veth pair on failure
		if vethRoot, getErr := netlink.LinkByName("veth-root"); getErr == nil {
			netlink.LinkDel(vethRoot)
		}
		return nil, fmt.Errorf("failed to move veth-cont to container namespace: %w", err)
	}

	// Step 4: Create wg0 in ROOT namespace (pure tunnel, no IP)
	// This is critical: encrypted packets arrive on eth0, so wg0's UDP socket must be in the same namespace
	log.Printf("Step 4: Creating wg0 in root namespace (pure tunnel)...")
	if err := createWg0InRootNs(privateKey, listenPort); err != nil {
		// Cleanup veth pair on failure
		if vethRoot, getErr := netlink.LinkByName("veth-root"); getErr == nil {
			netlink.LinkDel(vethRoot)
		}
		return nil, fmt.Errorf("failed to create wg0 in root namespace: %w", err)
	}

	// Step 5: Configure veth-root with gateway IP in root namespace
	// veth-root gets the overlay network gateway (e.g., 172.18.0.1) and routes local container traffic
	log.Printf("Step 5: Configuring veth-root with gateway IP in root namespace...")
	if err := configureVethRootWithIP(ipAddress, networkCIDR); err != nil {
		// Cleanup on failure
		if vethRoot, getErr := netlink.LinkByName("veth-root"); getErr == nil {
			netlink.LinkDel(vethRoot)
		}
		if wg0, getErr := netlink.LinkByName("wg0"); getErr == nil {
			netlink.LinkDel(wg0)
		}
		return nil, fmt.Errorf("failed to configure veth-root with IP: %w", err)
	}

	// Step 6: Rename veth-cont to eth0 in container namespace and assign IP
	// This provides a clean abstraction: container sees normal eth0 with its IP
	log.Printf("Step 6: Renaming veth-cont to eth0 in container namespace...")
	if err := renameVethToEth0InContainerNs(netnsPath, ipAddress, networkCIDR); err != nil {
		// Cleanup on failure
		if vethRoot, getErr := netlink.LinkByName("veth-root"); getErr == nil {
			netlink.LinkDel(vethRoot)
		}
		if wg0, getErr := netlink.LinkByName("wg0"); getErr == nil {
			netlink.LinkDel(wg0)
		}
		return nil, fmt.Errorf("failed to rename veth-cont to eth0: %w", err)
	}

	// Step 7: Configure NAT for internet access
	log.Printf("Step 7: Configuring NAT for internet access...")
	if err := configureNATForInternet(); err != nil {
		log.Printf("Warning: failed to configure NAT: %v", err)
		// Don't fail - NAT might be configured elsewhere
	}

	log.Printf("WireGuard hub created successfully: interface=%s public_key=%s", hub.interfaceName, hub.publicKey)
	log.Printf("Architecture:")
	log.Printf("  Root namespace (vminitd):")
	log.Printf("    - vmnet eth0 (UDP port 51820) ← encrypted WireGuard packets arrive")
	log.Printf("    - wg0 (10.254.0.1/32) ← WireGuard endpoint, auto-creates peer routes")
	log.Printf("    - veth-root (172.18.0.1/%s) ← gateway for overlay network", strings.Split(networkCIDR, "/")[1])
	log.Printf("    - route: %s/32 dev veth-root ← local container (this VM)", ipAddress)
	log.Printf("    - route: peer IPs dev wg0 ← auto-created by WireGuard allowed-IPs")
	log.Printf("  Container namespace:")
	log.Printf("    - eth0 (renamed veth-cont, %s/%s) ← container overlay IP", ipAddress, strings.Split(networkCIDR, "/")[1])
	log.Printf("    - default via 172.18.0.1 ← uses veth-root as gateway")
	log.Printf("  Packet flow (container → peer):")
	log.Printf("    1. Container sends to peer IP (e.g., 172.18.0.3)")
	log.Printf("    2. Default route → gateway 172.18.0.1")
	log.Printf("    3. Veth pair → veth-root in root namespace")
	log.Printf("    4. Kernel routing finds WireGuard's route: 172.18.0.3/32 dev wg0")
	log.Printf("    5. Packet goes to wg0, encrypted, sent to peer via UDP")
	log.Printf("  Key insight: WireGuard routes (172.18.0.x/32 dev wg0) work even though wg0 has 10.254.0.1!")

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
	// Only if ipAddress is provided (not empty) - allows peer-only additions for mesh config
	if ipAddress != "" {
		if err := h.addIPAddress(ipAddress, networkCIDR); err != nil {
			h.removePeer(peerPublicKey)
			return fmt.Errorf("failed to add IP address: %w", err)
		}
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

	// Remove IP address from interface (only if it was assigned)
	if network.IPAddress != "" {
		if err := h.removeIPAddress(network.IPAddress, network.NetworkCIDR); err != nil {
			log.Printf("Warning: failed to remove IP address: %v", err)
		}
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

// GetVmnetEndpoint returns the container's vmnet endpoint (eth0 IP:port)
// This is used by peer containers to configure WireGuard peers
func (h *Hub) GetVmnetEndpoint() (string, error) {
	// Get eth0 interface via netlink
	link, err := netlink.LinkByName("eth0")
	if err != nil {
		return "", fmt.Errorf("failed to get eth0 interface: %w", err)
	}

	// Get IPv4 addresses on eth0
	addrs, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil {
		return "", fmt.Errorf("failed to get eth0 addresses: %w", err)
	}

	if len(addrs) == 0 {
		return "", fmt.Errorf("no IPv4 addresses found on eth0")
	}

	// Use first IPv4 address
	ip := addrs[0].IP.String()

	// Format as IP:port endpoint
	endpoint := fmt.Sprintf("%s:%d", ip, h.listenPort)

	log.Printf("Vmnet endpoint: %s", endpoint)

	return endpoint, nil
}

// assignIPAddress adds an IP address to the interface using netlink
func (h *Hub) assignIPAddress(ipAddress, networkCIDR string) error {
	// Extract network mask from CIDR (e.g., "172.18.0.0/16" -> 16)
	parts := strings.Split(networkCIDR, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid CIDR: %s", networkCIDR)
	}
	prefixLen := parts[1]

	// Parse CIDR address
	addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%s", ipAddress, prefixLen))
	if err != nil {
		return fmt.Errorf("failed to parse address %s/%s: %w", ipAddress, prefixLen, err)
	}

	// wg0 is in root namespace, operate directly
	link, err := netlink.LinkByName(h.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", h.interfaceName, err)
	}

	// Add address to link
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IP address via netlink: %w", err)
	}

	return nil
}

// addIPAddress adds an additional IP address to the interface (for multi-network)
func (h *Hub) addIPAddress(ipAddress, networkCIDR string) error {
	return h.assignIPAddress(ipAddress, networkCIDR)
}

// removeIPAddress removes an IP address from the interface using netlink
func (h *Hub) removeIPAddress(ipAddress, networkCIDR string) error {
	// Extract network mask from CIDR
	parts := strings.Split(networkCIDR, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid CIDR: %s", networkCIDR)
	}
	prefixLen := parts[1]

	// Parse CIDR address
	addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%s", ipAddress, prefixLen))
	if err != nil {
		return fmt.Errorf("failed to parse address %s/%s: %w", ipAddress, prefixLen, err)
	}

	// wg0 is in root namespace, operate directly
	link, err := netlink.LinkByName(h.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", h.interfaceName, err)
	}

	// Remove address from link
	if err := netlink.AddrDel(link, addr); err != nil {
		return fmt.Errorf("failed to remove IP address via netlink: %w", err)
	}

	return nil
}

// bringInterfaceUp brings the interface up using netlink
func (h *Hub) bringInterfaceUp() error {
	// wg0 is in root namespace, operate directly
	link, err := netlink.LinkByName(h.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", h.interfaceName, err)
	}

	// Set link up
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring interface up via netlink: %w", err)
	}

	return nil
}

// destroyInterface destroys the WireGuard interface using netlink
func (h *Hub) destroyInterface() error {
	// wg0 is in root namespace, operate directly
	link, err := netlink.LinkByName(h.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", h.interfaceName, err)
	}

	// Delete link
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to destroy interface via netlink: %w", err)
	}

	return nil
}

// executeInContainerNs executes a function in the container's network namespace
// This ensures wgctrl operations can see devices in the container namespace
func (h *Hub) executeInContainerNs(fn func() error) error {
	// CRITICAL: Lock goroutine to OS thread for namespace operations
	// Network namespaces are thread-local. Without this, the Go scheduler can move
	// our goroutine to a different OS thread during blocking operations (like genetlink
	// calls in wgctrl), causing us to suddenly be in the wrong namespace.
	// See: https://github.com/WireGuard/wgctrl-go/issues/58
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get current namespace (root namespace) to return to later
	rootNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get root namespace: %w", err)
	}
	defer rootNs.Close()

	// Open the container namespace
	containerNs, err := netns.GetFromPath(h.netnsPath)
	if err != nil {
		return fmt.Errorf("failed to get container namespace: %w", err)
	}
	defer containerNs.Close()

	// Ensure we always return to root namespace
	defer func() {
		if err := netns.Set(rootNs); err != nil {
			log.Printf("Warning: failed to return to root namespace: %v", err)
		}
	}()

	// Switch to container namespace
	if err := netns.Set(containerNs); err != nil {
		return fmt.Errorf("failed to switch to container namespace: %w", err)
	}

	// Execute the function in container namespace
	return fn()
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

	// wg0 is in root namespace, operate directly
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	defer client.Close()

	// Configure device to add peer
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	log.Printf("DEBUG addPeer: Calling ConfigureDevice to add peer %s with allowed-IPs: %v", peerKey.String(), allowedIPs)
	if err := client.ConfigureDevice(h.interfaceName, config); err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}
	log.Printf("DEBUG addPeer: ConfigureDevice succeeded - peer %s added", peerKey.String())

	// CRITICAL: Manually create routes for allowed-IPs
	// wgctrl does NOT auto-create routes (unlike wg-quick)
	// We must explicitly add kernel routes for each allowed-IP
	wg0Link, err := netlink.LinkByName(h.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get wg0 interface for route creation: %w", err)
	}

	log.Printf("DEBUG addPeer: Creating routes for allowed-IPs...")
	for _, allowedIPNet := range allowedIPNets {
		route := &netlink.Route{
			LinkIndex: wg0Link.Attrs().Index,
			Dst:       &allowedIPNet,
		}

		log.Printf("DEBUG addPeer: Adding route: %s dev wg0", allowedIPNet.String())
		if err := netlink.RouteAdd(route); err != nil {
			// Check if route already exists (not a fatal error)
			if !strings.Contains(err.Error(), "file exists") {
				return fmt.Errorf("failed to add route for %s: %w", allowedIPNet.String(), err)
			}
			log.Printf("DEBUG addPeer: Route %s already exists (skipping)", allowedIPNet.String())
		} else {
			log.Printf("DEBUG addPeer: ✓ Route created: %s dev wg0", allowedIPNet.String())
		}
	}

	// Debug: Verify the peer was actually added by checking device state
	device, err := client.Device(h.interfaceName)
	if err != nil {
		log.Printf("WARN: Failed to verify peer addition: %v", err)
	} else {
		log.Printf("DEBUG addPeer: wg0 now has %d peers", len(device.Peers))
		for _, p := range device.Peers {
			log.Printf("DEBUG addPeer: - Peer %s: endpoint=%v allowed-IPs=%v", p.PublicKey.String()[:16], p.Endpoint, p.AllowedIPs)
		}
	}

	log.Printf("DEBUG addPeer: Successfully added peer %s with %d allowed-IPs and routes", peerKey.String()[:16], len(allowedIPNets))

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

	// wg0 is in root namespace, operate directly
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

	// wg0 is in root namespace, operate directly
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	defer client.Close()

	// Get current device state to find peer's allowed IPs
	device, err := client.Device(h.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device state: %w", err)
	}

	// Find the peer and get its allowed IPs
	var allowedIPs []net.IPNet
	for _, peer := range device.Peers {
		if peer.PublicKey.String() == peerKey.String() {
			allowedIPs = peer.AllowedIPs
			break
		}
	}

	// Remove routes for this peer's allowed IPs BEFORE removing the peer
	if len(allowedIPs) > 0 {
		wg0Link, err := netlink.LinkByName(h.interfaceName)
		if err != nil {
			log.Printf("WARN: Failed to get wg0 link for route removal: %v", err)
		} else {
			log.Printf("DEBUG removePeer: Removing %d routes for peer %s", len(allowedIPs), peerKey.String()[:16])
			for _, allowedIP := range allowedIPs {
				route := &netlink.Route{
					LinkIndex: wg0Link.Attrs().Index,
					Dst:       &allowedIP,
				}

				log.Printf("DEBUG removePeer: Removing route: %s dev wg0", allowedIP.String())
				if err := netlink.RouteDel(route); err != nil {
					// Not fatal - route might not exist
					log.Printf("WARN: Failed to remove route %s: %v", allowedIP.String(), err)
				} else {
					log.Printf("DEBUG removePeer: ✓ Route removed: %s dev wg0", allowedIP.String())
				}
			}
		}
	}

	// Remove peer config (Remove=true)
	remove := true
	peerConfig := wgtypes.PeerConfig{
		PublicKey: peerKey,
		Remove:    remove,
	}

	// Configure device to remove peer
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	log.Printf("DEBUG removePeer: Removing peer %s from WireGuard device", peerKey.String()[:16])
	if err := client.ConfigureDevice(h.interfaceName, config); err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}

	log.Printf("DEBUG removePeer: Successfully removed peer %s", peerKey.String()[:16])
	return nil
}

// getPeerStats retrieves peer statistics using wgctrl
func (h *Hub) getPeerStats() []PeerStatus {
	peers := make([]PeerStatus, 0, len(h.networks))

	// wg0 is in root namespace, operate directly
	client, err := wgctrl.New()
	if err != nil {
		log.Printf("Failed to create wgctrl client: %v", err)
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
