// Package forwarder provides packet forwarding between TAP devices and vsock connections
package forwarder

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/mdlayher/vsock"
	"github.com/vas-solutus/arca-tap-forwarder/internal/tap"
)

// NetworkAttachment represents an active network interface with forwarding
type NetworkAttachment struct {
	Device    string
	VsockPort uint32
	IPAddress string
	Gateway   string
	MAC       string

	tap        *tap.TAP
	vsockConn  net.Conn
	cancel     context.CancelFunc
	stats      Stats
	statsLock  sync.RWMutex
}

// Stats tracks packet statistics
type Stats struct {
	PacketsSent     atomic.Uint64
	PacketsReceived atomic.Uint64
	BytesSent       atomic.Uint64
	BytesReceived   atomic.Uint64
	SendErrors      atomic.Uint64
	ReceiveErrors   atomic.Uint64
}

// Forwarder manages multiple network attachments
type Forwarder struct {
	attachments map[string]*NetworkAttachment
	mu          sync.RWMutex
}

// New creates a new Forwarder
func New() *Forwarder {
	return &Forwarder{
		attachments: make(map[string]*NetworkAttachment),
	}
}

// AttachNetwork creates a TAP device and starts forwarding packets to/from vsock
func (f *Forwarder) AttachNetwork(device string, vsockPort uint32, ipAddress string, gateway string, netmask uint32, macAddress string) (*NetworkAttachment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check if already attached
	if _, exists := f.attachments[device]; exists {
		return nil, fmt.Errorf("device %s already attached", device)
	}

	// Create TAP device with specified MAC (or empty for random)
	tapDev, err := tap.Create(device, macAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create TAP device: %w", err)
	}

	// Bring interface up WITHOUT IP configuration yet
	// IP will be configured AFTER vsock relay is connected
	if err := tapDev.BringUp(); err != nil {
		tapDev.Close()
		return nil, fmt.Errorf("failed to bring interface up: %w", err)
	}

	log.Printf("TAP device %s created and brought up (MAC: %s) - waiting for relay before configuring IP", device, tapDev.MAC().String())

	// Listen on vsock port for host connection
	listener, err := vsock.Listen(vsockPort, nil)
	if err != nil {
		tapDev.Close()
		return nil, fmt.Errorf("failed to listen on vsock port %d: %w", vsockPort, err)
	}

	// Create attachment WITHOUT IP yet (will be set after relay connects)
	ctx, cancel := context.WithCancel(context.Background())
	attachment := &NetworkAttachment{
		Device:    device,
		VsockPort: vsockPort,
		IPAddress: "",  // Will be set after DHCP/static config
		Gateway:   "",  // Will be set after DHCP/static config
		MAC:       tapDev.MAC().String(),
		tap:       tapDev,
		vsockConn: nil, // Will be set when host connects
		cancel:    cancel,
	}

	// Accept connection from host in background
	go func() {
		log.Printf("Waiting for host connection on vsock port %d for device %s", vsockPort, device)
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept vsock connection on port %d: %v", vsockPort, err)
			cancel()
			return
		}

		attachment.vsockConn = conn
		log.Printf("Host connected to vsock port %d for device %s - relay is ready", vsockPort, device)

		// Start packet forwarding BEFORE DHCP so DHCP packets are actually relayed!
		go attachment.forwardTAPtoVsock(ctx)
		go attachment.forwardVsockToTAP(ctx)
		log.Printf("Packet forwarding started for device %s", device)

		// NOW configure IP (after relay is connected so DHCP packets can flow)
		var actualIP, actualGateway string
		var actualNetmask uint32

		if ipAddress == "" {
			// DHCP mode - acquire lease from OVN DHCP server
			// Retry up to 3 times with increasing delays to account for OVN flow installation
			// OVN can take ~10 seconds to install flows after port creation
			log.Printf("Starting DHCP client for %s (MAC: %s)", device, tapDev.MAC().String())

			var lease *DHCPLease
			maxAttempts := 3
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				if attempt > 1 {
					// Wait before retry (5s, 10s delays)
					delay := time.Duration(attempt) * 5 * time.Second
					log.Printf("Waiting %v before DHCP retry %d/%d for %s", delay, attempt, maxAttempts, device)
					time.Sleep(delay)
				}

				log.Printf("DHCP attempt %d/%d for %s", attempt, maxAttempts, device)
				var err error
				lease, err = performDHCP(device, tapDev.MAC())
				if err == nil {
					// Success!
					break
				}

				log.Printf("DHCP attempt %d/%d failed for %s: %v", attempt, maxAttempts, device, err)
				if attempt == maxAttempts {
					log.Printf("All DHCP attempts exhausted for %s, continuing without IP", device)
					// Don't kill the connection - continue without IP
					goto startForwarding
				}
			}

			actualIP = lease.IP
			actualGateway = lease.Gateway
			actualNetmask = lease.Netmask

			log.Printf("DHCP lease acquired for %s: IP=%s Gateway=%s Netmask=/%d DNS=%v",
				device, actualIP, actualGateway, actualNetmask, lease.DNS)

			// Apply IP configuration from DHCP lease
			if err := tapDev.SetIP(actualIP, actualNetmask); err != nil {
				log.Printf("Failed to apply DHCP IP for %s: %v", device, err)
				goto startForwarding
			}

			// Add default route via gateway from DHCP
			if actualGateway != "" {
				if err := tapDev.AddDefaultRoute(actualGateway); err != nil {
					log.Printf("Failed to add default route for %s: %v", device, err)
					// Continue anyway - networking may still work without default route
				} else {
					log.Printf("Added default route via %s for %s", actualGateway, device)
				}
			}

			// NOTE: DNS configuration is now handled by embedded-DNS (127.0.0.11:53)
			// which is auto-started by vminitd and receives DNS topology updates via gRPC.
			// Commenting out /etc/resolv.conf configuration for now.
			//
			// Configure DNS from DHCP lease (for eth0 only)
			// if device == "eth0" && len(lease.DNS) > 0 {
			// 	if err := configureDNS(lease.DNS[0]); err != nil {
			// 		log.Printf("Warning: Failed to configure DNS from DHCP: %v", err)
			// 	}
			// }

			// Update attachment with actual IP
			attachment.IPAddress = actualIP
			attachment.Gateway = actualGateway
		} else {
			// Static IP mode
			log.Printf("Configuring static IP for %s: IP=%s Gateway=%s Netmask=/%d",
				device, ipAddress, gateway, netmask)

			if err := tapDev.SetIP(ipAddress, netmask); err != nil {
				log.Printf("Failed to set static IP for %s: %v", device, err)
				goto startForwarding
			}

			actualIP = ipAddress
			actualGateway = gateway
			actualNetmask = netmask

			// NOTE: DNS configuration is now handled by embedded-DNS (127.0.0.11:53)
			// which is auto-started by vminitd and receives DNS topology updates via gRPC.
			// Commenting out /etc/resolv.conf configuration for now.
			//
			// Configure DNS to use gateway as nameserver (for eth0 only)
			// if device == "eth0" && gateway != "" {
			// 	if err := configureDNS(gateway); err != nil {
			// 		log.Printf("Warning: Failed to configure DNS: %v", err)
			// 	}
			// }

			// Update attachment with actual IP
			attachment.IPAddress = actualIP
			attachment.Gateway = actualGateway
		}

	startForwarding:
		// Start bidirectional forwarding now that we have the connection
		go attachment.forwardTAPtoVsock(ctx)
		go attachment.forwardVsockToTAP(ctx)
	}()

	f.attachments[device] = attachment

	if ipAddress == "" {
		log.Printf("Network attached: device=%s vsock_port=%d mode=DHCP mac=%s (IP will be configured after relay connects)",
			device, vsockPort, attachment.MAC)
	} else {
		log.Printf("Network attached: device=%s vsock_port=%d mode=static ip=%s mac=%s (IP will be configured after relay connects)",
			device, vsockPort, ipAddress, attachment.MAC)
	}

	return attachment, nil
}

// DetachNetwork stops forwarding and destroys the TAP device
func (f *Forwarder) DetachNetwork(device string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	attachment, exists := f.attachments[device]
	if !exists {
		return fmt.Errorf("device %s not found", device)
	}

	// Stop forwarding
	attachment.cancel()

	// Close connections
	if attachment.vsockConn != nil {
		attachment.vsockConn.Close()
	}
	if attachment.tap != nil {
		attachment.tap.Close()
	}

	delete(f.attachments, device)

	log.Printf("Network detached: device=%s", device)

	return nil
}

// GetAttachment returns the attachment for a device
func (f *Forwarder) GetAttachment(device string) (*NetworkAttachment, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	attachment, exists := f.attachments[device]
	return attachment, exists
}

// ListAttachments returns all active attachments
func (f *Forwarder) ListAttachments() []*NetworkAttachment {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make([]*NetworkAttachment, 0, len(f.attachments))
	for _, attachment := range f.attachments {
		result = append(result, attachment)
	}
	return result
}

// GetTotalStats returns aggregated statistics across all attachments
func (f *Forwarder) GetTotalStats() Stats {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var total Stats
	for _, attachment := range f.attachments {
		attachment.statsLock.RLock()
		total.PacketsSent.Add(attachment.stats.PacketsSent.Load())
		total.PacketsReceived.Add(attachment.stats.PacketsReceived.Load())
		total.BytesSent.Add(attachment.stats.BytesSent.Load())
		total.BytesReceived.Add(attachment.stats.BytesReceived.Load())
		total.SendErrors.Add(attachment.stats.SendErrors.Load())
		total.ReceiveErrors.Add(attachment.stats.ReceiveErrors.Load())
		attachment.statsLock.RUnlock()
	}
	return total
}

// forwardTAPtoVsock forwards packets from TAP device to vsock
func (a *NetworkAttachment) forwardTAPtoVsock(ctx context.Context) {
	buf := make([]byte, 65536) // Max Ethernet frame size

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read from TAP device
		n, err := a.tap.Read(buf)
		if err != nil {
			if err != io.EOF {
				a.stats.ReceiveErrors.Add(1)
				log.Printf("TAP read error on %s: %v", a.Device, err)
			}
			return
		}

		a.stats.PacketsReceived.Add(1)
		a.stats.BytesReceived.Add(uint64(n))

		// Log first few packets for debugging
		if a.stats.PacketsReceived.Load() <= 5 {
			log.Printf("TAP->vsock: device=%s bytes=%d packet=%d", a.Device, n, a.stats.PacketsReceived.Load())
		}

		// Write 4-byte length prefix to vsock (network byte order, big-endian)
		lengthBuf := [4]byte{
			byte(n >> 24),
			byte(n >> 16),
			byte(n >> 8),
			byte(n),
		}
		if _, err := a.vsockConn.Write(lengthBuf[:]); err != nil {
			a.stats.SendErrors.Add(1)
			log.Printf("vsock write length error on %s: %v", a.Device, err)
			return
		}

		// Write packet data to vsock
		_, err = a.vsockConn.Write(buf[:n])
		if err != nil {
			a.stats.SendErrors.Add(1)
			log.Printf("vsock write error on %s: %v", a.Device, err)
			return
		}

		a.stats.PacketsSent.Add(1)
		a.stats.BytesSent.Add(uint64(n))
	}
}

// forwardVsockToTAP forwards packets from vsock to TAP device
func (a *NetworkAttachment) forwardVsockToTAP(ctx context.Context) {
	buf := make([]byte, 65536) // Max Ethernet frame size
	var reversePackets atomic.Uint64

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read 4-byte length prefix from vsock (network byte order)
		// CRITICAL: Use io.ReadFull to guarantee reading exactly 4 bytes
		// vsockConn.Read() can return partial reads which corrupts the framing
		var lengthBuf [4]byte
		if _, err := io.ReadFull(a.vsockConn, lengthBuf[:]); err != nil {
			if err != io.EOF {
				a.stats.ReceiveErrors.Add(1)
				log.Printf("vsock read length error on %s: %v", a.Device, err)
			}
			return
		}

		// Decode length (big-endian)
		packetLen := uint32(lengthBuf[0])<<24 | uint32(lengthBuf[1])<<16 |
		             uint32(lengthBuf[2])<<8 | uint32(lengthBuf[3])

		if packetLen > 65536 {
			a.stats.ReceiveErrors.Add(1)
			log.Printf("Invalid packet length from vsock: %d (max 65536)", packetLen)
			return
		}

		// Read exact packet data from vsock
		// CRITICAL: Use io.ReadFull to guarantee reading exactly packetLen bytes
		packet := buf[:packetLen]
		if _, err := io.ReadFull(a.vsockConn, packet); err != nil {
			if err != io.EOF {
				a.stats.ReceiveErrors.Add(1)
				log.Printf("vsock read data error on %s: %v", a.Device, err)
			}
			return
		}

		reversePackets.Add(1)

		// Log first few packets for debugging
		if reversePackets.Load() <= 5 {
			log.Printf("vsock->TAP: device=%s bytes=%d packet=%d", a.Device, packetLen, reversePackets.Load())
		}

		a.stats.PacketsReceived.Add(1)
		a.stats.BytesReceived.Add(uint64(packetLen))

		// Write to TAP device
		_, err := a.tap.Write(packet)
		if err != nil {
			a.stats.SendErrors.Add(1)
			log.Printf("TAP write error on %s: %v", a.Device, err)
			return
		}

		a.stats.PacketsSent.Add(1)
		a.stats.BytesSent.Add(uint64(packetLen))
	}
}

// GetStats returns a copy of the current statistics
func (a *NetworkAttachment) GetStats() Stats {
	a.statsLock.RLock()
	defer a.statsLock.RUnlock()

	// Create new Stats with current values
	var stats Stats
	stats.PacketsSent.Store(a.stats.PacketsSent.Load())
	stats.PacketsReceived.Store(a.stats.PacketsReceived.Load())
	stats.BytesSent.Store(a.stats.BytesSent.Load())
	stats.BytesReceived.Store(a.stats.BytesReceived.Load())
	stats.SendErrors.Store(a.stats.SendErrors.Load())
	stats.ReceiveErrors.Store(a.stats.ReceiveErrors.Load())

	return stats
}

// DHCPLease represents a DHCP lease with all configuration
type DHCPLease struct {
	IP      string
	Netmask uint32
	Gateway string
	DNS     []string
}

// performDHCP performs a DHCP request and returns the lease
func performDHCP(interfaceName string, mac net.HardwareAddr) (*DHCPLease, error) {
	log.Printf("Performing DHCP on interface %s (MAC: %s)", interfaceName, mac.String())

	// Create DHCP client with 10 second timeout
	client, err := nclient4.New(interfaceName,
		nclient4.WithTimeout(10*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHCP client: %w", err)
	}
	defer client.Close()

	log.Printf("Sending DHCPDISCOVER on %s", interfaceName)

	// Perform DHCP 4-way handshake (DISCOVER -> OFFER -> REQUEST -> ACK)
	lease, err := client.Request(context.Background())
	if err != nil {
		return nil, fmt.Errorf("DHCP request failed: %w", err)
	}

	if lease == nil || lease.ACK == nil {
		return nil, fmt.Errorf("DHCP returned nil lease")
	}

	ack := lease.ACK

	log.Printf("Received DHCPACK: YourIP=%s ServerIP=%s", ack.YourIPAddr, ack.ServerIPAddr)

	// Extract IP address
	ip := ack.YourIPAddr.String()
	if ip == "" || ip == "0.0.0.0" {
		return nil, fmt.Errorf("DHCP did not provide an IP address")
	}

	// Extract subnet mask (Option 1)
	var netmask uint32 = 24 // Default to /24
	if maskOption := ack.Options.Get(dhcpv4.OptionSubnetMask); maskOption != nil {
		if len(maskOption) == 4 {
			mask := net.IPMask(maskOption)
			ones, _ := mask.Size()
			netmask = uint32(ones)
		}
	}

	// Extract gateway (Option 3 - Router)
	var gateway string
	if routerOption := ack.Options.Get(dhcpv4.OptionRouter); routerOption != nil && len(routerOption) >= 4 {
		gateway = net.IP(routerOption[:4]).String()
	}

	// Extract DNS servers (Option 6)
	var dns []string
	if dnsOption := ack.Options.Get(dhcpv4.OptionDomainNameServer); dnsOption != nil {
		// DNS option contains multiple 4-byte IP addresses
		for i := 0; i+3 < len(dnsOption); i += 4 {
			dnsIP := net.IP(dnsOption[i : i+4])
			dns = append(dns, dnsIP.String())
		}
	}

	log.Printf("DHCP lease details: IP=%s/%d Gateway=%s DNS=%v", ip, netmask, gateway, dns)

	return &DHCPLease{
		IP:      ip,
		Netmask: netmask,
		Gateway: gateway,
		DNS:     dns,
	}, nil
}

// configureDNS updates /etc/resolv.conf to use the network gateway as nameserver
// This allows containers to resolve DNS names via the helper VM's dnsmasq
func configureDNS(gateway string) error {
	// Create resolv.conf content with gateway as nameserver
	resolvConf := fmt.Sprintf("nameserver %s\n", gateway)

	// Write to /etc/resolv.conf with proper permissions (0644)
	if err := os.WriteFile("/etc/resolv.conf", []byte(resolvConf), 0644); err != nil {
		return fmt.Errorf("failed to write /etc/resolv.conf: %w", err)
	}

	log.Printf("Configured DNS: nameserver=%s", gateway)
	return nil
}
