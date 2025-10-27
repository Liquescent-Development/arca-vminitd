package dns

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// GetDefaultGateway reads /proc/net/route to find the default gateway IP
// Falls back to calculating gateway from first interface if no default route exists
func GetDefaultGateway() (string, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("failed to open /proc/net/route: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	if !scanner.Scan() {
		return "", fmt.Errorf("empty route table")
	}

	var firstInterface string
	var firstDestination string

	// Find default route (destination 00000000)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// Format: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
		if len(fields) < 8 {
			continue
		}

		iface := fields[0]
		destination := fields[1]
		gateway := fields[2]

		// Save first interface info for fallback
		if firstInterface == "" {
			firstInterface = iface
			firstDestination = destination
		}

		// Default route has destination 00000000
		if destination == "00000000" {
			// Gateway is in hex format (little-endian)
			ip, err := parseHexIP(gateway)
			if err != nil {
				return "", fmt.Errorf("failed to parse gateway IP: %v", err)
			}
			return ip, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading route table: %v", err)
	}

	// No default route found - calculate gateway as .1 of first network
	// For bridge networks, the gateway is always the .1 address
	// Example: 172.18.0.0/24 network -> gateway is 172.18.0.1
	if firstInterface != "" {
		networkIP, err := parseHexIP(firstDestination)
		if err != nil {
			return "", fmt.Errorf("failed to parse network IP: %v", err)
		}

		// Calculate gateway as network base + 1
		// Split IP into octets
		parts := strings.Split(networkIP, ".")
		if len(parts) != 4 {
			return "", fmt.Errorf("invalid IP format: %s", networkIP)
		}

		// Gateway is .1 of the network (assuming /24)
		gateway := fmt.Sprintf("%s.%s.%s.1", parts[0], parts[1], parts[2])
		return gateway, nil
	}

	return "", fmt.Errorf("no routes found")
}

// parseHexIP converts hex IP from /proc/net/route to dotted decimal
// Example: 0100A8C0 -> 192.168.0.1 (little-endian)
func parseHexIP(hexIP string) (string, error) {
	if len(hexIP) != 8 {
		return "", fmt.Errorf("invalid hex IP length: %s", hexIP)
	}

	// Parse as little-endian bytes
	var bytes [4]byte
	for i := 0; i < 4; i++ {
		var b byte
		_, err := fmt.Sscanf(hexIP[i*2:i*2+2], "%02X", &b)
		if err != nil {
			return "", fmt.Errorf("failed to parse hex byte: %v", err)
		}
		bytes[3-i] = b // Reverse byte order (little-endian to big-endian)
	}

	return fmt.Sprintf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]), nil
}
