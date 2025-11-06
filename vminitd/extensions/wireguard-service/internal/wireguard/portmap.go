package wireguard

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// PortMapping represents a published port mapping
type PortMapping struct {
	Protocol      string // "tcp" or "udp"
	HostPort      uint32
	ContainerIP   string
	ContainerPort uint32
}

// PublishPort creates nftables rules to expose a container port on the vmnet interface
// This adds:
// 1. PREROUTING DNAT rule: vmnet_eth0:host_port → container_overlay_ip:container_port
// 2. INPUT ACCEPT rule: allow traffic to host_port on vmnet eth0
func PublishPort(protocol string, hostPort uint32, containerIP string, containerPort uint32) error {
	log.Printf("Publishing port: %s %d → %s:%d", protocol, hostPort, containerIP, containerPort)

	// Connect to nftables
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %w", err)
	}
	defer conn.Flush()

	// Get the arca-wireguard table (created during NAT setup)
	table := &nftables.Table{
		Name:   "arca-wireguard",
		Family: nftables.TableFamilyIPv4,
	}

	// Get or create PREROUTING chain for DNAT
	preroutingChain := &nftables.Chain{
		Name:     "prerouting-portmap",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	}

	// Try to find existing chain, create if not exists
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("failed to list chains: %w", err)
	}

	chainExists := false
	for _, c := range chains {
		if c.Table.Name == table.Name && c.Name == preroutingChain.Name {
			chainExists = true
			break
		}
	}

	if !chainExists {
		conn.AddChain(preroutingChain)
	}

	// Get or create INPUT chain for port filtering
	inputChain := &nftables.Chain{
		Name:     "input-portmap",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	}

	chainExists = false
	for _, c := range chains {
		if c.Table.Name == table.Name && c.Name == inputChain.Name {
			chainExists = true
			break
		}
	}

	if !chainExists {
		conn.AddChain(inputChain)
	}

	// Parse container IP
	containerIPAddr := net.ParseIP(containerIP)
	if containerIPAddr == nil {
		return fmt.Errorf("invalid container IP: %s", containerIP)
	}
	containerIPv4 := containerIPAddr.To4()
	if containerIPv4 == nil {
		return fmt.Errorf("container IP is not IPv4: %s", containerIP)
	}

	// Determine protocol number
	var protoNum byte
	if strings.ToLower(protocol) == "tcp" {
		protoNum = unix.IPPROTO_TCP
	} else if strings.ToLower(protocol) == "udp" {
		protoNum = unix.IPPROTO_UDP
	} else {
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	// RULE 1: PREROUTING DNAT rule (vmnet eth0 → container overlay IP)
	// Match: iifname eth0, protocol, dport host_port
	// Action: DNAT to container_ip:container_port
	log.Printf("Adding PREROUTING DNAT rule: eth0 %s dport %d → %s:%d", protocol, hostPort, containerIP, containerPort)

	hostPortBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(hostPortBytes, uint16(hostPort))

	containerPortBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(containerPortBytes, uint16(containerPort))

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: preroutingChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Match protocol
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{protoNum},
			},
			// Match destination port
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     hostPortBytes,
			},
			// DNAT: Immediate load container IP and port into registers
			&expr.Immediate{
				Register: 1,
				Data:     containerIPv4,
			},
			&expr.Immediate{
				Register: 2,
				Data:     containerPortBytes,
			},
			// NAT: DNAT to container_ip:container_port
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		},
	})

	// RULE 2: INPUT ACCEPT rule (allow traffic to published port)
	// Match: iifname eth0, protocol, dport host_port
	// Action: ACCEPT
	log.Printf("Adding INPUT ACCEPT rule: eth0 %s dport %d", protocol, hostPort)

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Match protocol
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{protoNum},
			},
			// Match destination port
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     hostPortBytes,
			},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables rules: %w", err)
	}

	log.Printf("✓ Port published successfully: %s %d → %s:%d", protocol, hostPort, containerIP, containerPort)
	return nil
}

// UnpublishPort removes nftables rules for a published port
// Removes both PREROUTING DNAT and INPUT ACCEPT rules
func UnpublishPort(protocol string, hostPort uint32) error {
	log.Printf("Unpublishing port: %s %d", protocol, hostPort)

	// Connect to nftables
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %w", err)
	}
	defer conn.Flush()

	// Get the arca-wireguard table
	table := &nftables.Table{
		Name:   "arca-wireguard",
		Family: nftables.TableFamilyIPv4,
	}

	// Determine protocol number
	var protoNum byte
	if strings.ToLower(protocol) == "tcp" {
		protoNum = unix.IPPROTO_TCP
	} else if strings.ToLower(protocol) == "udp" {
		protoNum = unix.IPPROTO_UDP
	} else {
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	hostPortBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(hostPortBytes, uint16(hostPort))

	// Find and delete matching rules in PREROUTING chain
	preroutingChain := &nftables.Chain{
		Name:  "prerouting-portmap",
		Table: table,
	}

	rules, err := conn.GetRules(table, preroutingChain)
	if err != nil {
		log.Printf("Warning: failed to get PREROUTING rules (chain may not exist): %v", err)
	} else {
		for _, rule := range rules {
			// Check if this rule matches our protocol and port
			if ruleMatchesPortMapping(rule, protoNum, hostPortBytes) {
				log.Printf("Deleting PREROUTING rule for %s:%d", protocol, hostPort)
				if err := conn.DelRule(rule); err != nil {
					log.Printf("Warning: failed to delete PREROUTING rule: %v", err)
				}
			}
		}
	}

	// Find and delete matching rules in INPUT chain
	inputChain := &nftables.Chain{
		Name:  "input-portmap",
		Table: table,
	}

	rules, err = conn.GetRules(table, inputChain)
	if err != nil {
		log.Printf("Warning: failed to get INPUT rules (chain may not exist): %v", err)
	} else {
		for _, rule := range rules {
			// Check if this rule matches our protocol and port
			if ruleMatchesPortMapping(rule, protoNum, hostPortBytes) {
				log.Printf("Deleting INPUT rule for %s:%d", protocol, hostPort)
				if err := conn.DelRule(rule); err != nil {
					log.Printf("Warning: failed to delete INPUT rule: %v", err)
				}
			}
		}
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables rules: %w", err)
	}

	log.Printf("✓ Port unpublished successfully: %s %d", protocol, hostPort)
	return nil
}

// ruleMatchesPortMapping checks if an nftables rule matches a given protocol and port
func ruleMatchesPortMapping(rule *nftables.Rule, protoNum byte, portBytes []byte) bool {
	matchesProto := false
	matchesPort := false

	for i, e := range rule.Exprs {
		// Check for protocol match
		if cmp, ok := e.(*expr.Cmp); ok {
			if len(cmp.Data) == 1 && cmp.Data[0] == protoNum {
				matchesProto = true
			}
		}

		// Check for port match
		if cmp, ok := e.(*expr.Cmp); ok {
			if len(cmp.Data) == 2 && cmp.Data[0] == portBytes[0] && cmp.Data[1] == portBytes[1] {
				// Verify previous expression is a transport header payload (offset 2 = dport)
				if i > 0 {
					if payload, ok := rule.Exprs[i-1].(*expr.Payload); ok {
						if payload.Base == expr.PayloadBaseTransportHeader && payload.Offset == 2 {
							matchesPort = true
						}
					}
				}
			}
		}
	}

	return matchesProto && matchesPort
}

// ConfigureDefaultVmnetSecurity sets up default INPUT rules to block all vmnet traffic except WireGuard
// This secures the vmnet interface as WireGuard underlay only
func ConfigureDefaultVmnetSecurity() error {
	log.Printf("Configuring default vmnet security (block all except WireGuard UDP)")

	// Connect to nftables
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %w", err)
	}
	defer conn.Flush()

	// Get the arca-wireguard table (should already exist from NAT setup)
	table := &nftables.Table{
		Name:   "arca-wireguard",
		Family: nftables.TableFamilyIPv4,
	}

	// Create INPUT security chain
	// Priority -1 runs before portmap rules (which use ChainPriorityFilter = 0)
	filterPriority := nftables.ChainPriorityFilter
	securityPriority := *filterPriority - 1
	inputChain := &nftables.Chain{
		Name:     "input-vmnet-security",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &securityPriority, // Higher priority than portmap rules
	}

	// Try to find existing chain, create if not exists
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("failed to list chains: %w", err)
	}

	chainExists := false
	for _, c := range chains {
		if c.Table.Name == table.Name && c.Name == inputChain.Name {
			chainExists = true
			break
		}
	}

	if !chainExists {
		conn.AddChain(inputChain)
	}

	// RULE 1: ACCEPT established and related connections
	log.Printf("Adding INPUT rule: ACCEPT established,related connections on eth0")
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Match connection state: established or related
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x00, 0x00, 0x00, 0x06}, // ESTABLISHED | RELATED
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// RULE 2: ACCEPT WireGuard UDP traffic (port 51820 and higher)
	// We use a range check: dport >= 51820
	log.Printf("Adding INPUT rule: ACCEPT UDP port 51820+ on eth0 (WireGuard underlay)")

	minPort := uint16(51820)
	minPortBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(minPortBytes, minPort)

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Match protocol: UDP
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},
			// Match destination port >= 51820
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpGte,
				Register: 1,
				Data:     minPortBytes,
			},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// RULE 3: DROP all other traffic on eth0 (vmnet)
	log.Printf("Adding INPUT rule: DROP all other traffic on eth0 (vmnet secured as underlay)")
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Verdict: DROP
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables rules: %w", err)
	}

	log.Printf("✓ Default vmnet security configured successfully")
	return nil
}
