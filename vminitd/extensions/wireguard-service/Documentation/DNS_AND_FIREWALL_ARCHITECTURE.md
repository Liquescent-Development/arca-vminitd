# DNS and Firewall Architecture

**Version**: 1.0
**Last Updated**: 2025-11-07
**Status**: Production

## Overview

This document describes the complete networking, DNS, and firewall architecture for Arca's WireGuard-based container networking. The architecture enables:

1. **Container DNS resolution** via embedded DNS server (127.0.0.11:53)
2. **Internet access** for containers via NAT/MASQUERADE
3. **Control plane security** - Isolation between vmnet control plane and container overlay networks
4. **Port mapping** - Publishing container ports on the vmnet interface
5. **Multi-network support** - Containers can attach to multiple WireGuard networks

## Network Topology

### Interfaces and Namespaces

```
┌────────────────────────────────────────────────────────────┐
│ Container VM (Linux)                                       │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Root Namespace                                       │  │
│  │                                                      │  │
│  │  eth0 (vmnet)          veth-root0           wg0      │  │
│  │  192.168.64.2/24  ←→  172.17.0.1/32    172.17.0.2/24 │  │
│  │       ↕                    ↕                  ↕      │  │
│  │   [vmnet gateway]    [container ns]    [WireGuard]   │  │
│  │   192.168.64.1           │                  │        │  │
│  │                          │                  │        │  │
│  │  DNS Server: 0.0.0.0:53 ←┼──────────────────┘        │  │
│  │  (listens on all IPs)    │                           │  │
│  └──────────────────────────┼───────────────────────────┘  │
│                             ↓                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Container Namespace (PID 1 process)                  │  │
│  │                                                      │  │
│  │  veth-cont0              eth0 (WireGuard)            │  │
│  │  172.17.0.2/32          172.17.0.2/24                │  │
│  │                                                      │  │
│  │  DNS: 127.0.0.11:53 (embedded-DNS)                   │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘
         ↑                                              ↑
         │                                              │
    vmnet interface                              WireGuard UDP
    (control plane)                              (overlay traffic)
         ↓                                              ↓
    macOS host                                  Other containers
    192.168.64.1                               (peer-to-peer mesh)
```

### Interface Roles

1. **eth0 (vmnet)** - Root namespace only
   - Control plane interface
   - Assigned IP: 192.168.64.2/24 (varies per container)
   - Gateway: 192.168.64.1 (macOS host)
   - Purpose: Communication with host, DNS forwarding, internet access
   - Security: Locked down by nftables (only WireGuard UDP and DNS responses allowed)

2. **veth-root0 / veth-cont0** - Virtual ethernet pair
   - Connects root namespace to container namespace
   - Root side: 172.17.0.1/32 (gateway for container)
   - Container side: 172.17.0.2/32
   - Purpose: Traffic forwarding between namespaces

3. **wg0 (WireGuard)** - Root namespace only
   - WireGuard overlay interface
   - Assigned IP: 172.17.0.2/24 (container's network IP)
   - Purpose: Encrypted peer-to-peer networking with other containers
   - Creates full mesh topology within each Docker network

## DNS Architecture

### Components

1. **Embedded DNS Server** (Go service)
   - Listens on: `0.0.0.0:53` (UDP)
   - Accessible at: `172.17.0.1:53`, `172.18.0.1:53`, etc. (gateway IPs)
   - Containers query: `127.0.0.11:53` (Docker convention)
   - Routes to gateway: iptables DNAT rule redirects 127.0.0.11 → gateway IP

2. **DNS Resolver** (internal component)
   - Maintains mapping: container name → IP address
   - Handles A (IPv4) queries for internal containers
   - Returns NODATA for AAAA (IPv6) queries (no IPv6 support yet)

3. **Upstream DNS** (dynamic)
   - Initially: `8.8.8.8:53`, `8.8.4.4:53` (fallback)
   - Updated on first network: `192.168.64.1:53` (vmnet gateway)
   - Forwards external queries to macOS DNS resolver

### DNS Query Flow

```
Container process
    ↓ query: google.com
127.0.0.11:53 (embedded-DNS address)
    ↓ DNAT rule (container namespace)
172.17.0.1:53 (gateway IP in container namespace)
    ↓ veth pair forwarding
0.0.0.0:53 (DNS server in root namespace)
    ↓ check internal resolver
Not found internally
    ↓ forward to upstream
192.168.64.1:53 (vmnet gateway - macOS DNS)
    ↓ macOS DNS resolver
Internet DNS servers
    ↓ response (from 192.168.64.1:53, src_port=53)
eth0 interface (INPUT chain)
    ↓ nftables rule: ACCEPT UDP src_port=53
DNS server receives response
    ↓ forward response to container
Container receives answer
```

### DNS Initialization Sequence

1. **Service Start** (`main.go`):
   - Create DNS resolver
   - Create DNS server with fallback DNS (`8.8.8.8`)
   - Start DNS server on `0.0.0.0:53`
   - Configure firewall rules

2. **First Network Added** (`hub.go:AddNetwork`):
   - Setup default route (discovers vmnet gateway)
   - Invoke callback: `onGatewayReady("192.168.64.1")`
   - DNS server updates upstream: `192.168.64.1:53`

3. **Container Name Added** (`main.go:AddPeer`):
   - Add DNS entry: `dnsResolver.AddEntry(networkId, name, containerID, ip, aliases)`
   - Now container name resolves internally

## Firewall Rules (nftables)

### Rule Priorities

nftables chains execute by priority (lower numbers run first):

- **Priority -150**: PREROUTING conntrack enablement
- **Priority -100**: PREROUTING DNAT (port mapping)
- **Priority -1**: INPUT port mapping acceptance
- **Priority 0**: INPUT/OUTPUT/FORWARD security rules
- **Priority 50**: POSTROUTING port mapping MASQUERADE
- **Priority 100**: POSTROUTING general MASQUERADE

### Tables and Chains

All rules use the `arca-wireguard` table (IPv4 family).

#### 1. PREROUTING Chains

**Chain: `prerouting-conntrack`** (Priority -150)
- **Purpose**: Enable connection tracking for ALL packets
- **Critical**: Must run before any other rules
- **Rule**: Touch `ct state` for all packets → ACCEPT
- **Why**: Without this, conntrack state (established/related/DNAT) is not set

**Chain: `prerouting-portmap`** (Priority -100, per port mapping)
- **Purpose**: DNAT incoming traffic from vmnet to container overlay
- **Rule**: Match `iifname eth0 && protocol && dport <host_port>` → DNAT to `<container_ip>:<container_port>`
- **Example**: TCP port 8080 on vmnet → 172.17.0.2:80
- **Created**: When `PublishPort()` is called

#### 2. INPUT Chains

**Chain: `input-portmap`** (Priority -1, per port mapping)
- **Purpose**: Accept port-mapped traffic arriving on eth0
- **Rule**: Match `iifname eth0 && protocol && dport <host_port>` → ACCEPT
- **Why**: Must run BEFORE security DROP rules
- **Created**: When `PublishPort()` is called

**Chain: `input-vmnet-security`** (Priority 0)
- **Purpose**: Security policy for vmnet interface (eth0)
- **Rules** (in order):

1. **ACCEPT DNS responses** (CRITICAL for embedded DNS)
   ```
   Match: iifname eth0 && protocol UDP && sport 53
   Action: ACCEPT
   ```
   - **Why**: DNS server queries vmnet gateway, responses come from src_port=53
   - **Without this**: DNS queries timeout (responses get DROPped)
   - **Note**: Must come BEFORE established/related rule

2. **ACCEPT established/related connections**
   ```
   Match: iifname eth0 && ct state established,related
   Action: ACCEPT
   ```
   - **Why**: Allow return traffic for connections initiated from container
   - **Covers**: HTTP responses, TCP handshakes, etc.

3. **ACCEPT WireGuard UDP traffic**
   ```
   Match: iifname eth0 && protocol UDP && dport >= 51820
   Action: ACCEPT
   ```
   - **Why**: WireGuard underlay uses ports 51820, 51821, 51822, etc.
   - **Note**: One port per network (wg0=51820, wg1=51821, wg2=51822)

4. **DROP all other traffic on eth0**
   ```
   Match: iifname eth0
   Action: DROP
   ```
   - **Why**: vmnet is control plane underlay, should not receive overlay traffic
   - **Security**: Prevents host from accessing container services directly

**Chain: `input-security`** (Priority 0, from `netns.go`)
- **Purpose**: Block DNS queries arriving on eth0 from host
- **Rule**: Match `iifname eth0 && protocol UDP && dport 53` → DROP
- **Why**: DNS server should only be accessed via veth from containers, not from host
- **Note**: Does NOT block DNS responses (different ports)

#### 3. OUTPUT Chains

**Chain: `output-vmnet-security`** (Priority 0)
- **Purpose**: Enable conntrack for outgoing packets on eth0
- **Rule**: Match `oifname eth0` → Touch `ct state` → ACCEPT
- **Critical**: Without this, DNS responses don't match established/related state
- **Why**: Ensures DNS queries are tracked so responses are accepted

#### 4. FORWARD Chains

**Chain: `forward-portmap`** (Priority -1, per port mapping)
- **Purpose**: Accept forwarded traffic for port mappings
- **Rule**: Match `protocol && ct state established,related && dport <container_port>` → ACCEPT
- **Why**: Return traffic from container → macOS must be accepted before security DROP

**Chain: `forward-vmnet-security`** (Priority -1)
- **Purpose**: Accept port mapping return traffic
- **Rule**: Match `ct state established,related` → ACCEPT
- **Critical**: Must run BEFORE control plane DROP rule

**Chain: `forward-security`** (Priority 0, regular chain - jumped to)
- **Purpose**: Block container overlay → control plane access
- **Rule**: Match `src 172.16.0.0/12 && dst 192.168.0.0/16` → DROP
- **Why**: Containers should not access control plane network
- **Security**: Prevents containers from accessing macOS services on vmnet

#### 5. POSTROUTING Chains

**Chain: `postrouting-portmap`** (Priority 50, per port mapping)
- **Purpose**: MASQUERADE port-mapped connections
- **Rule**: Match `protocol && ct status dnat && dport <container_port>` → MASQUERADE
- **Why**: Ensures conntrack properly tracks DNAT'd connections
- **Effect**: Source becomes gateway IP (e.g., 172.17.0.1)

**Chain: `postrouting-nat`** (Priority 100)
- **Purpose**: MASQUERADE internet-bound traffic
- **Rule**: Match `oifname eth0 && dst != 192.168.0.0/16` → MASQUERADE
- **Why**: Allows containers to access internet via vmnet gateway
- **Critical exclusion**: Does NOT masquerade traffic to 192.168.0.0/16 (control plane)
- **Why exclusion**: DNS queries to gateway (192.168.64.1) must preserve source IP for responses

## Routing Configuration

### Root Namespace Routes

```
# Default route (added when first network created)
default via 192.168.64.1 dev eth0

# Container network route (added per network)
172.17.0.2/32 dev veth-root0 scope link

# WireGuard peer routes (added per peer)
172.17.0.3/32 dev wg0 scope link
172.17.0.4/32 dev wg0 scope link
```

### Container Namespace Routes

```
# Default route (via veth to root namespace)
default via 172.17.0.1 dev veth-cont0

# Container's own IP (WireGuard)
172.17.0.2/24 dev eth0 scope link
```

### Route Discovery Process

**Function**: `SetupDefaultRoute()` in `netns.go`

1. Get eth0 interface (vmnet)
2. Get eth0's IP address (e.g., 192.168.64.2/24)
3. Calculate gateway: `network + 1` (e.g., 192.168.64.0 + 1 = 192.168.64.1)
4. Check if default route already exists (avoid duplicates)
5. Add default route: `0.0.0.0/0 via 192.168.64.1 dev eth0`
6. **Return gateway IP** for DNS configuration

**Timing**: Called in `hub.go:AddNetwork()` when `networkIndex == 0` (first network only)

**Callback**: Invokes `onGatewayReady(gatewayIP)` → `dnsServer.UpdateUpstreamDNS([gatewayIP+":53"])`

## Use Cases and Data Flows

### Use Case 1: Container DNS Resolution

**Scenario**: Container process queries `google.com`

```
1. Container process: getaddrinfo("google.com")
2. glibc resolver queries: 127.0.0.11:53 (from /etc/resolv.conf)
3. iptables DNAT: 127.0.0.11:53 → 172.17.0.1:53
4. veth forwards to root namespace
5. DNS server receives query on 0.0.0.0:53
6. Check internal resolver: "google.com" not found
7. Forward to upstream: 192.168.64.1:53
8. Query packet: 192.168.64.2:random → 192.168.64.1:53
9. POSTROUTING: No MASQUERADE (destination is 192.168.0.0/16)
10. vmnet gateway (macOS) receives query, queries internet DNS
11. Response packet: 192.168.64.1:53 → 192.168.64.2:random
12. INPUT chain: ACCEPT (rule 1: UDP src_port=53)
13. DNS server receives response
14. Forward response to container via veth
15. Container receives answer
```

**Key Rules**:
- INPUT RULE 1: ACCEPT UDP src_port=53 (DNS responses)
- POSTROUTING: Exclude 192.168.0.0/16 from MASQUERADE
- OUTPUT: Touch ct state for tracking

### Use Case 2: Container Internet Access

**Scenario**: Container makes HTTP request to `1.1.1.1:80`

```
1. Container sends: TCP SYN to 1.1.1.1:80
2. Container routing: via default gateway 172.17.0.1
3. veth forwards to root namespace
4. Root namespace routing: via default gateway 192.168.64.1 dev eth0
5. POSTROUTING: Match oifname eth0, dst=1.1.1.1 (not 192.168.0.0/16)
6. MASQUERADE: Change src to 192.168.64.2
7. Packet sent: 192.168.64.2:random → 1.1.1.1:80
8. vmnet forwards to macOS → internet
9. Response: 1.1.1.1:80 → 192.168.64.2:random
10. INPUT: ACCEPT (established connection)
11. Reverse MASQUERADE: Change dst to original container IP
12. Forward to container via veth
13. Container receives response
```

**Key Rules**:
- POSTROUTING: MASQUERADE on eth0 (excluding control plane)
- INPUT: ACCEPT established/related
- FORWARD: Allow established/related

### Use Case 3: Port Mapping (Docker -p 8080:80)

**Scenario**: Publish container port 80 on host port 8080

```
# Setup (PublishPort called):
1. Create PREROUTING DNAT: eth0 dport 8080 → 172.17.0.2:80
2. Create INPUT ACCEPT: eth0 dport 8080 → ACCEPT (priority -1)
3. Create POSTROUTING MASQUERADE: ct status dnat, dport 80 → MASQUERADE

# Traffic flow:
1. macOS sends: TCP SYN to 192.168.64.2:8080
2. PREROUTING: DNAT to 172.17.0.2:80 (mark as DNAT in conntrack)
3. INPUT: ACCEPT (priority -1, before security DROP)
4. FORWARD: ACCEPT (established/related)
5. Packet forwarded to container via veth
6. Container receives: TCP SYN on port 80
7. Container responds: TCP SYN-ACK from port 80
8. POSTROUTING: Match ct status dnat, MASQUERADE
9. Response packet: 192.168.64.2:80 → macOS (conntrack handles reverse DNAT)
10. macOS receives: TCP SYN-ACK from port 8080
```

**Key Rules**:
- PREROUTING DNAT: Port mapping translation
- INPUT priority -1: Accept before security DROP
- POSTROUTING MASQUERADE: Required for DNAT'd connections
- FORWARD: Allow established/related

### Use Case 4: Container-to-Container (WireGuard)

**Scenario**: Container A (172.17.0.2) pings Container B (172.17.0.3)

```
1. Container A sends: ICMP echo request to 172.17.0.3
2. Container namespace routing: via 172.17.0.1 (veth gateway)
3. veth forwards to root namespace
4. Root namespace routing: 172.17.0.3/32 dev wg0
5. WireGuard encrypts packet
6. UDP packet sent: 192.168.64.2:51820 → 192.168.64.3:51820
7. Container B receives encrypted packet on eth0
8. INPUT: ACCEPT (UDP dport 51820)
9. WireGuard decrypts packet
10. wg0 interface receives: ICMP echo request
11. Container B responds: ICMP echo reply to 172.17.0.2
12. WireGuard encrypts, sends via eth0
13. Container A receives on eth0, INPUT accepts
14. WireGuard decrypts, delivers to wg0
15. Forwarded to container namespace via veth
16. Container A receives reply
```

**Key Rules**:
- INPUT: ACCEPT UDP dport >= 51820 (WireGuard)
- No MASQUERADE needed (overlay traffic)

## Control Plane Isolation

### Security Goals

1. **Block container overlay → control plane access**
   - Containers cannot access services on 192.168.64.1 (macOS)
   - Exception: DNS queries (required for name resolution)

2. **Block host → container direct access**
   - macOS cannot directly connect to container services
   - Exception: Port-mapped ports (explicitly published)

3. **Allow DNS forwarding**
   - Containers query DNS via embedded server
   - DNS server forwards to vmnet gateway (192.168.64.1:53)
   - Responses must be received (src_port=53)

### Implementation

**FORWARD Security** (`forward-security` chain):
```
Match: src 172.16.0.0/12 && dst 192.168.0.0/16
Action: DROP
```
- Blocks ALL overlay → control plane traffic
- 172.16.0.0/12: Docker/container overlay networks
- 192.168.0.0/16: vmnet control plane subnet

**INPUT Security** (`input-vmnet-security` chain):
```
Match: iifname eth0 && protocol UDP && dport 53
Action: DROP (via input-security chain)
```
- Blocks DNS queries arriving on eth0 from host
- Containers query via veth, not eth0

**DNS Exception**:
```
Match: iifname eth0 && protocol UDP && sport 53
Action: ACCEPT (RULE 1 in input-vmnet-security)
```
- **Critical**: Allows DNS responses from vmnet gateway
- Must come BEFORE established/related rule
- **Why separate rule**: Conntrack may not mark DNS responses as established

**POSTROUTING Exclusion**:
```
Match: oifname eth0 && dst != 192.168.0.0/16
Action: MASQUERADE
```
- Does NOT masquerade control plane traffic
- Preserves source IP for DNS queries to gateway
- Allows responses to find their way back

## Troubleshooting Guide

### DNS Queries Timing Out

**Symptoms**:
- `nslookup google.com` times out
- Container cannot resolve external names
- Logs show: `read udp 192.168.64.2:random->192.168.64.1:53: i/o timeout`

**Root Cause**:
- DNS responses from vmnet gateway (src_port=53) are being blocked by INPUT chain

**Fix**:
- Ensure INPUT RULE 1 exists: `ACCEPT UDP src_port=53 on eth0`
- This rule must come BEFORE established/related rule
- Check with: `grep "ACCEPT UDP from vmnet gateway port 53" bootlog`

**Prevention**:
- Never remove or reorder INPUT RULE 1
- Always test DNS after modifying INPUT chain

### Intermittent DNS Failures

**Symptoms**:
- DNS works sometimes, fails other times
- AAAA queries succeed, A queries fail (or vice versa)

**Root Cause**:
- Race condition in conntrack state
- Multiple chains at same priority executing in undefined order

**Fix**:
- Use explicit ACCEPT rule for DNS responses (src_port=53)
- Do not rely solely on established/related rule

### Port Mapping Not Working

**Symptoms**:
- Cannot connect to published port from macOS
- Connection refused or timeout

**Checks**:
1. **INPUT chain priority**: Ensure `input-portmap` priority is -1 (before security DROP)
2. **DNAT rule**: Verify PREROUTING DNAT rule exists for the port
3. **MASQUERADE rule**: Ensure POSTROUTING MASQUERADE for ct status dnat

### Internet Access Not Working

**Symptoms**:
- Container cannot reach external IPs
- DNS works, but HTTP/HTTPS fails

**Checks**:
1. **Default route**: Verify `ip route` shows default via vmnet gateway
2. **MASQUERADE rule**: Ensure POSTROUTING MASQUERADE exists
3. **IP forwarding**: Check `/proc/sys/net/ipv4/ip_forward` is 1

**Debug**:
```bash
# From root namespace in container:
ip route
# Should show: default via 192.168.64.1 dev eth0

cat /proc/sys/net/ipv4/ip_forward
# Should show: 1

# Check MASQUERADE rule
grep "MASQUERADE on eth0" bootlog
```

### Control Plane Leakage

**Symptoms**:
- Container can access macOS services directly
- Security violation

**Checks**:
1. **FORWARD security**: Verify DROP rule for 172.16.0.0/12 → 192.168.0.0/16
2. **Rule priority**: Ensure security rule runs after port mapping rules

**Test**:
```bash
# From container, this should FAIL:
curl http://192.168.64.1:8080

# This should SUCCEED (DNS exception):
nslookup google.com
```

## Modification Guidelines

### Before Making Changes

1. **Read this document completely**
2. **Understand the rule priorities** - Order matters!
3. **Test DNS first** - It's the most fragile component
4. **Use counters** - Add `&expr.Counter{}` to debug rules
5. **Check established/related** - Don't break existing connections

### Safe Modification Process

1. **Add new rule**:
   - Determine correct priority
   - Place before or after existing rules carefully
   - Add counter for debugging

2. **Test immediately**:
   ```bash
   # Test DNS
   docker exec <container> nslookup google.com

   # Test internet
   docker exec <container> wget -O- http://1.1.1.1

   # Test port mapping
   curl http://192.168.64.X:<port>
   ```

3. **Check bootlog**:
   ```bash
   ./scripts/get-bootlog.sh <container-id> | grep -E "(DNS|nftables|Adding)"
   ```

4. **Verify with multiple queries**:
   ```bash
   for i in 1 2 3 4 5; do
     docker exec <container> nslookup github.com
   done
   ```

### Common Pitfalls

1. **Removing DNS src_port=53 rule** ❌
   - Breaks DNS forwarding
   - Queries timeout

2. **Masquerading control plane traffic** ❌
   - Breaks DNS responses
   - Prevents reverse path

3. **Wrong rule priority** ❌
   - Security DROP runs before port mapping ACCEPT
   - Port mapping broken

4. **Multiple chains at same priority** ⚠️
   - Undefined execution order
   - Use priority offsets (-1, 0, 1)

5. **Forgetting conntrack enablement** ❌
   - DNAT status not set
   - MASQUERADE rules don't match

## Version History

### v1.0 (2025-11-07)
- Initial production version
- DNS forwarding via vmnet gateway working
- All firewall rules documented
- Routing configuration complete
- Control plane isolation verified

## References

- WireGuard service: `containerization/vminitd/extensions/wireguard-service/`
- DNS implementation: `internal/dns/server.go`
- Firewall rules: `internal/wireguard/portmap.go`, `internal/wireguard/netns.go`
- Main service: `cmd/arca-wireguard-service/main.go`
- Testing scripts: `scripts/test-dns.sh`, `scripts/get-bootlog.sh`