// Package tap provides TAP device management for Linux
package tap

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// /dev/net/tun device path
	tunDevice = "/dev/net/tun"

	// TAP device type
	iffTAP   = 0x0002
	iffNOPI  = 0x1000

	// Network configuration ioctls
	TUNSETIFF    = 0x400454ca
	SIOCSIFADDR  = 0x8916
	SIOCSIFNETMASK = 0x891c
	SIOCSIFFLAGS = 0x8914
	SIOCGIFFLAGS = 0x8913
	SIOCSIFHWADDR = 0x8924

	// Interface flags
	IFF_UP = 0x1
	IFF_RUNNING = 0x40

	// Hardware address type (Ethernet)
	ARPHRD_ETHER = 1

	// Netlink constants (Linux-specific, not in unix package on macOS)
	AF_NETLINK         = 16
	NETLINK_ROUTE      = 0
	RTM_NEWROUTE       = 24
	NLM_F_REQUEST      = 0x1
	NLM_F_CREATE       = 0x400
	NLM_F_EXCL         = 0x200
	NLM_F_ACK          = 0x4
	RT_TABLE_MAIN      = 254
	RTPROT_BOOT        = 3
	RT_SCOPE_UNIVERSE  = 0
	RTN_UNICAST        = 1
	RTA_GATEWAY        = 5
	RTA_OIF            = 4
	NLMSG_ERROR        = 2
)

// sockaddrNetlink is the netlink socket address (not in unix package on macOS)
type sockaddrNetlink struct {
	Family uint16
	Pad    uint16
	Pid    uint32
	Groups uint32
}

// ifreq structure for ioctl calls
type ifreq struct {
	ifrName  [unix.IFNAMSIZ]byte
	ifrFlags uint16
	_        [22]byte // padding to match kernel struct size
}

// ifrReqAddr structure for IP address configuration
type ifrReqAddr struct {
	ifrName [unix.IFNAMSIZ]byte
	ifrAddr unix.RawSockaddrInet4
	_       [8]byte // padding
}

// ifrReqHWAddr structure for MAC address configuration
type ifrReqHWAddr struct {
	ifrName   [unix.IFNAMSIZ]byte
	ifrHWAddr unix.RawSockaddr
	_         [8]byte // padding
}

// TAP represents a TAP network device
type TAP struct {
	file *os.File
	name string
	mac  net.HardwareAddr
}

// Create creates a new TAP device with the specified name and optional MAC address
// If macAddr is empty, a random MAC address will be generated
func Create(name string, macAddr string) (*TAP, error) {
	// Open /dev/net/tun in blocking mode
	// Blocking I/O is fine since we're in dedicated goroutines
	fd, err := unix.Open(tunDevice, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", tunDevice, err)
	}

	// Prepare ifreq structure
	var ifr ifreq
	copy(ifr.ifrName[:], name)
	ifr.ifrFlags = iffTAP | iffNOPI

	// Create TAP device via TUNSETIFF ioctl
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF ioctl failed: %v", errno)
	}

	// Create os.File from fd for compatibility
	file := os.NewFile(uintptr(fd), tunDevice)

	// Parse or generate MAC address
	var mac net.HardwareAddr
	if macAddr != "" {
		// Use provided MAC address
		mac, err = net.ParseMAC(macAddr)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to parse MAC address %q: %w", macAddr, err)
		}
	} else {
		// Generate random MAC address (locally administered)
		mac = make(net.HardwareAddr, 6)
		if _, err := rand.Read(mac); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to generate MAC address: %w", err)
		}
		// Set locally administered bit, clear multicast bit
		mac[0] = (mac[0] & 0xfe) | 0x02
	}

	tap := &TAP{
		file: file,
		name: name,
		mac:  mac,
	}

	// Set MAC address
	if err := tap.setMAC(mac); err != nil {
		tap.Close()
		return nil, fmt.Errorf("failed to set MAC address: %w", err)
	}

	return tap, nil
}

// SetIP configures the IP address and netmask for the TAP device
func (t *TAP) SetIP(ipAddr string, netmask uint32) error {
	// Parse IP address
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipAddr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("not an IPv4 address: %s", ipAddr)
	}

	// Open socket for ioctl
	sockFd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer unix.Close(sockFd)

	// Set IP address
	var ifrAddr ifrReqAddr
	copy(ifrAddr.ifrName[:], t.name)
	ifrAddr.ifrAddr.Family = unix.AF_INET
	copy(ifrAddr.ifrAddr.Addr[:], ip4)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(sockFd),
		uintptr(SIOCSIFADDR),
		uintptr(unsafe.Pointer(&ifrAddr)),
	)
	if errno != 0 {
		return fmt.Errorf("SIOCSIFADDR ioctl failed: %v", errno)
	}

	// Set netmask
	mask := net.CIDRMask(int(netmask), 32)
	var ifrMask ifrReqAddr
	copy(ifrMask.ifrName[:], t.name)
	ifrMask.ifrAddr.Family = unix.AF_INET
	copy(ifrMask.ifrAddr.Addr[:], mask)

	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(sockFd),
		uintptr(SIOCSIFNETMASK),
		uintptr(unsafe.Pointer(&ifrMask)),
	)
	if errno != 0 {
		return fmt.Errorf("SIOCSIFNETMASK ioctl failed: %v", errno)
	}

	return nil
}

// BringUp brings the TAP interface up
func (t *TAP) BringUp() error {
	sockFd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer unix.Close(sockFd)

	// Get current flags
	var ifr ifreq
	copy(ifr.ifrName[:], t.name)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(sockFd),
		uintptr(SIOCGIFFLAGS),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return fmt.Errorf("SIOCGIFFLAGS ioctl failed: %v", errno)
	}

	// Set UP and RUNNING flags
	ifr.ifrFlags |= IFF_UP | IFF_RUNNING

	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(sockFd),
		uintptr(SIOCSIFFLAGS),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return fmt.Errorf("SIOCSIFFLAGS ioctl failed: %v", errno)
	}

	return nil
}

// setMAC sets the MAC address for the TAP device
func (t *TAP) setMAC(mac net.HardwareAddr) error {
	sockFd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer unix.Close(sockFd)

	var ifrHW ifrReqHWAddr
	copy(ifrHW.ifrName[:], t.name)
	ifrHW.ifrHWAddr.Family = ARPHRD_ETHER
	for i := 0; i < len(mac) && i < len(ifrHW.ifrHWAddr.Data); i++ {
		ifrHW.ifrHWAddr.Data[i] = int8(mac[i])
	}

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(sockFd),
		uintptr(SIOCSIFHWADDR),
		uintptr(unsafe.Pointer(&ifrHW)),
	)
	if errno != 0 {
		return fmt.Errorf("SIOCSIFHWADDR ioctl failed: %v", errno)
	}

	return nil
}

// Read reads a packet from the TAP device using blocking I/O
func (t *TAP) Read(buf []byte) (int, error) {
	n, err := unix.Read(int(t.file.Fd()), buf)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Write writes a packet to the TAP device using blocking I/O
func (t *TAP) Write(buf []byte) (int, error) {
	n, err := unix.Write(int(t.file.Fd()), buf)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Name returns the TAP device name
func (t *TAP) Name() string {
	return t.name
}

// MAC returns the MAC address
func (t *TAP) MAC() net.HardwareAddr {
	return t.mac
}

// AddDefaultRoute adds a default route via the specified gateway using netlink
func (t *TAP) AddDefaultRoute(gateway string) error {
	// Parse gateway IP
	gwIP := net.ParseIP(gateway)
	if gwIP == nil {
		return fmt.Errorf("invalid gateway IP: %s", gateway)
	}
	gwIP4 := gwIP.To4()
	if gwIP4 == nil {
		return fmt.Errorf("not an IPv4 gateway: %s", gateway)
	}

	// Get interface index
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", t.name, err)
	}

	// Create netlink socket
	fd, err := unix.Socket(AF_NETLINK, unix.SOCK_RAW, NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("failed to create netlink socket: %w", err)
	}
	defer unix.Close(fd)

	// Bind netlink socket
	addr := &sockaddrNetlink{Family: AF_NETLINK}
	sa := (*unix.RawSockaddrAny)(unsafe.Pointer(addr))
	if _, _, errno := unix.Syscall(unix.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(sa)), unsafe.Sizeof(*addr)); errno != 0 {
		return fmt.Errorf("failed to bind netlink socket: %v", errno)
	}

	// Build RTM_NEWROUTE message for default route (0.0.0.0/0 via gateway)
	// Message: nlmsghdr + rtmsg + RTA_GATEWAY + RTA_OIF

	const (
		nlmsgHdrLen = 16  // sizeof(struct nlmsghdr)
		rtmsgLen    = 12  // sizeof(struct rtmsg)
		rtaHdrLen   = 4   // sizeof(struct rtattr)
	)

	// Align to 4-byte boundary
	align := func(n int) int {
		return (n + 3) & ^3
	}

	// RTA_GATEWAY: header (4) + IPv4 (4) = 8 bytes aligned
	gwAttrLen := align(rtaHdrLen + 4)
	// RTA_OIF: header (4) + uint32 (4) = 8 bytes aligned
	oifAttrLen := align(rtaHdrLen + 4)

	msgLen := nlmsgHdrLen + rtmsgLen + gwAttrLen + oifAttrLen

	buf := make([]byte, msgLen)
	pos := 0

	// nlmsghdr
	*(*uint32)(unsafe.Pointer(&buf[pos])) = uint32(msgLen) // len
	pos += 4
	*(*uint16)(unsafe.Pointer(&buf[pos])) = RTM_NEWROUTE // type
	pos += 2
	*(*uint16)(unsafe.Pointer(&buf[pos])) = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK // flags
	pos += 2
	*(*uint32)(unsafe.Pointer(&buf[pos])) = 1 // seq
	pos += 4
	*(*uint32)(unsafe.Pointer(&buf[pos])) = 0 // pid
	pos += 4

	// rtmsg
	buf[pos] = unix.AF_INET           // family
	buf[pos+1] = 0                    // dst_len (0 for default route)
	buf[pos+2] = 0                    // src_len
	buf[pos+3] = 0                    // tos
	buf[pos+4] = RT_TABLE_MAIN   // table
	buf[pos+5] = RTPROT_BOOT     // protocol
	buf[pos+6] = RT_SCOPE_UNIVERSE // scope
	buf[pos+7] = RTN_UNICAST     // type
	*(*uint32)(unsafe.Pointer(&buf[pos+8])) = 0 // flags
	pos += rtmsgLen

	// RTA_GATEWAY
	*(*uint16)(unsafe.Pointer(&buf[pos])) = uint16(rtaHdrLen + 4) // len
	pos += 2
	*(*uint16)(unsafe.Pointer(&buf[pos])) = RTA_GATEWAY // type
	pos += 2
	copy(buf[pos:], gwIP4)
	pos += 4
	pos = align(pos)

	// RTA_OIF (output interface)
	*(*uint16)(unsafe.Pointer(&buf[pos])) = uint16(rtaHdrLen + 4) // len
	pos += 2
	*(*uint16)(unsafe.Pointer(&buf[pos])) = RTA_OIF // type
	pos += 2
	*(*uint32)(unsafe.Pointer(&buf[pos])) = uint32(iface.Index)

	// Send netlink message
	_, _, errno := unix.Syscall6(
		unix.SYS_SENDTO,
		uintptr(fd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
		uintptr(unsafe.Pointer(addr)),
		unsafe.Sizeof(*addr),
	)
	if errno != 0 {
		return fmt.Errorf("failed to send netlink message: %v", errno)
	}

	// Read ACK
	ackBuf := make([]byte, 4096)
	n, _, errno := unix.Syscall(
		unix.SYS_RECVFROM,
		uintptr(fd),
		uintptr(unsafe.Pointer(&ackBuf[0])),
		uintptr(len(ackBuf)),
	)
	if errno != 0 {
		return fmt.Errorf("failed to receive netlink ACK: %v", errno)
	}

	// Check for error in ACK
	if n < nlmsgHdrLen {
		return fmt.Errorf("netlink ACK too short: %d bytes", n)
	}

	ackType := *(*uint16)(unsafe.Pointer(&ackBuf[4]))
	if ackType == NLMSG_ERROR {
		if n >= nlmsgHdrLen+4 {
			errCode := *(*int32)(unsafe.Pointer(&ackBuf[nlmsgHdrLen]))
			if errCode != 0 {
				return fmt.Errorf("netlink error: %d", -errCode)
			}
		}
	}

	return nil
}

// Close closes the TAP device
func (t *TAP) Close() error {
	if t.file != nil {
		return t.file.Close()
	}
	return nil
}
