package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/vishvananda/netlink"
	pb "github.com/Liquescent-Development/arca-vminitd/vminitd/extensions/vlan-service/proto"
	"google.golang.org/grpc"
)

// VLANServer implements the NetworkConfig gRPC service
type VLANServer struct {
	pb.UnimplementedNetworkConfigServer
}

// CreateVLAN creates a VLAN subinterface on a parent interface
func (s *VLANServer) CreateVLAN(ctx context.Context, req *pb.CreateVLANRequest) (*pb.CreateVLANResponse, error) {
	log.Printf("CreateVLAN: parent=%s vlanID=%d ip=%s gateway=%s",
		req.ParentInterface, req.VlanId, req.IpAddress, req.Gateway)

	// Validate VLAN ID
	if req.VlanId < 1 || req.VlanId > 4094 {
		return &pb.CreateVLANResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid VLAN ID %d (must be 1-4094)", req.VlanId),
		}, nil
	}

	// Get parent interface
	parent, err := netlink.LinkByName(req.ParentInterface)
	if err != nil {
		return &pb.CreateVLANResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to find parent interface %s: %v", req.ParentInterface, err),
		}, nil
	}

	// Create VLAN interface name (e.g., eth0.100)
	vlanName := fmt.Sprintf("%s.%d", req.ParentInterface, req.VlanId)

	// Check if VLAN interface already exists
	existing, _ := netlink.LinkByName(vlanName)
	if existing != nil {
		log.Printf("VLAN interface %s already exists, will reconfigure", vlanName)
		// Delete and recreate to ensure clean state
		if err := netlink.LinkDel(existing); err != nil {
			log.Printf("Warning: failed to delete existing VLAN %s: %v", vlanName, err)
		}
	}

	// Create VLAN subinterface
	vlan := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        vlanName,
			ParentIndex: parent.Attrs().Index,
		},
		VlanId: int(req.VlanId),
	}

	// Set MTU if specified
	if req.Mtu > 0 {
		vlan.MTU = int(req.Mtu)
	}

	// Create the VLAN interface
	if err := netlink.LinkAdd(vlan); err != nil {
		return &pb.CreateVLANResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to create VLAN interface: %v", err),
		}, nil
	}

	log.Printf("Created VLAN interface %s", vlanName)

	// Get the created interface to access its attributes
	vlanLink, err := netlink.LinkByName(vlanName)
	if err != nil {
		// Clean up on error
		netlink.LinkDel(vlan)
		return &pb.CreateVLANResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to retrieve created VLAN interface: %v", err),
		}, nil
	}

	// Set custom MAC address if provided
	if req.MacAddress != "" {
		hwAddr, err := net.ParseMAC(req.MacAddress)
		if err != nil {
			netlink.LinkDel(vlanLink)
			return &pb.CreateVLANResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid MAC address %s: %v", req.MacAddress, err),
			}, nil
		}
		if err := netlink.LinkSetHardwareAddr(vlanLink, hwAddr); err != nil {
			netlink.LinkDel(vlanLink)
			return &pb.CreateVLANResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to set MAC address: %v", err),
			}, nil
		}
	}

	// Configure IP address if provided
	if req.IpAddress != "" {
		addr, err := netlink.ParseAddr(req.IpAddress)
		if err != nil {
			netlink.LinkDel(vlanLink)
			return &pb.CreateVLANResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid IP address %s: %v", req.IpAddress, err),
			}, nil
		}

		if err := netlink.AddrAdd(vlanLink, addr); err != nil {
			netlink.LinkDel(vlanLink)
			return &pb.CreateVLANResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to add IP address: %v", err),
			}, nil
		}

		log.Printf("Configured IP %s on %s", req.IpAddress, vlanName)
	}

	// Bring interface up
	if err := netlink.LinkSetUp(vlanLink); err != nil {
		netlink.LinkDel(vlanLink)
		return &pb.CreateVLANResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to bring interface up: %v", err),
		}, nil
	}

	log.Printf("Brought up VLAN interface %s", vlanName)

	// Add default route via gateway if provided
	if req.Gateway != "" {
		gatewayIP := net.ParseIP(req.Gateway)
		if gatewayIP == nil {
			// Don't fail if gateway is invalid, just log warning
			log.Printf("Warning: invalid gateway IP %s, skipping route", req.Gateway)
		} else {
			route := &netlink.Route{
				LinkIndex: vlanLink.Attrs().Index,
				Dst:       nil, // nil = default route (0.0.0.0/0)
				Gw:        gatewayIP,
				Priority:  100, // Higher priority than other routes
			}

			if err := netlink.RouteAdd(route); err != nil {
				// Don't fail if route already exists
				log.Printf("Warning: failed to add default route via %s: %v", req.Gateway, err)
			} else {
				log.Printf("Added default route via %s on %s", req.Gateway, vlanName)
			}
		}
	}

	// Get actual MAC address
	macAddr := vlanLink.Attrs().HardwareAddr.String()

	return &pb.CreateVLANResponse{
		Success:       true,
		InterfaceName: vlanName,
		MacAddress:    macAddr,
	}, nil
}

// DeleteVLAN removes a VLAN subinterface
func (s *VLANServer) DeleteVLAN(ctx context.Context, req *pb.DeleteVLANRequest) (*pb.DeleteVLANResponse, error) {
	log.Printf("DeleteVLAN: interface=%s", req.InterfaceName)

	// Get interface
	link, err := netlink.LinkByName(req.InterfaceName)
	if err != nil {
		// Interface doesn't exist - consider it success
		log.Printf("VLAN interface %s not found (already deleted?)", req.InterfaceName)
		return &pb.DeleteVLANResponse{
			Success: true,
		}, nil
	}

	// Delete the interface
	if err := netlink.LinkDel(link); err != nil {
		return &pb.DeleteVLANResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to delete interface: %v", err),
		}, nil
	}

	log.Printf("Deleted VLAN interface %s", req.InterfaceName)

	return &pb.DeleteVLANResponse{
		Success: true,
	}, nil
}

// ConfigureIP adds or updates an IP address on an interface
func (s *VLANServer) ConfigureIP(ctx context.Context, req *pb.ConfigureIPRequest) (*pb.ConfigureIPResponse, error) {
	log.Printf("ConfigureIP: interface=%s ip=%s replace=%t",
		req.InterfaceName, req.IpAddress, req.Replace)

	// Get interface
	link, err := netlink.LinkByName(req.InterfaceName)
	if err != nil {
		return &pb.ConfigureIPResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to find interface %s: %v", req.InterfaceName, err),
		}, nil
	}

	// Parse IP address
	addr, err := netlink.ParseAddr(req.IpAddress)
	if err != nil {
		return &pb.ConfigureIPResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid IP address %s: %v", req.IpAddress, err),
		}, nil
	}

	// If replace=true, remove all existing IPs first
	if req.Replace {
		addrs, err := netlink.AddrList(link, 0) // 0 = all address families
		if err != nil {
			return &pb.ConfigureIPResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to list existing IPs: %v", err),
			}, nil
		}

		for _, a := range addrs {
			if err := netlink.AddrDel(link, &a); err != nil {
				log.Printf("Warning: failed to delete IP %s: %v", a.IPNet.String(), err)
			}
		}
	}

	// Add new IP address
	if err := netlink.AddrAdd(link, addr); err != nil {
		// Check if error is because address already exists
		if err.Error() == "file exists" {
			log.Printf("IP address %s already exists on %s", req.IpAddress, req.InterfaceName)
			return &pb.ConfigureIPResponse{
				Success: true,
			}, nil
		}
		return &pb.ConfigureIPResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to add IP address: %v", err),
		}, nil
	}

	log.Printf("Configured IP %s on %s", req.IpAddress, req.InterfaceName)

	return &pb.ConfigureIPResponse{
		Success: true,
	}, nil
}

// AddRoute adds a route to the routing table
func (s *VLANServer) AddRoute(ctx context.Context, req *pb.AddRouteRequest) (*pb.AddRouteResponse, error) {
	log.Printf("AddRoute: dst=%s gateway=%s interface=%s metric=%d",
		req.Destination, req.Gateway, req.InterfaceName, req.Metric)

	// Get interface
	link, err := netlink.LinkByName(req.InterfaceName)
	if err != nil {
		return &pb.AddRouteResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to find interface %s: %v", req.InterfaceName, err),
		}, nil
	}

	// Parse gateway IP
	gatewayIP := net.ParseIP(req.Gateway)
	if gatewayIP == nil {
		return &pb.AddRouteResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid gateway IP %s", req.Gateway),
		}, nil
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        gatewayIP,
	}

	// Parse destination (nil = default route)
	if req.Destination != "" && req.Destination != "0.0.0.0/0" {
		_, dst, err := net.ParseCIDR(req.Destination)
		if err != nil {
			return &pb.AddRouteResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid destination %s: %v", req.Destination, err),
			}, nil
		}
		route.Dst = dst
	}

	// Set metric if provided
	if req.Metric > 0 {
		route.Priority = int(req.Metric)
	}

	// Add route
	if err := netlink.RouteAdd(route); err != nil {
		// Check if error is because route already exists
		if err.Error() == "file exists" {
			log.Printf("Route to %s via %s already exists", req.Destination, req.Gateway)
			return &pb.AddRouteResponse{
				Success: true,
			}, nil
		}
		return &pb.AddRouteResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to add route: %v", err),
		}, nil
	}

	log.Printf("Added route to %s via %s on %s", req.Destination, req.Gateway, req.InterfaceName)

	return &pb.AddRouteResponse{
		Success: true,
	}, nil
}

// DeleteRoute removes a route from the routing table
func (s *VLANServer) DeleteRoute(ctx context.Context, req *pb.DeleteRouteRequest) (*pb.DeleteRouteResponse, error) {
	log.Printf("DeleteRoute: dst=%s gateway=%s interface=%s",
		req.Destination, req.Gateway, req.InterfaceName)

	route := &netlink.Route{}

	// Parse destination
	if req.Destination != "" && req.Destination != "0.0.0.0/0" {
		_, dst, err := net.ParseCIDR(req.Destination)
		if err != nil {
			return &pb.DeleteRouteResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid destination %s: %v", req.Destination, err),
			}, nil
		}
		route.Dst = dst
	}

	// Parse gateway if provided
	if req.Gateway != "" {
		gatewayIP := net.ParseIP(req.Gateway)
		if gatewayIP == nil {
			return &pb.DeleteRouteResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid gateway IP %s", req.Gateway),
			}, nil
		}
		route.Gw = gatewayIP
	}

	// Get interface if provided
	if req.InterfaceName != "" {
		link, err := netlink.LinkByName(req.InterfaceName)
		if err != nil {
			return &pb.DeleteRouteResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to find interface %s: %v", req.InterfaceName, err),
			}, nil
		}
		route.LinkIndex = link.Attrs().Index
	}

	// Delete route
	if err := netlink.RouteDel(route); err != nil {
		// Route not found is considered success
		if err.Error() == "no such process" {
			log.Printf("Route not found (already deleted?)")
			return &pb.DeleteRouteResponse{
				Success: true,
			}, nil
		}
		return &pb.DeleteRouteResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to delete route: %v", err),
		}, nil
	}

	log.Printf("Deleted route to %s", req.Destination)

	return &pb.DeleteRouteResponse{
		Success: true,
	}, nil
}

// ListInterfaces lists all network interfaces
func (s *VLANServer) ListInterfaces(ctx context.Context, req *pb.ListInterfacesRequest) (*pb.ListInterfacesResponse, error) {
	log.Printf("ListInterfaces: filter=%s", req.NameFilter)

	// Get all links
	links, err := netlink.LinkList()
	if err != nil {
		return &pb.ListInterfacesResponse{
			Error: fmt.Sprintf("failed to list interfaces: %v", err),
		}, nil
	}

	var interfaces []*pb.NetworkInterface

	for _, link := range links {
		attrs := link.Attrs()

		// Apply name filter if provided
		if req.NameFilter != "" && attrs.Name != req.NameFilter {
			continue
		}

		iface := &pb.NetworkInterface{
			Name:       attrs.Name,
			Index:      int32(attrs.Index),
			MacAddress: attrs.HardwareAddr.String(),
			Mtu:        uint32(attrs.MTU),
			IsUp:       attrs.Flags&net.FlagUp != 0,
		}

		// Get IP addresses
		addrs, err := netlink.AddrList(link, 0) // 0 = all address families
		if err == nil {
			for _, addr := range addrs {
				iface.IpAddresses = append(iface.IpAddresses, addr.IPNet.String())
			}
		}

		// Check if it's a VLAN interface
		if vlan, ok := link.(*netlink.Vlan); ok {
			iface.VlanId = uint32(vlan.VlanId)
			// Get parent interface name
			if parent, err := netlink.LinkByIndex(attrs.ParentIndex); err == nil {
				iface.Parent = parent.Attrs().Name
			}
		}

		interfaces = append(interfaces, iface)
	}

	log.Printf("Listed %d interfaces", len(interfaces))

	return &pb.ListInterfacesResponse{
		Interfaces: interfaces,
	}, nil
}

// NewVLANServer creates a new VLAN server instance
func NewVLANServer() *VLANServer {
	return &VLANServer{}
}

// StartServer starts the gRPC server
func StartServer(port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", port, err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterNetworkConfigServer(grpcServer, NewVLANServer())

	log.Printf("VLAN service listening on port %d", port)
	return grpcServer.Serve(lis)
}
