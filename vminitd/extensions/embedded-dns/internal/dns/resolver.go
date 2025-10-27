package dns

import (
	"log"
)

// Resolver resolves hostnames using local DNS mappings
// Mappings are updated by the Arca daemon via the control server
type Resolver struct {
	controlServer *ControlServer
}

// NewResolver creates a new resolver with a control server for receiving updates
func NewResolver(controlSocketPath string) (*Resolver, error) {
	controlServer, err := NewControlServer(controlSocketPath)
	if err != nil {
		return nil, err
	}

	return &Resolver{
		controlServer: controlServer,
	}, nil
}

// Resolve queries the local DNS mappings to resolve a hostname
// Searches across all networks this container is attached to
func (r *Resolver) Resolve(hostname string) (string, bool) {
	// Try to resolve across all networks
	ipAddress := r.controlServer.Resolve(hostname, "")
	if ipAddress != "" {
		log.Printf("Resolved %s -> %s", hostname, ipAddress)
		return ipAddress, true
	}

	log.Printf("Failed to resolve: %s", hostname)
	return "", false
}

// GetControlServer returns the control server for starting it
func (r *Resolver) GetControlServer() *ControlServer {
	return r.controlServer
}

// Close closes the resolver and control server
func (r *Resolver) Close() error {
	return r.controlServer.Close()
}
