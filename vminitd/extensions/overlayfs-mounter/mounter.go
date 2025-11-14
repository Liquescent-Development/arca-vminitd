// Package overlayfs provides OverlayFS mounting services for Arca containers
//
// This service runs inside each container's Linux VM and manages OverlayFS
// mounts for stacked layer filesystems.
package overlayfs

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
	pb "github.com/apple/containerization/vminitd/extensions/overlayfs-mounter/proto"
)

// Server implements the OverlayFS service
type Server struct {
	pb.UnimplementedOverlayFSServiceServer
}

// MountOverlay mounts an OverlayFS filesystem with multiple lower layers
//
// Process:
// 1. Mount each lower layer block device to /overlay/lower/{index}
// 2. Create upper and work directories
// 3. Mount OverlayFS with all layers
//
// OverlayFS mount options:
// - lowerdir: Colon-separated list of read-only layers (reversed order)
// - upperdir: Read-write directory for container changes
// - workdir: OverlayFS work directory for metadata
func (s *Server) MountOverlay(ctx context.Context, req *pb.MountOverlayRequest) (*pb.MountOverlayResponse, error) {
	log.Printf("OverlayFS mount request: %d layers, target=%s", len(req.LowerBlockDevices), req.Target)

	// 1. Create and mount lower layer directories
	lowerDirs := []string{}
	for i, blockDev := range req.LowerBlockDevices {
		mountPoint := fmt.Sprintf("/overlay/lower/%d", i)

		// Create mount point
		if err := os.MkdirAll(mountPoint, 0755); err != nil {
			return &pb.MountOverlayResponse{
				Success:      false,
				ErrorMessage: fmt.Sprintf("failed to create lower mount point %s: %v", mountPoint, err),
			}, nil
		}

		// Mount the block device (read-only EXT4)
		log.Printf("Mounting lower layer %d: %s -> %s", i, blockDev, mountPoint)
		if err := unix.Mount(blockDev, mountPoint, "ext4", unix.MS_RDONLY, ""); err != nil {
			return &pb.MountOverlayResponse{
				Success:      false,
				ErrorMessage: fmt.Sprintf("failed to mount %s: %v", blockDev, err),
			}, nil
		}

		lowerDirs = append(lowerDirs, mountPoint)
	}

	// 2. Create upper and work directories
	if err := os.MkdirAll(req.UpperDir, 0755); err != nil {
		return &pb.MountOverlayResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to create upper dir: %v", err),
		}, nil
	}

	if err := os.MkdirAll(req.WorkDir, 0755); err != nil {
		return &pb.MountOverlayResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to create work dir: %v", err),
		}, nil
	}

	// 3. Build OverlayFS mount options
	// lowerdir must be ordered from top to bottom (reverse of input)
	reversedLowers := make([]string, len(lowerDirs))
	for i, dir := range lowerDirs {
		reversedLowers[len(lowerDirs)-1-i] = dir
	}
	lowerOpt := strings.Join(reversedLowers, ":")

	data := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lowerOpt, req.UpperDir, req.WorkDir)

	// 4. Mount OverlayFS
	log.Printf("Mounting OverlayFS: %s", data)
	if err := unix.Mount("overlay", req.Target, "overlay", 0, data); err != nil {
		return &pb.MountOverlayResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to mount overlay: %v", err),
		}, nil
	}

	log.Printf("OverlayFS mounted successfully at %s", req.Target)
	return &pb.MountOverlayResponse{Success: true}, nil
}

// UnmountOverlay unmounts the OverlayFS filesystem and cleans up lower layers
func (s *Server) UnmountOverlay(ctx context.Context, req *pb.UnmountOverlayRequest) (*pb.UnmountOverlayResponse, error) {
	log.Printf("OverlayFS unmount request: target=%s", req.Target)

	// Unmount the overlay
	if err := unix.Unmount(req.Target, 0); err != nil {
		return &pb.UnmountOverlayResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to unmount overlay: %v", err),
		}, nil
	}

	// Clean up lower layer mounts recursively
	// This unmounts all mounts under /overlay/lower
	cmd := exec.Command("umount", "-R", "/overlay/lower")
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: failed to cleanup lower mounts: %v", err)
		// Don't fail the operation - overlay is already unmounted
	}

	log.Printf("OverlayFS unmounted successfully from %s", req.Target)
	return &pb.UnmountOverlayResponse{Success: true}, nil
}
