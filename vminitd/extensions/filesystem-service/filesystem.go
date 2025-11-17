// Package filesystem provides filesystem services for Arca containers
//
// This service runs inside each container's Linux VM (vsock:51821) and provides:
// - Filesystem sync (flush buffers)
// - OverlayFS upperdir enumeration (for docker diff)
// - Archive operations (tar creation/extraction for buildx)
package filesystem

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	pb "github.com/vas-solutus/arca-filesystem-service/proto"
)

// Server implements the FilesystemService
type Server struct {
	pb.UnimplementedFilesystemServiceServer
}

// SyncFilesystem flushes all filesystem buffers to disk
// Calls the sync() syscall to ensure all cached writes are persisted
func (s *Server) SyncFilesystem(ctx context.Context, req *pb.SyncFilesystemRequest) (*pb.SyncFilesystemResponse, error) {
	log.Printf("Syncing filesystem")

	// Call sync() syscall to flush all filesystem buffers
	unix.Sync()

	log.Printf("Filesystem sync complete")
	return &pb.SyncFilesystemResponse{
		Success: true,
	}, nil
}

// EnumerateUpperdir enumerates all files in the OverlayFS upperdir
// Returns added/modified files and whiteouts (deleted files)
// Much faster than full filesystem enumeration
func (s *Server) EnumerateUpperdir(ctx context.Context, req *pb.EnumerateUpperdirRequest) (*pb.EnumerateUpperdirResponse, error) {
	log.Printf("Enumerating OverlayFS upperdir at /mnt/vdb/upper")

	upperdirPath := "/mnt/vdb/upper"

	// Check if upperdir exists
	if _, err := os.Stat(upperdirPath); os.IsNotExist(err) {
		return &pb.EnumerateUpperdirResponse{
			Success: false,
			Error:   fmt.Sprintf("upperdir not found at %s", upperdirPath),
		}, nil
	}

	var entries []*pb.UpperdirEntry

	// Walk the upperdir and collect all entries
	err := filepath.Walk(upperdirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error walking %s: %v", path, err)
			return err
		}

		// Skip the upperdir root itself
		if path == upperdirPath {
			return nil
		}

		// Get path relative to upperdir (this is the container path)
		relPath, err := filepath.Rel(upperdirPath, path)
		if err != nil {
			return err
		}

		// Prepend "/" to make it an absolute container path
		containerPath := "/" + relPath

		// Determine entry type
		var entryType string
		var size int64
		mode := uint32(info.Mode())

		// Check for whiteout (character device 0/0)
		// OverlayFS uses whiteouts to mark deleted files
		if info.Mode()&os.ModeCharDevice != 0 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok && stat.Rdev == 0 {
				entryType = "whiteout"
				size = 0
				log.Printf("Found whiteout: %s", containerPath)
			} else {
				// Regular char device (not a whiteout)
				entryType = "file"
				size = info.Size()
			}
		} else if info.IsDir() {
			entryType = "dir"
			size = 0
		} else if info.Mode()&os.ModeSymlink != 0 {
			entryType = "symlink"
			size = 0
		} else {
			entryType = "file"
			size = info.Size()
		}

		// Add entry
		entries = append(entries, &pb.UpperdirEntry{
			Path:  containerPath,
			Type:  entryType,
			Size:  size,
			Mtime: info.ModTime().Unix(),
			Mode:  mode,
		})

		return nil
	})

	if err != nil {
		return &pb.EnumerateUpperdirResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to enumerate upperdir: %v", err),
		}, nil
	}

	log.Printf("Enumerated upperdir: %d entries", len(entries))
	return &pb.EnumerateUpperdirResponse{
		Success: true,
		Entries: entries,
	}, nil
}

// ReadArchive creates a tar archive of the specified path
// Works universally without requiring tar binary in container
// Used for GET /containers/{id}/archive endpoint (buildx)
func (s *Server) ReadArchive(ctx context.Context, req *pb.ReadArchiveRequest) (*pb.ReadArchiveResponse, error) {
	log.Printf("ReadArchive: container=%s path=%s", req.ContainerId, req.Path)

	// Resolve container rootfs path
	rootfsPath := fmt.Sprintf("/run/container/%s/rootfs", req.ContainerId)
	fullPath := filepath.Join(rootfsPath, req.Path)

	// Get file info for the path
	info, err := os.Lstat(fullPath)
	if err != nil {
		return &pb.ReadArchiveResponse{
			Success: false,
			Error:   fmt.Sprintf("path not found: %v", err),
		}, nil
	}

	// Create tar archive in memory
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	// Add files to tar
	err = addToTar(tarWriter, fullPath, filepath.Base(req.Path), info)
	if err != nil {
		tarWriter.Close()
		gzWriter.Close()
		return &pb.ReadArchiveResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to create tar: %v", err),
		}, nil
	}

	tarWriter.Close()
	gzWriter.Close()

	// Create PathStat for response header
	stat := &pb.PathStat{
		Name:  info.Name(),
		Size:  info.Size(),
		Mode:  uint32(info.Mode()),
		Mtime: info.ModTime().Format(time.RFC3339),
	}

	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(fullPath)
		if err == nil {
			stat.LinkTarget = target
		}
	}

	log.Printf("ReadArchive complete: %d bytes", buf.Len())
	return &pb.ReadArchiveResponse{
		Success: true,
		TarData: buf.Bytes(),
		Stat:    stat,
	}, nil
}

// addToTar recursively adds files to a tar archive
func addToTar(tw *tar.Writer, fullPath, nameInTar string, info os.FileInfo) error {
	// Create tar header
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = nameInTar

	// Handle symlinks
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(fullPath)
		if err != nil {
			return err
		}
		header.Linkname = target
	}

	// Write header
	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	// If it's a regular file, write contents
	if info.Mode().IsRegular() {
		file, err := os.Open(fullPath)
		if err != nil {
			return err
		}
		defer file.Close()

		if _, err := io.Copy(tw, file); err != nil {
			return err
		}
	}

	// If it's a directory, recurse
	if info.IsDir() {
		entries, err := os.ReadDir(fullPath)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			entryPath := filepath.Join(fullPath, entry.Name())
			entryInfo, err := entry.Info()
			if err != nil {
				return err
			}

			if err := addToTar(tw, entryPath, filepath.Join(nameInTar, entry.Name()), entryInfo); err != nil {
				return err
			}
		}
	}

	return nil
}

// WriteArchive extracts a tar archive to the specified path
// Works universally without requiring tar binary in container
// Used for PUT /containers/{id}/archive endpoint (buildx)
func (s *Server) WriteArchive(ctx context.Context, req *pb.WriteArchiveRequest) (*pb.WriteArchiveResponse, error) {
	log.Printf("WriteArchive: container=%s path=%s size=%d", req.ContainerId, req.Path, len(req.TarData))

	// Resolve container rootfs path
	rootfsPath := fmt.Sprintf("/run/container/%s/rootfs", req.ContainerId)
	destPath := filepath.Join(rootfsPath, req.Path)

	// Ensure destination exists
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return &pb.WriteArchiveResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to create destination: %v", err),
		}, nil
	}

	// Decompress gzip
	gzReader, err := gzip.NewReader(bytes.NewReader(req.TarData))
	if err != nil {
		return &pb.WriteArchiveResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to decompress gzip: %v", err),
		}, nil
	}
	defer gzReader.Close()

	// Extract tar
	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &pb.WriteArchiveResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to read tar: %v", err),
			}, nil
		}

		// Security: prevent directory traversal
		if strings.Contains(header.Name, "..") {
			continue
		}

		targetPath := filepath.Join(destPath, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to create directory: %v", err),
				}, nil
			}

		case tar.TypeReg:
			// Create parent directory
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to create parent directory: %v", err),
				}, nil
			}

			// Write file
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to create file: %v", err),
				}, nil
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to write file: %v", err),
				}, nil
			}
			outFile.Close()

		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, targetPath); err != nil && !os.IsExist(err) {
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to create symlink: %v", err),
				}, nil
			}
		}
	}

	log.Printf("WriteArchive complete")
	return &pb.WriteArchiveResponse{
		Success: true,
	}, nil
}
