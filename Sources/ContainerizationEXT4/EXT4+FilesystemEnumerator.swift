//===----------------------------------------------------------------------===//
// Copyright © 2025 Apple Inc. and the Containerization project authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//===----------------------------------------------------------------------===//

import Foundation
import SystemPackage

extension EXT4 {
    /// Wrapper around EXT4Reader that provides filesystem enumeration functionality.
    /// This wrapper isolates us from changes to Apple's internal EXT4Reader implementation.
    public class FilesystemEnumerator {
        private let reader: EXT4Reader

        public init(reader: EXT4Reader) {
            self.reader = reader
        }

        /// Information about a file in the EXT4 filesystem
        public struct FileInfo {
            public let path: String
            public let type: String  // 'f' = file, 'd' = directory, 'l' = symlink
            public let size: Int64
            public let mtime: Int64  // Unix timestamp (seconds since epoch)

            public init(path: String, type: String, size: Int64, mtime: Int64) {
                self.path = path
                self.type = type
                self.size = size
                self.mtime = mtime
            }
        }

        /// Enumerate all files in the filesystem
        /// - Returns: Array of FileInfo structs representing all files and directories
        public func enumerateFilesystem() throws -> [FileInfo] {
            var files: [FileInfo] = []

            // Access internal tree property through the reader
            let tree = reader.tree
            let rootNode = tree.root.pointee

            // Traverse the file tree recursively
            try traverseNode(node: rootNode, files: &files)

            return files
        }

        /// Recursively traverse a file tree node
        private func traverseNode(node: FileTree.FileTreeNode, files: inout [FileInfo]) throws {
            // Get inode information using internal getInode method
            let inode = try reader.getInode(number: node.inode)

            // Get the full path for this node
            guard let filePath = node.path else {
                return
            }

            // Determine file type from inode mode
            let fileType: String
            if inode.mode.isDir() {
                fileType = "d"
            } else if inode.mode.isLink() {
                fileType = "l"
            } else {
                fileType = "f"
            }

            // Create FileInfo with absolute path (ensure leading slash)
            let pathString = filePath.string
            let absolutePath = pathString.hasPrefix("/") ? pathString : "/" + pathString
            let fileInfo = FileInfo(
                path: absolutePath,
                type: fileType,
                size: Int64(inode.sizeLow),
                mtime: Int64(inode.mtime)
            )
            files.append(fileInfo)

            // Recursively process children
            for childPtr in node.children {
                try traverseNode(node: childPtr.pointee, files: &files)
            }
        }
    }
}
