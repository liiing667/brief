//go:build unix

package detect

import (
	"io/fs"
	"syscall"
)

// IsHardLinkedFile reports whether info describes a regular file with more
// than one directory entry. A hard-linked file shares its inode with a name
// that may live outside the project root, so its content cannot be trusted
// to stay within the scan boundary.
func IsHardLinkedFile(info fs.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink > 1
}
