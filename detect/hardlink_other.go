//go:build !unix

package detect

import "io/fs"

// IsHardLinkedFile is a best-effort fallback on platforms where hard link
// counts are not available through syscall.Stat_t.
func IsHardLinkedFile(info fs.FileInfo) bool {
	return false
}
