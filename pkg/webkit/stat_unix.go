//go:build unix

package webkit

import (
	"os"
	"syscall"
)

func statNlink(fi os.FileInfo) uint64 {
	if fi == nil {
		return 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 0
}
