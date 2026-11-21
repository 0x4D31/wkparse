//go:build !unix

package webkit

import "os"

func statNlink(fi os.FileInfo) uint64 {
	return 0
}
