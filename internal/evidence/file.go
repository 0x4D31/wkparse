// Package evidence handles file access on a stationary, offline extraction.
package evidence

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Open requires a regular leaf. Do not follow evidence symlinks or open devices/pipes.
func Open(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular evidence file", path)
	}
	return os.Open(path)
}

func ReadFile(path string) ([]byte, error) {
	f, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func ReadSalt(path string) ([]byte, error) {
	f, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 9))
	if err != nil {
		return nil, err
	}
	if len(b) != 8 {
		return nil, fmt.Errorf("salt must contain exactly 8 bytes: %s", path)
	}
	return b, nil
}

// Outside rejects output under root, even through existing symlink ancestors.
// Resolve the longest existing ancestor of a not-yet-created destination.
func Outside(root, dest string) error {
	if dest == "" {
		return nil
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	dest, err = filepath.Abs(dest)
	if err != nil {
		return err
	}
	base := dest
	for {
		_, err := os.Lstat(base)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) || filepath.Dir(base) == base {
			return err
		}
		base = filepath.Dir(base)
	}
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		return err
	}
	tail, err := filepath.Rel(base, dest)
	if err != nil {
		return err
	}
	resolved = filepath.Join(resolved, tail)
	// SameFile also handles case-insensitive volumes and alternate directory names.
	for dir := resolved; ; dir = filepath.Dir(dir) {
		if fi, err := os.Stat(dir); err == nil {
			ri, err := os.Stat(root)
			if err != nil {
				return err
			}
			if os.SameFile(ri, fi) {
				return fmt.Errorf("output must be outside the evidence directory: %s", dest)
			}
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return nil
}
