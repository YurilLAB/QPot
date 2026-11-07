package intelligence

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
)

// acquireWorkerLock excludes competing processes in the same local OS account.
// This is deliberately not a distributed lease: operators must still select one
// owner when several hosts/accounts can reach the same database. Keep the lock
// file after unlock, since removing it would let peers lock different inodes.
func acquireWorkerLock(identity string) (*os.File, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, "qpot", "intelligence-locks")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(identity))
	f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("%x.lock", sum)), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("intelligence ownership lock is not a regular file")
	}
	if err = lockWorkerFile(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// nextRevision reserves a revision on disk before sending the checkpoint. A
// process can die while its database save is still in flight; its successor
// must never reuse that revision for a different batch. The checked counter is
// synced under the lifetime ownership lock. Corrupt/torn writes fail closed.
func (w *Worker) nextRevision(minimum uint64) (uint64, error) {
	if minimum >= math.MaxInt64-1 {
		return 0, fmt.Errorf("intelligence revision exhausted")
	}
	if w.ownershipKey == "" {
		return minimum + 1, nil
	} // non-runtime test stores
	if w.ownershipLock == nil {
		return 0, fmt.Errorf("intelligence ownership is not held")
	}
	var data [16]byte
	n, err := w.ownershipLock.ReadAt(data[:], 0)
	if err != nil && err != io.EOF {
		return 0, err
	}
	var previous uint64
	if n != 0 {
		if n != len(data) {
			return 0, fmt.Errorf("incomplete intelligence revision reservation")
		}
		previous = binary.BigEndian.Uint64(data[:8])
		if binary.BigEndian.Uint64(data[8:]) != ^previous {
			return 0, fmt.Errorf("corrupt intelligence revision reservation")
		}
	}
	if previous > minimum {
		minimum = previous
	}
	if minimum >= math.MaxInt64-1 {
		return 0, fmt.Errorf("intelligence revision exhausted")
	}
	next := minimum + 1
	binary.BigEndian.PutUint64(data[:8], next)
	binary.BigEndian.PutUint64(data[8:], ^next)
	if n, err = w.ownershipLock.WriteAt(data[:], 0); err != nil {
		return 0, err
	} else if n != len(data) {
		return 0, io.ErrShortWrite
	}
	if err = w.ownershipLock.Sync(); err != nil {
		return 0, err
	}
	return next, nil
}
