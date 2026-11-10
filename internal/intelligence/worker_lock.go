package intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
)

// acquireWorkerLock is additional same-account exclusion and retains the
// pre-lease revision counter for migration. Distributed authority belongs to
// the database lease. Keep the file after unlock so peers lock the same inode.
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

// nextRevision reserves globally before sending a checkpoint. The local file
// is retained as a migration floor; it is never the lease authority.
func (w *Worker) nextRevision(ctx context.Context, minimum uint64) (uint64, error) {
	if minimum >= math.MaxInt64-1 {
		return 0, fmt.Errorf("intelligence revision exhausted")
	}
	if w.ownershipKey == "" {
		return minimum + 1, nil
	} // non-runtime test stores
	if w.ownershipLock == nil {
		return 0, fmt.Errorf("intelligence ownership is not held")
	}
	if err := w.checkDatabaseOwnership(ctx); err != nil {
		return 0, err
	}
	previous, err := readWorkerRevision(w.ownershipLock)
	if err != nil {
		return 0, err
	}
	minimum = max(minimum, previous)
	if minimum >= math.MaxInt64-1 {
		return 0, fmt.Errorf("intelligence revision exhausted")
	}
	leaser, lease, _, err := w.leaseSnapshot()
	if err != nil {
		return 0, err
	}
	next, err := leaser.ReserveIntelligenceRevision(ctx, lease, minimum)
	if err != nil {
		w.loseLease(err)
		return 0, err
	}
	if next <= minimum || next >= math.MaxInt64-1 {
		err := fmt.Errorf("database returned invalid intelligence revision")
		w.loseLease(err)
		return 0, err
	}
	if err := writeWorkerRevision(w.ownershipLock, next); err != nil {
		return 0, err
	}
	return next, nil
}

func readWorkerRevision(file *os.File) (uint64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if info.Size() != 0 && info.Size() != 16 {
		return 0, fmt.Errorf("incomplete intelligence revision reservation")
	}
	var data [16]byte
	n, err := file.ReadAt(data[:], 0)
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
	if previous >= math.MaxInt64-1 {
		return 0, fmt.Errorf("intelligence revision exhausted")
	}
	return previous, nil
}

func writeWorkerRevision(file *os.File, next uint64) error {
	previous, err := readWorkerRevision(file)
	if err != nil {
		return err
	}
	if next <= previous || next >= math.MaxInt64-1 {
		return fmt.Errorf("intelligence revision reservation did not advance")
	}
	var data [16]byte
	binary.BigEndian.PutUint64(data[:8], next)
	binary.BigEndian.PutUint64(data[8:], ^next)
	if n, err := file.WriteAt(data[:], 0); err != nil {
		return err
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	return file.Sync()
}
