package sshbackend

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const metadataReserve = 512 << 10

// reserveCapture serializes admission, rather than commands. A sparse claim
// accounts for the entire possible capture while concurrent channels run.
// Abandoned claims remain conservative until the disposable cell is reset.
func reserveCapture(dir, prefix string) (int64, func(), error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, nil, err
	}
	defer root.Close()
	lock, err := admissionLock(root)
	if err != nil {
		return 0, nil, err
	}
	defer lock.Close()
	directory, err := os.Open(dir)
	if err != nil {
		return 0, nil, err
	}
	entries, err := directory.ReadDir(maxLogFiles + 1)
	_ = directory.Close()
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > maxLogFiles {
		return 0, nil, errors.New("session record capacity reached")
	}
	claims := make(map[string]int64)
	stats := make(map[string]os.FileInfo)
	names := make(map[string]bool)
	for _, entry := range entries {
		names[entry.Name()] = true
		if !entry.Type().IsRegular() {
			continue
		}
		stat, err := entry.Info()
		if err != nil {
			return 0, nil, err
		}
		stats[entry.Name()] = stat
		if strings.HasSuffix(entry.Name(), ".reserve") {
			if stat.Size() < metadataReserve || stat.Size() > maxSessionBytes+metadataReserve {
				return 0, nil, errors.New("invalid session capture reservation")
			}
			claims[strings.TrimSuffix(entry.Name(), ".reserve")] = stat.Size()
		}
	}
	// A concurrent recorder may have reserved its budget before creating its
	// five capture files. Include those pending names in the admission bound.
	count := len(entries)
	for claimed := range claims {
		for _, suffix := range []string{".json", ".out", ".err", ".in", ".timing"} {
			if !names[claimed+suffix] {
				count++
			}
		}
	}
	if count+6 > maxLogFiles {
		return 0, nil, errors.New("session record capacity reached")
	}
	var used int64
	for name, stat := range stats {
		if name == ".admission.lock" {
			continue
		}
		if extension := filepath.Ext(name); extension != ".reserve" {
			if _, claimed := claims[strings.TrimSuffix(name, extension)]; claimed {
				continue
			}
		}
		if stat.Size() < 0 || stat.Size() > maxUserLogBytes-used {
			return 0, nil, errors.New("session record capacity reached")
		}
		used += stat.Size()
	}
	remaining := int64(maxUserLogBytes) - used
	if remaining < metadataReserve+(64<<10) {
		return 0, nil, errors.New("session record capacity reached")
	}
	limit := int64(maxSessionBytes)
	if remaining-metadataReserve < limit {
		limit = remaining - metadataReserve
	}
	claim := prefix + ".reserve"
	file, err := root.OpenFile(claim, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, nil, err
	}
	err = file.Truncate(limit + metadataReserve)
	if err == nil {
		err = file.Sync()
	}
	_ = file.Close()
	if err != nil {
		_ = root.Remove(claim)
		return 0, nil, err
	}
	release := func() {
		r, err := os.OpenRoot(dir)
		if err != nil {
			return
		}
		defer r.Close()
		l, err := admissionLock(r)
		if err != nil {
			return
		}
		defer l.Close()
		_ = r.Remove(claim)
	}
	return limit, release, nil
}

func admissionLock(root *os.Root) (*os.File, error) {
	if info, err := root.Lstat(".admission.lock"); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("session admission lock is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := root.OpenFile(".admission.lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err == nil && (!info.Mode().IsRegular() || fileUID(info) != os.Getuid()) {
		err = errors.New("session admission lock has invalid ownership or type")
	}
	if err == nil {
		err = lockFile(file)
	}
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock session admission: %w", err)
	}
	return file, nil
}
