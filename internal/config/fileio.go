package config

import (
	"fmt"
	"io"
)

// ReadFile reads a config file, refusing one larger than limit bytes (0: no
// limit). It sees either the whole file before a Save or the whole file after
// it; on Windows it waits out a Save that is replacing the file that moment.
func ReadFile(path string, limit int64) ([]byte, error) {
	f, err := openConfig(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := io.Reader(f)
	if limit > 0 {
		r = io.LimitReader(f, limit+1)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if limit > 0 && int64(len(data)) > limit {
		return nil, fmt.Errorf("config file larger than %d bytes", limit)
	}
	return data, nil
}
