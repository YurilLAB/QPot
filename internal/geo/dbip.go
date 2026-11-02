package geo

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DBIPAttribution must accompany any use of the DB-IP Lite data (CC BY 4.0).
const DBIPAttribution = `IP Geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0`

// DBIPCountryFile is the file name QPot stores the database under.
const DBIPCountryFile = "dbip-country-lite.mmdb"

// dbipURL is the monthly DB-IP Lite country database (MaxMind DB format).
var dbipURL = func(month time.Time) string {
	return "https://download.db-ip.com/free/dbip-country-lite-" + month.Format("2006-01") + ".mmdb.gz"
}

const (
	maxCompressed   = 64 << 20  // the real file is ~4 MB
	maxDecompressed = 256 << 20 // ~8 MB in practice; guards against a gzip bomb
)

// mmdbMarker starts the metadata section of every MaxMind DB file.
var mmdbMarker = []byte("\xab\xcd\xefMaxMind.com")

// DownloadDBIPCountry downloads this month's DB-IP Lite country database
// (falling back to last month's, which is what exists early in a month),
// checks it is a MaxMind DB file and writes it to dest atomically, readable by
// the collector container. client may be nil.
func DownloadDBIPCountry(ctx context.Context, client *http.Client, dest string, now time.Time) error {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	var lastErr error
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		data, err := fetchGzip(ctx, client, dbipURL(month))
		if err != nil {
			lastErr = err
			continue
		}
		if !bytes.Contains(tail(data, 128<<10), mmdbMarker) {
			return errors.New("downloaded file is not a MaxMind DB (.mmdb) database")
		}
		return writeAtomic(dest, data)
	}
	return fmt.Errorf("download DB-IP country database: %w", lastErr)
}

func fetchGzip(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	zr, err := gzip.NewReader(io.LimitReader(resp.Body, maxCompressed))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	defer zr.Close()
	data, err := io.ReadAll(io.LimitReader(zr, maxDecompressed+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	if len(data) > maxDecompressed {
		return nil, fmt.Errorf("%s: database larger than %d bytes", url, maxDecompressed)
	}
	return data, nil
}

func tail(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}

func writeAtomic(dest string, data []byte) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".dbip-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return errors.Join(werr, cerr)
	}
	// The collector container reads it; it is public data.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), dest)
}
