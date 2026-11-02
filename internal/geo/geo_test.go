package geo

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLookup(t *testing.T) {
	c, ok := Lookup(" au ")
	if !ok || c.Code != "AU" || c.Name != "Australia" || c.Lat > -20 || c.Lon < 120 {
		t.Fatalf("Lookup(au) = %+v, %v", c, ok)
	}
	if _, ok := Lookup("ZZ"); ok {
		t.Error("unknown code found")
	}
	if len(countries) < 240 {
		t.Errorf("only %d countries", len(countries))
	}
}

func TestCountryForZone(t *testing.T) {
	tab := filepath.Join(t.TempDir(), "zone1970.tab")
	if err := os.WriteFile(tab, []byte("# comment\nAU\t-3352+15113\tAustralia/Sydney\tNew South Wales\nCH,DE,LI\t+4723+00832\tEurope/Zurich\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := countryForZone(tab, "Australia/Sydney"); got != "AU" {
		t.Errorf("Sydney -> %q", got)
	}
	if got := countryForZone(tab, "Europe/Zurich"); got != "CH" {
		t.Errorf("Zurich -> %q (first listed code)", got)
	}
	if got := countryForZone(tab, "Etc/UTC"); got != "" {
		t.Errorf("UTC -> %q", got)
	}
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func TestDownloadDBIPCountry(t *testing.T) {
	good := append(bytes.Repeat([]byte{0}, 1024), append(mmdbMarker, []byte("metadata")...)...)
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		switch {
		case strings.Contains(r.URL.Path, "2026-11"):
			http.NotFound(w, r) // not published yet this month
		case strings.Contains(r.URL.Path, "2026-10"):
			w.Write(gz(t, good))
		case strings.Contains(r.URL.Path, "bad"):
			w.Write(gz(t, []byte("<html>not a database</html>")))
		}
	}))
	defer srv.Close()
	orig := dbipURL
	defer func() { dbipURL = orig }()
	dbipURL = func(m time.Time) string { return srv.URL + "/dbip-country-lite-" + m.Format("2006-01") + ".mmdb.gz" }

	dest := filepath.Join(t.TempDir(), "geoip", DBIPCountryFile)
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	if err := DownloadDBIPCountry(context.Background(), srv.Client(), dest, now); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, good) || len(hits) != 2 {
		t.Fatalf("file %d bytes, requests %v", len(got), hits)
	}
	st, _ := os.Stat(dest)
	if st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", st.Mode().Perm())
	}

	dbipURL = func(m time.Time) string { return srv.URL + "/bad.mmdb.gz" }
	if err := DownloadDBIPCountry(context.Background(), srv.Client(), filepath.Join(t.TempDir(), "x.mmdb"), now); err == nil {
		t.Error("a non-mmdb download was accepted")
	}
}
