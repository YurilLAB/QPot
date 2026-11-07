package doctor

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

func listenLocal(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// A web UI held by something else (e.g. another instance) must not pass the
// health check.
func TestWebUICheckRequiresThisInstance(t *testing.T) {
	cfg := config.Default("mine")
	cfg.QPotID = "qp_aaaaaaaaaaaaaaaaaaaaaaaa"
	cfg.WebUI.BindAddr = "127.0.0.1"

	serve := func(h http.HandlerFunc) {
		ln, port := listenLocal(t)
		srv := &http.Server{Handler: h}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		cfg.WebUI.Port = port
	}

	serve(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-QPot-ID") != cfg.QPotID {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"instance":"mine"}`))
	})
	if c := WebUICheck(context.Background(), cfg); c.Level != "ok" {
		t.Fatalf("own web UI: %+v", c)
	}

	// Another instance: rejects our QPot ID.
	serve(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	if c := WebUICheck(context.Background(), cfg); c.Level != "fail" {
		t.Fatalf("foreign web UI passed: %+v", c)
	}
	// Some other HTTP service entirely.
	serve(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>hi</html>")) })
	if c := WebUICheck(context.Background(), cfg); c.Level != "fail" {
		t.Fatalf("unrelated HTTP service passed: %+v", c)
	}
}

func TestGeoIPCheck(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{InstanceName: "t", DataPath: dir}
	if c := GeoIPCheck(cfg); c.Name != "" {
		t.Errorf("no database configured: want no check, got %+v", c)
	}
	cfg.Collector.GeoIPDBPath = "/data/geoip/db.mmdb"
	if c := GeoIPCheck(cfg); c.Level != "fail" {
		t.Errorf("missing file: %+v", c)
	}
	if err := os.MkdirAll(filepath.Join(dir, "geoip"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip", "db.mmdb"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := GeoIPCheck(cfg); c.Level != "ok" {
		t.Errorf("present file: %+v", c)
	}
}
