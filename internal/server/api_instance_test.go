package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

// downDB is a database that no longer answers.
type downDB struct{ fakeDB }

func (d *downDB) Ping(context.Context) error {
	return errors.New("dial tcp 127.0.0.1:19000: connection refused")
}

func TestInstanceInfo(t *testing.T) {
	a := newAPITestServer(t, "api-instance", func(c *config.Config) {
		c.EnableHoneypot("cowrie")
		c.Collector.GeoIPDBPath = "/data/geoip/dbip-country-lite.mmdb"
		c.AttackMap.Country = "AU"
		c.Database.Type = "clickhouse"
	})
	assertAuthRequired(t, a.h, http.MethodGet, "/api/instance", "")
	if rec := a.do(http.MethodPost, "/api/instance", `{}`); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}

	a.s.database = &fakeDB{}
	a.runner.states = map[string]instance.ServiceState{
		"database": {State: "running", Health: "healthy"}, "cowrie": {State: "running"}, "collector": {State: "exited"},
	}
	geoDir := filepath.Join(a.cfg.DataPath, "geoip")
	if err := os.MkdirAll(geoDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(geoDir, "dbip-country-lite.mmdb"), []byte("mmdb"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := a.do(http.MethodGet, "/api/instance", "")
	var info instanceInfo
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &info) != nil {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	if info.Name != "api-instance" || info.Status != "running" || info.WebUI["auth"] != "qpot-id" {
		t.Fatalf("instance: %+v", info)
	}
	var cowrie *instanceHoneypot
	for i := range info.Honeypots {
		if info.Honeypots[i].Name == "cowrie" {
			cowrie = &info.Honeypots[i]
		}
		if !info.Honeypots[i].Enabled && len(info.Honeypots[i].HostPorts) != 0 {
			t.Errorf("%s is off but lists host ports", info.Honeypots[i].Name)
		}
	}
	if cowrie == nil || !cowrie.Enabled || cowrie.Description == "" || !cowrie.HasSettings || len(cowrie.HostPorts) != 2 ||
		cowrie.HostPorts[0].ContainerPort != 22 || cowrie.HostPorts[1].ContainerPort != 23 || cowrie.HostPorts[0].HostPort == 0 {
		t.Fatalf("cowrie: %+v", cowrie)
	}
	if len(info.Services) != 3 || info.Services[0].Name != "collector" || info.Services[0].State != "exited" {
		t.Fatalf("services: %+v", info.Services)
	}
	if !info.Database.Connected || !info.Database.Healthy || info.Database.SchemaVersion != 1 || info.Database.Type != "clickhouse" {
		t.Fatalf("database: %+v", info.Database)
	}
	if !info.GeoIP.Configured || !info.GeoIP.Present || info.GeoIP.File != "dbip-country-lite.mmdb" || info.GeoIP.Updated == nil ||
		info.GeoIP.SizeBytes != 4 || info.GeoIP.UpdateCommand != "qpot geoip update -i api-instance" {
		t.Fatalf("geoip: %+v", info.GeoIP)
	}
	if info.AttackMap["country"] != "AU" || info.Cluster["clustered"] != false {
		t.Fatalf("map %v cluster %v", info.AttackMap, info.Cluster)
	}

	// Database down, Docker not answering, GeoIP file gone.
	a.s.database = &downDB{}
	a.runner.states, a.runner.statesErr = nil, errors.New("Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
	if err := os.Remove(filepath.Join(geoDir, "dbip-country-lite.mmdb")); err != nil {
		t.Fatal(err)
	}
	rec = a.do(http.MethodGet, "/api/instance", "")
	info = instanceInfo{}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &info) != nil {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	if info.Status != "unknown" || info.ServicesError == "" || len(info.Services) != 0 ||
		!info.Database.Connected || info.Database.Healthy || info.Database.Error == "" ||
		info.GeoIP.Present || !info.GeoIP.Configured {
		t.Fatalf("degraded: %+v", info)
	}
	for _, leak := range []string{"docker.sock", "19000", "connection refused"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("internal detail %q in the answer", leak)
		}
	}
}

// A configured URL is shown without anything that can carry a credential.
func TestPublicOrigin(t *testing.T) {
	secret := strings.Repeat("s3", 8)
	for in, want := range map[string]string{
		"https://canary.example.net":                                    "https://canary.example.net",
		"https://canary.example.net/c":                                  "https://canary.example.net/c",
		"http://u:" + secret + "@canary.example.net:8443/c?k=" + secret: "http://canary.example.net:8443/c",
		"https://canary.example.net/#" + secret:                         "https://canary.example.net/",
		"ftp://canary.example.net":                                      "",
		"javascript:alert(1)":                                           "",
		"":                                                              "",
		"%zz":                                                           "",
	} {
		if got := publicOrigin(in); got != want {
			t.Errorf("publicOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}
