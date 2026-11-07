package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/qpot/qpot/internal/doctor"
	"github.com/qpot/qpot/internal/geo"
	"github.com/qpot/qpot/internal/instance"
)

// GET /api/instance: what this instance is and how it is set up, for the web
// UI's instance page. It never carries a secret: no QPot ID, no passwords, no
// webhook URL, no cluster keys.

type instanceHoneypot struct {
	Name        string                 `json:"name"`
	Enabled     bool                   `json:"enabled"`
	Risk        string                 `json:"risk"`
	Description string                 `json:"description"`
	HostPorts   []instance.PortMapping `json:"host_ports"`
	HasSettings bool                   `json:"has_settings"`
}

type instanceService struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Health string `json:"health"`
}

type instanceDatabase struct {
	Type          string `json:"type"`
	Connected     bool   `json:"connected"`
	Healthy       bool   `json:"healthy"`
	SchemaVersion int    `json:"schema_version"`
	Error         string `json:"error,omitempty"`
}

type instanceGeoIP struct {
	Configured    bool       `json:"configured"`
	Present       bool       `json:"present"`
	File          string     `json:"file,omitempty"`
	Updated       *time.Time `json:"updated,omitempty"`
	AgeDays       int        `json:"age_days,omitempty"`
	SizeBytes     int64      `json:"size_bytes,omitempty"`
	Attribution   string     `json:"attribution"`
	UpdateCommand string     `json:"update_command"`
}

type instanceInfo struct {
	Name          string             `json:"name"`
	Version       string             `json:"version"`
	WebUI         map[string]any     `json:"web_ui"`
	Status        string             `json:"status"`
	Honeypots     []instanceHoneypot `json:"honeypots"`
	Services      []instanceService  `json:"services"`
	ServicesError string             `json:"services_error,omitempty"`
	Database      instanceDatabase   `json:"database"`
	GeoIP         instanceGeoIP      `json:"geoip"`
	AttackMap     map[string]any     `json:"attack_map"`
	Canary        map[string]any     `json:"canary"`
	Intelligence  map[string]any     `json:"intelligence"`
	Alerts        map[string]any     `json:"alerts"`
	Cluster       map[string]any     `json:"cluster"`
}

// serviceStater reaches the compose services' states: the test runner when
// it has them, else the server's manager.
func (s *Server) serviceStater() doctor.ServiceStater {
	if s.api.runner != nil {
		if st, ok := s.api.runner(s.config).(doctor.ServiceStater); ok {
			return st
		}
	}
	if s.manager == nil {
		return nil
	}
	return s.manager
}

func (s *Server) handleInstance(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	cfg, err := s.readConfig()
	if err != nil {
		slog.Error("instance info: config file not read", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be read.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	info := instanceInfo{
		Name:    cfg.InstanceName,
		Version: Version,
		WebUI:   map[string]any{"bind_addr": cfg.WebUI.BindAddr, "port": cfg.WebUI.Port, "auth": s.authMode()},
		Status:  "unknown",
	}

	ports := instance.HostPortMappings(cfg)
	hps := cfg.SnapshotHoneypots()
	names := make([]string, 0, len(hps))
	for n := range hps {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		hp := hps[n]
		hpPorts := ports[n]
		if hpPorts == nil {
			hpPorts = []instance.PortMapping{}
		}
		info.Honeypots = append(info.Honeypots, instanceHoneypot{
			Name: n, Enabled: hp.Enabled, Risk: hp.RiskLevel, Description: instance.HoneypotDescription(n),
			HostPorts: hpPorts, HasSettings: len(instance.SettingKeys(n)) > 0,
		})
	}

	info.Services = []instanceService{}
	if st := s.serviceStater(); st == nil {
		info.ServicesError = "This server cannot reach the instance's containers."
	} else if states, err := st.ServiceStates(ctx); err != nil {
		slog.Warn("instance info: container states not read", "error", err)
		info.ServicesError = "Docker did not report the containers (is Docker running?)."
	} else {
		info.Status = "stopped"
		for name, st := range states {
			info.Services = append(info.Services, instanceService{Name: name, State: st.State, Health: st.Health})
			if st.State == "running" {
				info.Status = "running"
			}
		}
		sort.Slice(info.Services, func(i, j int) bool { return info.Services[i].Name < info.Services[j].Name })
	}

	info.Database = s.databaseInfo(ctx)
	info.GeoIP = geoIPInfo(cfg.InstanceName, doctor.GeoIPFile(cfg))
	info.AttackMap = map[string]any{"country": cfg.AttackMap.Country}
	info.Canary = map[string]any{"enabled": cfg.Canary.Enabled && s.canaries != nil, "base_url": publicOrigin(cfg.Canary.BaseURL)}
	info.Intelligence = map[string]any{"enabled": cfg.Intelligence.Enabled, "worker_running": s.worker != nil}
	info.Alerts = map[string]any{
		"enabled":            cfg.Alerts.Enabled,
		"webhook_configured": cfg.Alerts.WebhookURL != "",
		"response_hooks":     len(cfg.Response.OnAttackDetected),
	}
	info.Cluster = map[string]any{"clustered": false}
	if cm, live := s.clusterView(); cm != nil {
		if st := cm.GetStatus(); st != nil {
			info.Cluster = map[string]any{"clustered": true, "name": st.Name, "nodes": st.NodeCount,
				"healthy": st.HealthyNodes, "running": st.IsRunning, "live": live}
		}
	}
	writeJSON(w, http.StatusOK, info)
}

// authMode names how the web UI authenticates.
func (s *Server) authMode() string {
	switch {
	case s.config.WebUI.QPotIDAuth:
		return "qpot-id"
	case s.config.WebUI.Username != "" && s.config.WebUI.Password != "":
		return "basic"
	}
	return "none"
}

// databaseInfo reports the database's type and whether it answers, without
// its address or credentials.
func (s *Server) databaseInfo(ctx context.Context) instanceDatabase {
	d := instanceDatabase{Type: s.config.Database.Type}
	if s.database == nil {
		d.Error = "The control plane has no database connection (it was not reachable when the server started)."
		return d
	}
	d.Connected = true
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.database.Ping(pctx); err != nil {
		slog.Warn("instance info: database ping failed", "error", err)
		d.Error = "The database does not answer."
		return d
	}
	d.Healthy = true
	if v, err := s.database.GetSchemaVersion(pctx); err == nil {
		d.SchemaVersion = v
	}
	return d
}

// publicOrigin is a configured URL without a user name, password, query or
// fragment (a credential could sit in any of them), or "" when it is not an
// http(s) URL.
func publicOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

// geoIPInfo reports the GeoIP country database the collector uses.
func geoIPInfo(instanceName, path string) instanceGeoIP {
	g := instanceGeoIP{Attribution: geo.DBIPAttribution, UpdateCommand: fmt.Sprintf("qpot geoip update -i %s", instanceName)}
	if path == "" {
		return g
	}
	g.Configured, g.File = true, filepath.Base(path)
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return g
	}
	mod := fi.ModTime().UTC()
	g.Present, g.Updated, g.SizeBytes = true, &mod, fi.Size()
	g.AgeDays = int(time.Since(mod).Hours() / 24)
	return g
}
