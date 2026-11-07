// Package doctor holds the read-only health checks behind `qpot doctor`,
// `qpot setup`'s reports and the web UI's GET /api/doctor: whether Docker is
// usable, whether the host has the memory and disk QPot needs, and whether a
// started instance's containers, database, control plane and web UI work.
//
// Nothing here installs, starts or changes anything. Every failed or warning
// check carries the error code that explains it (see internal/hostsetup and
// `qpot doctor --explain <code>`).
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
)

// Check is one line of a setup/doctor report. A failed or warning check
// carries the error code that explains it (qpot doctor --explain <code>).
type Check struct {
	Name   string `json:"name"`
	Level  string `json:"level"` // "ok", "warn", "fail"
	Detail string `json:"detail"`
	Code   string `json:"code"`
}

// FirstFailCode returns the code of the first failed check, or "".
func FirstFailCode(cs []Check) string {
	for _, c := range cs {
		if c.Level == "fail" {
			if c.Code == "" {
				return "QP-BUG-001"
			}
			return c.Code
		}
	}
	return ""
}

// HostChecks verifies the host can run QPot before anything is changed. It
// runs the docker command as the current user, never with sudo.
func HostChecks(ctx context.Context) []Check {
	r := &hostsetup.ExecRunner{EUID: os.Geteuid()}
	return DockerChecks(hostsetup.DetectDocker(ctx, r, exec.LookPath), TotalMemoryBytes, hostsetup.FreeBytes)
}

// DockerChecks turns what DetectDocker found into report lines.
func DockerChecks(st hostsetup.DockerState, mem func() int64, free func(string) int64) []Check {
	var cs []Check
	switch {
	case !st.CLI:
		return append(cs, Check{"docker", "fail", "not installed - run 'qpot setup' to install it", "QP-DOCKER-001"})
	case st.Podman:
		return append(cs, Check{"docker", "fail", "the docker command is Podman, which QPot does not support", "QP-DOCKER-004"})
	}
	cs = append(cs, Check{Name: "docker", Level: "ok", Detail: "installed"})
	switch {
	case st.PermissionDenied:
		return append(cs, Check{"docker daemon", "fail",
			"your user may not use Docker - 'qpot setup' can add you to the docker group (root-equivalent)", "QP-PERM-004"})
	case !st.DaemonUp:
		return append(cs, Check{"docker daemon", "fail", "not running - start it (sudo systemctl start docker, or open Docker Desktop)", "QP-DOCKER-002"})
	case st.Server.Less(hostsetup.MinEngine):
		cs = append(cs, Check{"docker daemon", "fail", fmt.Sprintf("version %s is too old (QPot needs %s+)", st.Server, hostsetup.MinEngine), "QP-DOCKER-005"})
	default:
		cs = append(cs, Check{Name: "docker daemon", Level: "ok", Detail: "version " + st.Server.String()})
	}
	switch {
	case !st.Compose && st.ComposeV1:
		cs = append(cs, Check{"docker compose", "fail", "only docker-compose v1 found; QPot needs the Compose v2 plugin", "QP-COMPOSE-002"})
	case !st.Compose:
		cs = append(cs, Check{"docker compose", "fail", "Compose v2 plugin missing (install docker-compose-plugin, or run 'qpot setup')", "QP-COMPOSE-001"})
	case st.ComposeVersion.Less(hostsetup.MinCompose):
		cs = append(cs, Check{"docker compose", "fail", "version " + st.ComposeVersion.String() + " is too old", "QP-COMPOSE-002"})
	default:
		cs = append(cs, Check{Name: "docker compose", Level: "ok", Detail: "version " + st.ComposeVersion.String()})
	}

	if m := mem(); m > 0 {
		gibs := float64(m) / (1 << 30)
		c := Check{Name: "memory", Level: "ok", Detail: fmt.Sprintf("%.1f GiB (2 GiB+ recommended)", gibs)}
		switch {
		case gibs < 1:
			c.Level, c.Code = "fail", "QP-RES-001"
		case gibs < 2:
			c.Level, c.Code = "warn", "QP-RES-001"
		}
		cs = append(cs, c)
	}
	if home, err := os.UserHomeDir(); err == nil {
		if f := free(home); f > 0 {
			gibs := float64(f) / (1 << 30)
			c := Check{Name: "disk", Level: "ok", Detail: fmt.Sprintf("%.1f GiB free in %s (5 GiB+ recommended)", gibs, home)}
			switch {
			case gibs < 2:
				c.Level, c.Code = "fail", "QP-RES-002"
			case gibs < 5:
				c.Level, c.Code = "warn", "QP-RES-002"
			}
			cs = append(cs, c)
		}
	}
	return cs
}

// ServiceStater reports the state of an instance's compose services
// (instance.Manager does).
type ServiceStater interface {
	ServiceStates(ctx context.Context) (map[string]instance.ServiceState, error)
}

// HealthChecks inspects a started instance: containers, database schema,
// control plane and web UI. controlPlanePID returns the pid of the instance's
// running control plane (0 when none runs); nil skips that check, as for an
// instance systemd runs.
func HealthChecks(ctx context.Context, cfg *config.Config, mgr ServiceStater, controlPlanePID func(*config.Config) int) []Check {
	var cs []Check
	// First: a missing database file is why a collector crash-loops.
	if c := GeoIPCheck(cfg); c.Name != "" {
		cs = append(cs, c)
	}
	states, err := mgr.ServiceStates(ctx)
	if err != nil {
		return append(cs, Check{"containers", "fail", firstLine(err.Error()), "QP-INST-007"})
	}
	svcCheck := func(name, svc string) {
		st, ok := states[svc]
		code := "QP-INST-008"
		if svc == "database" {
			code = "QP-INST-005"
		}
		switch {
		case !ok:
			cs = append(cs, Check{name, "fail", "not created", code})
		case st.State != "running":
			cs = append(cs, Check{name, "fail", st.State, code})
		case st.Health == "unhealthy":
			cs = append(cs, Check{name, "fail", "unhealthy", code})
		case st.Health == "starting":
			cs = append(cs, Check{name, "warn", "starting", "QP-INST-004"})
		default:
			detail := "running"
			if st.Health != "" {
				detail += " (" + st.Health + ")"
			}
			cs = append(cs, Check{Name: name, Level: "ok", Detail: detail})
		}
	}
	svcCheck("database", "database")
	svcCheck("collector", "collector")
	for _, hp := range cfg.GetEnabledHoneypots() {
		svcCheck("honeypot "+hp, hp)
		// Images without a shell carry no in-container healthcheck, so
		// "running" says nothing about whether they serve: probe their
		// published TCP ports from the host instead.
		if st, ok := states[hp]; ok && st.State == "running" {
			if ports := instance.HostProbePorts(cfg, hp); len(ports) > 0 {
				if !anyPortAccepts(ports) {
					cs[len(cs)-1] = Check{"honeypot " + hp, "fail", fmt.Sprintf("running, but not accepting connections on port %v", ports), "QP-INST-008"}
				} else {
					cs[len(cs)-1].Detail = "running (accepting connections)"
				}
			}
		}
	}

	// The schema must exist or the collector drops every event.
	db, err := database.New(cfg.DatabaseClient())
	if err == nil {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = db.Connect(dctx)
		if err == nil {
			_, err = db.GetStats(dctx, time.Now().Add(-time.Hour))
			_ = db.Close()
		}
		cancel()
	}
	if err != nil {
		cs = append(cs, Check{"database schema", "fail", "not ready: " + firstLine(err.Error()), "QP-INST-005"})
	} else {
		cs = append(cs, Check{Name: "database schema", Level: "ok", Detail: "events table present"})
	}

	if controlPlanePID != nil {
		if pid := controlPlanePID(cfg); pid != 0 {
			cs = append(cs, Check{Name: "control plane", Level: "ok", Detail: fmt.Sprintf("running (pid %d)", pid)})
		} else {
			cs = append(cs, Check{"control plane", "fail",
				"not running - web UI, intelligence and HiFi resets are off (qpot up -d / qpot serve)", "QP-WEB-003"})
		}
	}
	if cfg.WebUI.Enabled {
		cs = append(cs, WebUICheck(ctx, cfg))
	}
	return cs
}

// WebUICheck confirms the web UI answering on the configured port is THIS
// instance's: a bare "something answered" passed while another instance's UI
// held the port and this one's control plane had failed to bind.
func WebUICheck(ctx context.Context, cfg *config.Config) Check {
	base := fmt.Sprintf("http://%s/", net.JoinHostPort(webHost(cfg.WebUI.BindAddr), fmt.Sprint(cfg.WebUI.Port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"api/status", nil)
	if err != nil {
		return Check{"web UI", "fail", err.Error(), "QP-WEB-002"}
	}
	// Only ever sent to this host's own address for the instance's web UI.
	req.Header.Set("X-QPot-ID", cfg.QPotID)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return Check{"web UI", "fail", "no answer on " + base, "QP-WEB-002"}
	}
	defer resp.Body.Close()
	var st struct {
		Instance string `json:"instance"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st) != nil ||
		st.Instance != cfg.InstanceName {
		return Check{"web UI", "fail", fmt.Sprintf("%s answers, but not as instance %q (port taken by something else?)", base, cfg.InstanceName), "QP-WEB-002"}
	}
	return Check{Name: "web UI", Level: "ok", Detail: base}
}

func webHost(bind string) string {
	if bind == "" || bind == "0.0.0.0" || bind == "::" {
		return "127.0.0.1"
	}
	return bind
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// anyPortAccepts reports whether a TCP connection to any of the host ports on
// loopback succeeds.
func anyPortAccepts(ports []int) bool {
	for _, p := range ports {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)), 2*time.Second)
		if err == nil {
			c.Close()
			return true
		}
	}
	return false
}

// GeoIPCheck reports a configured GeoIP database the collector cannot open
// (it then refuses to start). Paths under /data are the instance data dir.
// It returns the zero Check when no database is configured.
func GeoIPCheck(cfg *config.Config) Check {
	host := GeoIPFile(cfg)
	if host == "" {
		return Check{}
	}
	if _, err := os.Stat(host); err != nil {
		return Check{"geoip database", "fail", fmt.Sprintf("%s missing (the collector cannot start); run: qpot geoip update -i %s", host, cfg.InstanceName), "QP-INST-006"}
	}
	return Check{Name: "geoip database", Level: "ok", Detail: filepath.Base(host)}
}

// GeoIPFile returns where on the host the instance's GeoIP database is (the
// collector sees the data path at /data), or "" when none is configured.
func GeoIPFile(cfg *config.Config) string {
	p := cfg.Collector.GeoIPDBPath
	if p == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(p, "/data/"); ok {
		return filepath.Join(cfg.DataPath, filepath.FromSlash(rest))
	}
	return p
}
