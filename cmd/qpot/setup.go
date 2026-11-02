package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
	"github.com/spf13/cobra"
)

// setupProfiles are the honeypot sets `qpot setup --profile` enables.
var setupProfiles = map[string][]string{
	// Low-risk SSH/Telnet deception and a tarpit: a safe first deployment.
	"minimal": {"cowrie", "endlessh"},
	// A broad, still medium-risk sensor.
	"standard": {"cowrie", "endlessh", "dionaea", "heralding", "conpot", "adbhoney"},
	// High-interaction SSH (real OpenSSH backends behind the HiFi broker).
	"hifi": {"cowrie", "endlessh", "ssh-proxy"},
}

// check is one line of a setup/doctor report.
type check struct {
	Name   string
	Level  string // "ok", "warn", "fail"
	Detail string
}

func printChecks(title string, cs []check) (failed bool) {
	fmt.Printf("\n%s\n", title)
	for _, c := range cs {
		tag := map[string]string{"ok": "[OK]  ", "warn": "[WARN]", "fail": "[FAIL]"}[c.Level]
		fmt.Printf("  %s %-22s %s\n", tag, c.Name, c.Detail)
		if c.Level == "fail" {
			failed = true
		}
	}
	return failed
}

// preflightChecks verifies the host can run QPot before anything is changed.
func preflightChecks(ctx context.Context) []check {
	var cs []check
	if _, err := exec.LookPath("docker"); err != nil {
		return append(cs, check{"docker", "fail", "not installed - see https://docs.docker.com/engine/install/"})
	}
	cs = append(cs, check{"docker", "ok", "installed"})

	ictx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ictx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput()
	switch {
	case err != nil && strings.Contains(string(out), "permission denied"):
		return append(cs, check{"docker daemon", "fail",
			"permission denied on the docker socket - add your user to the 'docker' group " +
				"(sudo usermod -aG docker $USER, then log in again)"})
	case err != nil:
		return append(cs, check{"docker daemon", "fail", "not reachable - is the docker service running?"})
	}
	cs = append(cs, check{"docker daemon", "ok", "version " + strings.TrimSpace(string(out))})

	cctx, ccancel := context.WithTimeout(ctx, 20*time.Second)
	defer ccancel()
	if out, err := exec.CommandContext(cctx, "docker", "compose", "version", "--short").Output(); err != nil {
		cs = append(cs, check{"docker compose", "fail", "Compose v2 plugin missing (install docker-compose-plugin)"})
	} else {
		cs = append(cs, check{"docker compose", "ok", "version " + strings.TrimSpace(string(out))})
	}

	if mem := totalMemoryBytes(); mem > 0 {
		gib := float64(mem) / (1 << 30)
		lvl := "ok"
		if gib < 2 {
			lvl = "warn"
		}
		cs = append(cs, check{"memory", lvl, fmt.Sprintf("%.1f GiB (2 GiB+ recommended)", gib)})
	}
	if home, err := os.UserHomeDir(); err == nil {
		if free := freeDiskBytes(home); free > 0 {
			gib := float64(free) / (1 << 30)
			lvl := "ok"
			if gib < 5 {
				lvl = "warn"
			}
			cs = append(cs, check{"disk", lvl, fmt.Sprintf("%.1f GiB free in %s (5 GiB+ recommended)", gib, home)})
		}
	}
	return cs
}

// portChecks reports host ports the instance needs that something else holds.
func portChecks(cfg *config.Config) []check {
	ports := instance.PublishedHostPorts(cfg)
	keys := make([]string, 0, len(ports))
	for k := range ports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var busy []string
	for _, k := range keys {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", ports[k]))
		if err != nil {
			busy = append(busy, fmt.Sprintf("%d (%s)", ports[k], strings.ReplaceAll(k, "\x00", ":")))
			continue
		}
		_ = ln.Close()
	}
	if len(busy) > 0 {
		return []check{{"host ports", "fail", "already in use: " + strings.Join(busy, ", ")}}
	}
	return []check{{"host ports", "ok", fmt.Sprintf("%d free", len(ports))}}
}

// healthChecks inspects a started instance: containers, database schema,
// control plane and web UI.
func healthChecks(ctx context.Context, cfg *config.Config, mgr *instance.Manager, wantControlPlane bool) []check {
	var cs []check
	states, err := mgr.ServiceStates(ctx)
	if err != nil {
		return append(cs, check{"containers", "fail", err.Error()})
	}
	svcCheck := func(name, svc string) {
		st, ok := states[svc]
		switch {
		case !ok:
			cs = append(cs, check{name, "fail", "not created"})
		case st.State != "running":
			cs = append(cs, check{name, "fail", st.State})
		case st.Health == "unhealthy":
			cs = append(cs, check{name, "fail", "unhealthy"})
		case st.Health == "starting":
			cs = append(cs, check{name, "warn", "starting"})
		default:
			detail := "running"
			if st.Health != "" {
				detail += " (" + st.Health + ")"
			}
			cs = append(cs, check{name, "ok", detail})
		}
	}
	svcCheck("database", "database")
	svcCheck("collector", "collector")
	for _, hp := range cfg.GetEnabledHoneypots() {
		svcCheck("honeypot "+hp, hp)
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
		cs = append(cs, check{"database schema", "fail", "not ready: " + firstLine(err.Error())})
	} else {
		cs = append(cs, check{"database schema", "ok", "events table present"})
	}

	if wantControlPlane {
		if pid := runningServePID(cfg); pid != 0 {
			cs = append(cs, check{"control plane", "ok", fmt.Sprintf("running (pid %d)", pid)})
		} else {
			cs = append(cs, check{"control plane", "fail",
				"not running - web UI, intelligence and HiFi resets are off (qpot up -d / qpot serve)"})
		}
	}
	if cfg.WebUI.Enabled {
		cs = append(cs, webUICheck(ctx, cfg))
	}
	return cs
}

// webUICheck confirms the web UI answering on the configured port is THIS
// instance's: a bare "something answered" passed while another instance's UI
// held the port and this one's control plane had failed to bind.
func webUICheck(ctx context.Context, cfg *config.Config) check {
	base := fmt.Sprintf("http://%s/", net.JoinHostPort(webHost(cfg.WebUI.BindAddr), fmt.Sprint(cfg.WebUI.Port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"api/status", nil)
	if err != nil {
		return check{"web UI", "fail", err.Error()}
	}
	// Only ever sent to this host's own address for the instance's web UI.
	req.Header.Set("X-QPot-ID", cfg.QPotID)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return check{"web UI", "fail", "no answer on " + base}
	}
	defer resp.Body.Close()
	var st struct {
		Instance string `json:"instance"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st) != nil ||
		st.Instance != cfg.InstanceName {
		return check{"web UI", "fail", fmt.Sprintf("%s answers, but not as instance %q (port taken by something else?)", base, cfg.InstanceName)}
	}
	return check{"web UI", "ok", base}
}

// freeWebPort returns the configured web UI port if it is usable, else the
// next usable one within 100 ports above it. A port is usable when nothing is
// listening on it and no other instance on this host has it configured (a
// stopped instance would otherwise collide on its next start).
func freeWebPort(cfg *config.Config) (int, bool) {
	claimed := map[int]bool{}
	if infos, err := instance.List(); err == nil {
		for _, inf := range infos {
			if inf.Name == cfg.InstanceName {
				continue
			}
			if other, err := config.Load(inf.Name); err == nil && other.WebUI.Enabled {
				claimed[other.WebUI.Port] = true
			}
		}
	}
	for p := cfg.WebUI.Port; p < cfg.WebUI.Port+100 && p <= 65535; p++ {
		if claimed[p] {
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(cfg.WebUI.BindAddr, fmt.Sprint(p)))
		if err == nil {
			_ = ln.Close()
			return p, true
		}
	}
	return 0, false
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

// waitHealthy re-runs healthChecks until nothing fails (warnings allowed) or
// the timeout passes, returning the last result.
func waitHealthy(ctx context.Context, cfg *config.Config, mgr *instance.Manager, wantCP bool, timeout time.Duration) []check {
	deadline := time.Now().Add(timeout)
	for {
		cs := healthChecks(ctx, cfg, mgr, wantCP)
		ok := true
		for _, c := range cs {
			if c.Level != "ok" {
				ok = false
			}
		}
		if ok || time.Now().After(deadline) || ctx.Err() != nil {
			return cs
		}
		time.Sleep(5 * time.Second)
	}
}

// createInstance creates a new instance (config, QPot ID, data directories).
func createInstance(ctx context.Context, name string) (*config.Config, *instance.QPotID, error) {
	if err := validateInstanceName(name); err != nil {
		return nil, nil, err
	}
	if _, err := os.Stat(config.Default(name).ConfigPath); err == nil {
		return nil, nil, fmt.Errorf("instance %q already exists; remove it first with 'qpot instance remove %s' or choose another name", name, name)
	}
	qpotID, err := instance.GenerateID(name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate QPot ID: %w", err)
	}
	cfg := config.Default(name)
	cfg.QPotID = qpotID.ID
	// Several instances on one host would all default to the same web UI port;
	// give a new one a port no other instance uses or has configured.
	if cfg.WebUI.Enabled {
		if port, ok := freeWebPort(cfg); ok && port != cfg.WebUI.Port {
			fmt.Printf("[INFO] Web UI port %d is taken by another instance; %q will use %d\n", cfg.WebUI.Port, name, port)
			cfg.WebUI.Port = port
		}
	}
	if err := config.Save(cfg); err != nil {
		return nil, nil, fmt.Errorf("failed to save config: %w", err)
	}
	qpotID.DataPath = cfg.DataPath
	if err := qpotID.Save(); err != nil {
		return nil, nil, fmt.Errorf("failed to save QPot ID: %w", err)
	}
	mgr, err := instance.NewManager(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create instance manager: %w", err)
	}
	if err := mgr.Initialize(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize instance: %w", err)
	}
	return cfg, qpotID, nil
}

func newSetupCommand() *cobra.Command {
	var (
		instanceName string
		profile      string
		service      bool
		noStart      bool
		timeout      time.Duration
	)
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Check the host, create and start a QPot instance, and verify it works",
		Long: `One command from a fresh host to a verified, running honeypot:

  1. checks Docker, Compose, permissions, memory and disk
  2. creates the instance (if new) with a honeypot profile
  3. checks the host ports it needs are free
  4. starts the containers and the control plane (web UI, intelligence)
  5. waits until the database, collector, honeypots and web UI are healthy
  6. optionally installs a systemd service so it survives reboots (--service)

Secure defaults are kept: the web UI listens on 127.0.0.1 with QPot ID auth,
the database is only reachable on 127.0.0.1 with a random password, and
nothing is run with sudo.`,
		Example: `  qpot setup
  qpot setup --profile standard
  qpot setup -i sensor1 --profile hifi --service`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			hps, ok := setupProfiles[profile]
			if !ok {
				return fmt.Errorf("unknown profile %q (minimal, standard, hifi)", profile)
			}
			if printChecks("Host checks", preflightChecks(ctx)) {
				return errors.New("fix the failed checks above and run 'qpot setup' again")
			}

			cfg, _, err := loadInstance(instanceName)
			created := false
			if _, statErr := os.Stat(config.Default(instanceName).ConfigPath); errors.Is(statErr, os.ErrNotExist) {
				if cfg, _, err = createInstance(ctx, instanceName); err != nil {
					return err
				}
				created = true
				for _, hp := range hps {
					cfg.EnableHoneypot(hp)
				}
				if err := config.Save(cfg); err != nil {
					return fmt.Errorf("failed to save config: %w", err)
				}
			} else if err != nil {
				return err
			}
			if created {
				fmt.Printf("\n[OK] Created instance %q with the %s profile: %s\n", instanceName, profile, strings.Join(hps, ", "))
			} else {
				fmt.Printf("\n[OK] Using existing instance %q (honeypots: %s)\n", instanceName, strings.Join(cfg.GetEnabledHoneypots(), ", "))
			}

			mgr, err := instance.NewManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to create instance manager: %w", err)
			}
			var pcs []check
			if !mgr.IsRunning(ctx) {
				pcs = portChecks(cfg)
			}
			if cfg.WebUI.Enabled && !service && runningServePID(cfg) == 0 {
				if err := webPortFree(cfg); err != nil {
					pcs = append(pcs, check{"web UI port", "fail", err.Error()})
				} else {
					pcs = append(pcs, check{"web UI port", "ok", fmt.Sprintf("%d free", cfg.WebUI.Port)})
				}
			}
			if len(pcs) > 0 && printChecks("Port checks", pcs) {
				return errors.New("free the ports above (or change base_port / web_ui.port in the config) and run 'qpot setup' again")
			}
			if noStart {
				fmt.Printf("\nReady. Start it with: qpot up -d -i %s\n", instanceName)
				return nil
			}

			if service {
				unit, err := installService(ctx, cfg)
				if err != nil {
					return fmt.Errorf("install service: %w", err)
				}
				fmt.Printf("\n[OK] Installed and started systemd service %s\n", unit)
			} else {
				if !mgr.IsRunning(ctx) {
					if err := mgr.Start(ctx, true); err != nil {
						return fmt.Errorf("failed to start instance: %w", err)
					}
				}
				if _, _, err := startBackgroundServe(cfg); err != nil {
					return fmt.Errorf("failed to start the control plane: %w", err)
				}
			}

			fmt.Printf("\nWaiting up to %s for everything to become healthy...\n", timeout)
			failed := printChecks("Health", waitHealthy(ctx, cfg, mgr, !service, timeout))
			fmt.Println()
			fmt.Printf("QPot ID (your web UI / API credential - keep it private): %s\n", cfg.QPotID)
			fmt.Printf("Web UI: http://%s:%d  (local only; from another machine use: ssh -L %d:127.0.0.1:%d <this-host>)\n",
				webHost(cfg.WebUI.BindAddr), cfg.WebUI.Port, cfg.WebUI.Port, cfg.WebUI.Port)
			fmt.Printf("Check health any time with: qpot doctor -i %s\n", instanceName)
			if failed {
				return errors.New("some health checks failed (see above); 'qpot doctor' re-runs them")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().StringVar(&profile, "profile", "minimal", "honeypot set for a new instance: minimal, standard or hifi")
	cmd.Flags().BoolVar(&service, "service", false, "install and start a systemd service (Linux) so QPot survives reboots")
	cmd.Flags().BoolVar(&noStart, "no-start", false, "only check the host and create the instance")
	cmd.Flags().DurationVar(&timeout, "timeout", 4*time.Minute, "how long to wait for the instance to become healthy")
	return cmd
}

func newDoctorCommand() *cobra.Command {
	var instanceName string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that a QPot instance is healthy end to end",
		Long: "Runs the host checks and inspects a running instance: containers, database schema, " +
			"control plane and web UI. Exits non-zero if anything failed.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			failed := printChecks("Host checks", preflightChecks(ctx))
			cfg, _, err := loadInstance(instanceName)
			if err != nil {
				return err
			}
			mgr, err := instance.NewManager(cfg)
			if err != nil {
				return err
			}
			if !mgr.IsRunning(ctx) {
				printChecks("Instance "+instanceName, []check{{"containers", "fail", "not running (qpot up -d -i " + instanceName + ")"}})
				return errors.New("instance is not running")
			}
			if printChecks("Instance "+instanceName, healthChecks(ctx, cfg, mgr, !systemdManaged(cfg))) || failed {
				return errors.New("some checks failed")
			}
			fmt.Println("\nAll checks passed.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	return cmd
}

// serviceName is the systemd unit name for an instance.
func serviceName(cfg *config.Config) string { return "qpot-" + cfg.InstanceName + ".service" }

// systemdManaged reports whether the instance runs as a systemd service (its
// control plane then lives in `qpot up`, not a background `qpot serve`).
func systemdManaged(cfg *config.Config) bool {
	for _, args := range [][]string{{"is-active", "--quiet"}, {"--user", "is-active", "--quiet"}} {
		if exec.Command("systemctl", append(args, serviceName(cfg))...).Run() == nil {
			return true
		}
	}
	return false
}

// installService writes and enables a systemd unit running `qpot up` for the
// instance: a system unit when run as root, otherwise a user unit.
func installService(ctx context.Context, cfg *config.Config) (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("--service is only supported on Linux (systemd)")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "", errors.New("systemctl not found (is this a systemd system?)")
	}
	// systemd must actually be PID 1 (not e.g. a container), checked before
	// anything is written.
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return "", errors.New("systemd is not running on this host; start QPot with 'qpot up -d' instead")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	asRoot := os.Geteuid() == 0
	dir, target, sysctl := "/etc/systemd/system", "multi-user.target", []string{}
	if !asRoot {
		dir, target, sysctl = filepath.Join(home, ".config", "systemd", "user"), "default.target", []string{"--user"}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	unit := renderServiceUnit(exe, home, cfg.InstanceName, target, asRoot)
	path := filepath.Join(dir, serviceName(cfg))
	// #nosec G306 -- a systemd unit is meant to be world-readable; it holds no secrets.
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return "", err
	}
	for _, a := range [][]string{{"daemon-reload"}, {"enable", "--now", serviceName(cfg)}} {
		c := exec.CommandContext(ctx, "systemctl", append(append([]string{}, sysctl...), a...)...)
		if out, err := c.CombinedOutput(); err != nil {
			_ = os.Remove(path) // don't leave a half-installed unit behind
			return "", fmt.Errorf("systemctl %s: %w: %s", strings.Join(a, " "), err, strings.TrimSpace(string(out)))
		}
	}
	if !asRoot {
		fmt.Println("[INFO] Installed as a user service. For it to start at boot without a login, run once:")
		fmt.Println("       sudo loginctl enable-linger " + os.Getenv("USER"))
	}
	return path, nil
}

// renderServiceUnit builds the systemd unit. `qpot up` runs in the foreground
// (containers + control plane) and stops the stack on SIGTERM.
func renderServiceUnit(exe, home, instanceName, target string, system bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, `[Unit]
Description=QPot honeypot instance %[1]s
Documentation=https://github.com/YurilLAB/QPot
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=%[2]s up -i %[1]s
Restart=on-failure
RestartSec=10
TimeoutStopSec=120
Environment=HOME=%[3]s
NoNewPrivileges=yes
PrivateTmp=yes
`, instanceName, exe, home)
	if system {
		// /usr, /boot, /efi and /etc read-only for the service; it only writes
		// under HOME/.qpot and talks to docker over its socket.
		b.WriteString("ProtectSystem=full\n")
	}
	fmt.Fprintf(&b, "\n[Install]\nWantedBy=%s\n", target)
	return b.String()
}
