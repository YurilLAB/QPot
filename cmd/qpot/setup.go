package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/doctor"
	"github.com/qpot/qpot/internal/hostsetup"
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

// check is one line of a setup/doctor report (see internal/doctor).
type check = doctor.Check

// totalMemoryBytes is the host's physical memory, or 0 when unknown.
func totalMemoryBytes() int64 { return doctor.TotalMemoryBytes() }

// printChecksTo prints a report; details can carry text from the system
// (docker, ports, paths), so they go through termSafe.
func printChecksTo(w io.Writer, title string, cs []check) (failed bool) {
	fmt.Fprintf(w, "\n%s\n", title)
	for _, c := range cs {
		tag := map[string]string{"ok": "[OK]  ", "warn": "[WARN]", "fail": "[FAIL]"}[c.Level]
		code := ""
		if c.Level != "ok" && c.Code != "" {
			code = "  (" + c.Code + ")"
		}
		fmt.Fprintf(w, "  %s %-22s %s%s\n", tag, termSafe(c.Name), termSafe(c.Detail), code)
		if c.Level == "fail" {
			failed = true
		}
	}
	return failed
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
		return []check{{Name: "host ports", Level: "fail", Detail: "already in use: " + strings.Join(busy, ", "), Code: "QP-PORT-002"}}
	}
	return []check{{Name: "host ports", Level: "ok", Detail: fmt.Sprintf("%d free", len(ports))}}
}

// healthChecks inspects a started instance: containers, database schema,
// control plane (when wantControlPlane) and web UI.
func healthChecks(ctx context.Context, cfg *config.Config, mgr *instance.Manager, wantControlPlane bool) []check {
	var controlPlane func(*config.Config) int
	if wantControlPlane {
		controlPlane = runningServePID
	}
	return doctor.HealthChecks(ctx, cfg, mgr, controlPlane)
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
		select {
		case <-ctx.Done():
			return cs
		case <-time.After(5 * time.Second):
		}
	}
}

// createInstance creates a new instance (config, QPot ID, data directories).
func createInstance(ctx context.Context, name string) (*config.Config, *instance.QPotID, error) {
	return createInstanceWith(ctx, name, nil, true)
}

// createInstanceWith creates a new instance. apply, when set, adjusts the
// default config before anything is saved. autoPort moves the web UI to the
// next free port when another instance has the default one; setup turns it
// off because it has already checked the port the owner chose. Errors are
// coded (see internal/hostsetup).
func createInstanceWith(ctx context.Context, name string, apply func(*config.Config), autoPort bool) (*config.Config, *instance.QPotID, error) {
	if err := validateInstanceName(name); err != nil {
		return nil, nil, hostsetup.E("QP-INPUT-001").Wrap(err)
	}
	if _, err := os.Stat(config.Default(name).ConfigPath); err == nil {
		return nil, nil, hostsetup.E("QP-INST-001").WithWhy("Instance %q already exists.", name).
			WithFix("Remove it first with 'qpot instance remove %s', or choose another name.", name)
	}
	qpotID, err := instance.GenerateID(name)
	if err != nil {
		return nil, nil, hostsetup.E("QP-INST-001").WithWhy("A QPot ID could not be generated.").Wrap(err)
	}
	cfg := config.Default(name)
	cfg.QPotID = qpotID.ID
	if apply != nil {
		apply(cfg)
	}
	// Several instances on one host would all default to the same web UI port;
	// give a new one a port no other instance uses or has configured.
	if autoPort && cfg.WebUI.Enabled {
		if port, ok := freeWebPort(cfg); ok && port != cfg.WebUI.Port {
			fmt.Printf("[INFO] Web UI port %d is taken by another instance; %q will use %d\n", cfg.WebUI.Port, name, port)
			cfg.WebUI.Port = port
		}
	}
	if err := config.Save(cfg); err != nil {
		return nil, nil, hostsetup.E("QP-INST-002").Wrap(err)
	}
	qpotID.DataPath = cfg.DataPath
	if err := qpotID.Save(); err != nil {
		return nil, nil, hostsetup.E("QP-INST-001").WithWhy("The QPot ID file could not be written.").Wrap(err)
	}
	mgr, err := instance.NewManager(cfg)
	if err != nil {
		return nil, nil, hostsetup.E("QP-INST-001").Wrap(err)
	}
	if err := mgr.Initialize(ctx); err != nil {
		return nil, nil, hostsetup.E("QP-INST-001").WithWhy("The instance's folders and files could not be prepared.").Wrap(err)
	}
	return cfg, qpotID, nil
}

// exitProcess ends the process with a status; tests replace it.
var exitProcess = os.Exit

// finishCoded prints a coded error in plain words to w and exits with its
// category's status. It never returns for a non-nil error.
func finishCoded(w io.Writer, err error) error {
	if err == nil {
		return nil
	}
	exitProcess(printSetupError(w, err))
	return err
}

// printSetupError prints a coded error: what went wrong, why, what to do,
// and the technical details indented below. It returns the exit status.
func printSetupError(w io.Writer, err error) int {
	e := hostsetup.AsError(err)
	fmt.Fprintf(w, "\nERROR %s: %s\n", e.Code, termSafe(e.Entry().Title))
	fmt.Fprintf(w, "  Why:  %s\n", termSafe(e.Cause()))
	fmt.Fprintf(w, "  Fix:  %s\n", termSafe(e.Remedy()))
	if d := strings.TrimSpace(e.Details); d != "" {
		lines := strings.Split(d, "\n")
		if len(lines) > 30 {
			lines = append(lines[:30], "...")
		}
		fmt.Fprintln(w, "  Details:")
		for _, l := range lines {
			fmt.Fprintf(w, "    %s\n", termSafe(strings.TrimRight(l, "\r")))
		}
	}
	fmt.Fprintf(w, "  More: qpot doctor --explain %s\n", e.Code)
	return hostsetup.ExitStatus(e.Code)
}

func newSetupCommand() *cobra.Command {
	var o setupOptions
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up QPot: check the host, install Docker if needed, create, start and verify an instance",
		Long: `Guided setup from a fresh host to a verified, running honeypot.

In a terminal it asks a few questions (instance name, honeypots, web UI
address and port, and a few more); every question has a safe default you
accept with Enter. Without a terminal, or with --yes, it asks nothing and
uses the flags and defaults instead.

  1. checks the computer (operating system, Docker, Compose)
  2. installs, updates or starts Docker Engine and the Compose plugin when
     needed - only after showing the exact commands and getting your yes
     (or --install-docker); on Linux from Docker's signed repository, with
     the signing key's fingerprint checked
  3. checks memory, disk space and the ports QPot needs
  4. creates the instance and downloads the free DB-IP Lite country database
     (--no-geoip skips it)
  5. starts the containers and the control plane (web UI, intelligence), or
     installs a systemd service (--service)
  6. waits until everything is healthy and prints where the web UI is, how
     to log in and what to do next

Setup can be run again at any time: it checks what is already done and
continues from there. Every problem it reports has a code such as
QP-PKG-001; 'qpot doctor --explain <code>' explains it, and the process exits
with the code's category status (see doc/setup-errors.md).

Secure defaults are kept: the web UI listens on 127.0.0.1 with QPot ID auth
and the database only on 127.0.0.1 with a random password.`,
		Example: `  qpot setup                                   # guided, in a terminal
  qpot setup --yes                             # no questions, defaults
  qpot setup --yes --install-docker --docker-group --profile standard
  qpot setup -i sensor1 --profile hifi --service
  qpot setup --honeypots cowrie,dionaea --port 8081
  qpot setup --dry-run                         # show what it would do
  qpot setup --country DE                      # where the attack map draws this sensor`,
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			o.instanceSet, o.profileSet, o.honeypotsSet = f.Changed("instance"), f.Changed("profile"), f.Changed("honeypots")
			o.bindSet, o.portSet, o.countrySet = f.Changed("bind"), f.Changed("port"), f.Changed("country")
			o.geoipSet, o.databaseSet, o.outboundSet = f.Changed("no-geoip"), f.Changed("database"), f.Changed("outbound")
			o.serviceSet = f.Changed("service")
			env, cleanup, eerr := newSetupEnv(cmd, o.verbose)
			if eerr != nil {
				return finishCoded(cmd.ErrOrStderr(), eerr)
			}
			err := runSetup(cmd.Context(), env, o)
			cleanup()
			return finishCoded(cmd.ErrOrStderr(), err)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.instance, "instance", "i", "default", "instance name")
	f.StringVar(&o.profile, "profile", "minimal", "honeypots for a new instance: minimal, standard or hifi")
	f.StringVar(&o.honeypots, "honeypots", "", "honeypots for a new instance by name, comma-separated (instead of --profile)")
	f.StringVar(&o.bind, "bind", "127.0.0.1", "web UI address for a new instance (127.0.0.1 = this computer only)")
	f.IntVar(&o.port, "port", 8080, "web UI port for a new instance (the next free one if the default is taken)")
	f.StringVar(&o.database, "database", "clickhouse", "event database for a new instance: clickhouse or timescaledb")
	f.StringVar(&o.outbound, "outbound", "allow", "honeypot connections to the internet for a new instance: allow or block (private networks are always blocked)")
	f.BoolVar(&o.service, "service", false, "install and start a systemd service (Linux) so QPot survives reboots")
	f.BoolVar(&o.noStart, "no-start", false, "set up and create the instance, but do not start it")
	f.BoolVar(&o.noGeoIP, "no-geoip", false, "do not download the DB-IP Lite country database")
	f.StringVar(&o.country, "country", "", "two-letter country code of this sensor, for the attack map (default: from the host's time zone)")
	f.DurationVar(&o.timeout, "timeout", 4*time.Minute, "how long to wait for the instance to become healthy")
	f.BoolVarP(&o.yes, "yes", "y", false, "ask no questions: use flags and defaults (installing Docker still needs --install-docker)")
	f.BoolVar(&o.installDocker, "install-docker", false, "allow setup to install, update and start Docker and the Compose plugin (uses sudo)")
	f.BoolVar(&o.dockerGroup, "docker-group", false, "allow setup to add your user to the docker group (root-equivalent; uses sudo)")
	f.StringVar(&o.dockerSource, "docker-source", "auto", "where Docker comes from on Linux: auto, docker (Docker's repository) or distro (the distribution's packages)")
	f.BoolVar(&o.dryRun, "dry-run", false, "check the computer and show what setup would do, without changing anything")
	f.BoolVar(&o.verbose, "verbose", false, "show the full output of the commands setup runs")
	f.DurationVar(&o.lockWait, "package-lock-wait", 2*time.Minute, "how long to wait for another program that is installing software")
	_ = f.MarkHidden("package-lock-wait")
	return cmd
}

func newDoctorCommand() *cobra.Command {
	var instanceName, explain string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that a QPot instance is healthy end to end",
		Long: "Runs the host checks and inspects a running instance: containers, database schema, " +
			"control plane and web UI. Every failed check shows an error code; the command exits with " +
			"the first failure's category status. --explain <code> explains an error code " +
			"(see doc/setup-errors.md).",
		Example: "  qpot doctor\n  qpot doctor -i sensor1\n  qpot doctor --explain QP-PKG-001",
		// --explain needs no instance, so the root's instance check is
		// only applied without it.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("explain") {
				return nil
			}
			return checkInstanceFlag(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("explain") {
				text, err := hostsetup.Explain(explain)
				if err != nil {
					return finishCoded(cmd.ErrOrStderr(), err)
				}
				w := &termSafeWriter{w: cmd.OutOrStdout()}
				fmt.Fprint(w, text)
				w.Flush()
				return nil
			}
			return finishCoded(cmd.ErrOrStderr(), runDoctor(cmd.Context(), cmd.OutOrStdout(), instanceName))
		},
	}
	cmd.Flags().StringVarP(&instanceName, "instance", "i", "default", "instance name")
	cmd.Flags().StringVar(&explain, "explain", "", "explain an error code, e.g. QP-PKG-001")
	return cmd
}

// runDoctor runs the checks; its error carries the first failure's code.
func runDoctor(ctx context.Context, w io.Writer, instanceName string) error {
	host := doctor.HostChecks(ctx)
	hostFailed := printChecksTo(w, "Host checks", host)
	cfg, _, err := loadInstance(instanceName)
	if err != nil {
		return hostsetup.E("QP-INST-002").WithWhy("The settings of instance %q could not be read.", instanceName).Wrap(err)
	}
	mgr, err := instance.NewManager(cfg)
	if err != nil {
		return hostsetup.E("QP-INST-001").Wrap(err)
	}
	if !mgr.IsRunning(ctx) {
		cs := []check{{Name: "containers", Level: "fail", Detail: "not running (qpot up -d" + iflagFor(instanceName) + ")", Code: "QP-INST-007"}}
		printChecksTo(w, "Instance "+instanceName, cs)
		return stoppedInstanceError(instanceName, hostFailed, host, cs)
	}
	cs := healthChecks(ctx, cfg, mgr, !systemdManaged(cfg))
	printChecksTo(w, "Instance "+instanceName, cs)
	if e := doctor.Failure(host, cs); e != nil {
		return e
	}
	fmt.Fprintln(w, "\nAll checks passed.")
	return nil
}

// stoppedInstanceError is doctor's error for a stopped instance: the first
// failed check's own Why and Fix (doctor.Failure), naming the instance when
// it is the only failure.
func stoppedInstanceError(instanceName string, hostFailed bool, host, cs []check) *hostsetup.Error {
	e := doctor.Failure(host, cs)
	if !hostFailed { // the stopped instance is the only failure
		e.WithWhy("Instance %q is not running.", instanceName).WithFix("Start it with: qpot up -d%s", iflagFor(instanceName))
	}
	return e
}

// serviceName is the systemd unit name for an instance.
func serviceName(cfg *config.Config) string { return "qpot-" + cfg.InstanceName + ".service" }

// systemdManaged reports whether the instance runs as a systemd service (its
// control plane then lives in `qpot up`, not a background `qpot serve`).
func systemdManaged(cfg *config.Config) bool {
	for _, args := range [][]string{{"is-active", "--quiet"}, {"--user", "is-active", "--quiet"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := exec.CommandContext(ctx, "systemctl", append(args, serviceName(cfg))...).Run()
		cancel()
		if err == nil {
			return true
		}
	}
	return false
}

// installService writes and enables a systemd unit running `qpot up` for the
// instance: a system unit when run as root, otherwise a user unit. Errors
// are coded.
func installService(ctx context.Context, cfg *config.Config) (string, error) {
	if runtime.GOOS != "linux" {
		return "", hostsetup.E("QP-SVC-003")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "", hostsetup.E("QP-SVC-004")
	}
	// systemd must actually be PID 1 (not e.g. a container), checked before
	// anything is written.
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return "", hostsetup.E("QP-SVC-001")
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return "", hostsetup.E("QP-SVC-002").WithWhy("Setup could not find the path of the qpot program.").Wrap(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", hostsetup.E("QP-SVC-002").WithWhy("Setup could not find your home folder.").Wrap(err)
	}
	asRoot := os.Geteuid() == 0
	dir, target, sysctl := "/etc/systemd/system", "multi-user.target", []string{}
	if !asRoot {
		dir, target, sysctl = filepath.Join(home, ".config", "systemd", "user"), "default.target", []string{"--user"}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", hostsetup.E("QP-SVC-002").WithWhy("Setup could not create %s.", dir).Wrap(err)
	}
	unit := renderServiceUnit(exe, home, cfg.InstanceName, target, asRoot)
	path := filepath.Join(dir, serviceName(cfg))
	// #nosec G306 -- a systemd unit is meant to be world-readable; it holds no secrets.
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return "", hostsetup.E("QP-SVC-002").WithWhy("Setup could not write %s.", path).Wrap(err)
	}
	for _, a := range [][]string{{"daemon-reload"}, {"enable", "--now", serviceName(cfg)}} {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		c := exec.CommandContext(cctx, "systemctl", append(append([]string{}, sysctl...), a...)...)
		out, err := c.CombinedOutput()
		cancel()
		if err != nil {
			_ = os.Remove(path) // don't leave a half-installed unit behind
			if ctx.Err() != nil {
				return "", hostsetup.E("QP-INT-001")
			}
			return "", hostsetup.E("QP-SVC-002").WithDetails("systemctl %s: %v\n%s", strings.Join(append(append([]string{}, sysctl...), a...), " "), err, strings.TrimSpace(string(out)))
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
