package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/geo"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/security"
)

// setupOptions are `qpot setup`'s flags. The *Set fields record whether a
// flag was given: a given flag is an answer, so its question is not asked.
type setupOptions struct {
	instance, profile, honeypots, bind, country, database, outbound, dockerSource string
	port                                                                          int
	service, noGeoIP, yes, installDocker, dockerGroup, dryRun, noStart, verbose   bool
	timeout, lockWait                                                             time.Duration

	instanceSet, profileSet, honeypotsSet, bindSet, portSet, countrySet, geoipSet bool
	databaseSet, outboundSet, serviceSet                                          bool
}

// setupEnv is everything setup reads from or acts on, so tests can replace
// the parts that touch the real machine.
type setupEnv struct {
	stdin     io.Reader
	stdout    io.Writer
	stdinTTY  bool
	stdoutTTY bool
	goos      string
	goarch    string
	root      string
	euid      int
	user      string
	runner    hostsetup.Runner
	lookPath  func(string) (string, error)
	fetcher   *hostsetup.Fetcher
	addrs     func() []netip.Addr
	memBytes  func() int64
	freeBytes func(string) int64
	logPath   string
	tempDir   string
	// start launches the instance and returns the systemd unit when it was
	// installed as a service.
	start func(ctx context.Context, cfg *config.Config, service bool) (string, error)
	// health waits for the instance to become healthy.
	health func(ctx context.Context, cfg *config.Config, service bool, timeout time.Duration) []check
	geoip  func(ctx context.Context, cfg *config.Config) error
	// runtimes reports configured isolation before startup and observed isolation after it.
	runtimes func(ctx context.Context, cfg *config.Config, started bool) string
	// daemonWait bounds the wait for Docker to answer after starting it.
	daemonWait time.Duration
	// repoBase overrides where Docker's repositories are (tests).
	repoBase string
}

func (e *setupEnv) say(format string, a ...any) { fmt.Fprintf(e.stdout, format+"\n", a...) }

// GiB in bytes.
const gib = int64(1) << 30

// runSetup is `qpot setup`. Every error it returns is a coded
// *hostsetup.Error.
func runSetup(ctx context.Context, env *setupEnv, opts setupOptions) error {
	if err := runSetupSteps(ctx, env, opts); err != nil {
		return hostsetup.AsError(err)
	}
	return nil
}

func runSetupSteps(ctx context.Context, env *setupEnv, opts setupOptions) *hostsetup.Error {
	if err := checkSetupFlags(&opts); err != nil {
		return err
	}
	interactive := env.stdinTTY && !opts.yes && !opts.dryRun
	var ask *prompter
	if interactive {
		ask = newPrompter(ctx, env.stdin, env.stdout)
	}
	safe := &termSafeWriter{w: env.stdout}
	defer safe.Flush()

	env.say("QPot setup")
	env.say("==========")
	plat, perr := hostsetup.DetectPlatform(env.goos, env.goarch, env.root, env.euid, env.user)
	if perr != nil {
		return perr
	}
	describePlatform(env, plat)
	if !interactive && !opts.dryRun {
		env.say("Running without questions: settings come from flags and defaults.")
	}

	// 1. Settings.
	a, existing, cfg, err := settleAnswers(ctx, env, ask, opts, plat)
	if err != nil {
		return err
	}
	if a.Service {
		if err := serviceSupported(plat, env.lookPath); err != nil {
			return err
		}
	}
	if !existing && !opts.dryRun {
		if serr := saveSetupState(a); serr != nil {
			return hostsetup.E("QP-PERM-007").WithWhy("Setup could not save your answers under %s.", filepath.Dir(setupStatePath())).Wrap(serr)
		}
	}

	// 2. Docker.
	installer := &hostsetup.Installer{P: plat, R: env.runner, F: env.fetcher, LookPath: env.lookPath, Out: safe,
		TempDir: env.tempDir, Source: opts.dockerSource, LockWait: opts.lockWait, DaemonWait: env.daemonWait,
		RepoBase: env.repoBase}
	if err := ensureDocker(ctx, env, ask, opts, installer, safe); err != nil {
		return err
	}
	if opts.dryRun {
		env.say("\nDry run: nothing was changed. Run the same command without --dry-run to set up QPot.")
		return nil
	}

	// 3. Memory and disk.
	if err := checkResources(env); err != nil {
		return err
	}

	// 4. The instance.
	if !existing {
		env.say("\nCreating instance %q...", termSafe(a.Instance))
		c, _, cerr := createInstanceWith(ctx, a.Instance, func(c *config.Config) { applyAnswers(c, a) }, false)
		if cerr != nil {
			return hostsetup.AsError(cerr)
		}
		cfg = c
		clearSetupState()
		env.say("[OK] Created instance %q with honeypots: %s", termSafe(a.Instance), termSafe(strings.Join(a.Honeypots, ", ")))
	}

	// 5. GeoIP (optional: a failure is only a warning).
	geoAdded := false
	if a.GeoIP && cfg.Collector.GeoIPDBPath == "" {
		env.say("Downloading the free DB-IP country database (for countries and the attack map)...")
		if gerr := env.geoip(ctx, cfg); gerr != nil {
			if ctx.Err() != nil {
				return hostsetup.E("QP-INT-001")
			}
			e := hostsetup.AsError(gerr)
			env.say("[WARN] %s: %s Add it later with: qpot geoip update%s", "QP-NET-008",
				termSafe(hostsetup.E("QP-NET-008").Entry().Title), iflagFor(cfg.InstanceName))
			env.say("       (%s)", termSafe(firstLine(e.Details)))
		} else {
			geoAdded = true
			env.say("[OK] GeoIP database installed (%s)", geo.DBIPAttribution)
		}
	}
	if serr := config.Save(cfg); serr != nil {
		return hostsetup.E("QP-INST-002").Wrap(serr)
	}
	if geoAdded && existing {
		// A running collector reads its configuration only at start.
		if mgr, merr := instance.NewManager(cfg); merr == nil && mgr.IsRunning(ctx) {
			if rerr := mgr.ReloadCollector(ctx); rerr != nil {
				env.say("[WARN] The running log collector did not pick up the GeoIP database: %s", termSafe(firstLine(rerr.Error())))
			}
		}
	}

	// 6. Ports.
	if err := checkSetupPorts(ctx, env.stdout, cfg, a.Service); err != nil {
		return err
	}

	sum := setupSummary{Instance: cfg.InstanceName, Bind: cfg.WebUI.BindAddr, Port: cfg.WebUI.Port,
		ShowID: env.stdoutTTY, QPotID: cfg.QPotID, SSHTarget: sshTarget(env.user),
		Honeypots: summaryHoneypots(cfg), Config: cfg.ConfigPath, DataPath: cfg.DataPath,
		SetupLog: env.logPath, Sandbox: env.runtimes(ctx, cfg, false)}
	if opts.noStart {
		renderSummary(env.stdout, sum)
		return nil
	}

	// 7. Start and check.
	env.say("\nStarting QPot (the first start downloads the container images; this can take a few minutes)...")
	unit, serr := env.start(ctx, cfg, a.Service)
	if serr != nil {
		if ctx.Err() != nil {
			return hostsetup.E("QP-INT-001")
		}
		return hostsetup.AsError(serr)
	}
	sum.Started, sum.Service = true, unit
	sum.Sandbox = env.runtimes(ctx, cfg, true)
	if unit == "" {
		sum.ServeLog = filepath.Join(cfg.DataPath, "logs", "qpot-serve.log")
	}
	env.say("\nWaiting up to %s for everything to become healthy...", opts.timeout)
	cs := env.health(ctx, cfg, a.Service, opts.timeout)
	if ctx.Err() != nil {
		return hostsetup.E("QP-INT-001")
	}
	failed := printChecksTo(env.stdout, "Health", cs)
	sum.Healthy = !failed
	renderSummary(env.stdout, sum)
	if failed {
		code := "QP-INST-004"
		for _, c := range cs {
			if c.Level == "fail" && c.Code != "" {
				code = c.Code
				break
			}
		}
		i := iflagFor(cfg.InstanceName)
		if partsStopped(cs) {
			return hostsetup.E(code).WithWhy("Some parts of the instance are not running (see above), so waiting will not help.").
				WithFix("Start them with: qpot up -d%s   If they stay down: qpot down%s, then run qpot setup%s again", i, i, i)
		}
		return hostsetup.E(code).WithWhy("Some health checks failed (see above); parts may still be starting.").
			WithFix("Wait a minute and run: qpot doctor%s", i)
	}
	return nil
}

// stoppedStates are the container states a health check reports for a part
// that is not running and will not start by itself.
var stoppedStates = map[string]bool{"not created": true, "created": true, "exited": true, "dead": true, "paused": true}

// partsStopped reports whether a failed health check names a container that
// is not running (rather than one still starting or unhealthy).
func partsStopped(cs []check) bool {
	for _, c := range cs {
		if c.Level == "fail" && (c.Code == "QP-INST-005" || c.Code == "QP-INST-008") && stoppedStates[c.Detail] {
			return true
		}
	}
	return false
}

func iflagFor(name string) string {
	if name == "default" || name == "" {
		return ""
	}
	return " -i " + name
}

func sshTarget(u string) string {
	host := getLocalIP()
	if host == "127.0.0.1" {
		if h, err := os.Hostname(); err == nil && h != "" {
			host = h
		}
	}
	if u == "" || !userNameOK(u) {
		u = "<user>"
	}
	return u + "@" + host
}

func userNameOK(u string) bool {
	if len(u) == 0 || len(u) > 32 {
		return false
	}
	for _, c := range u {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func describePlatform(env *setupEnv, p hostsetup.Platform) {
	name := map[string]string{"darwin": "macOS", "windows": "Windows"}[p.GOOS]
	if p.GOOS == "linux" {
		name = p.OS.Pretty()
	}
	env.say("This computer: %s (%s)", termSafe(name), p.GOARCH)
	switch {
	case p.WSL && !p.Systemd:
		env.say("  Note: this is WSL without systemd; QPot will not start by itself after a restart.")
	case p.Container:
		env.say("  Note: this looks like a container; Docker inside containers often does not work.")
	}
	if p.GOOS == "linux" && p.EUID == 0 {
		env.say("  Running as root: the instance will belong to root (fine for a dedicated server).")
	}
}

// checkSetupFlags rejects flag values and combinations before anything runs.
func checkSetupFlags(o *setupOptions) *hostsetup.Error {
	if o.profileSet && o.honeypotsSet {
		return hostsetup.E("QP-INPUT-010").WithWhy("--profile and --honeypots both choose the honeypots.").
			WithFix("Use only one: --profile minimal|standard|hifi|industrial|refrigeration, or --honeypots name,name.")
	}
	if o.instanceSet {
		if _, err := parseInstanceAnswer(o.instance); err != nil {
			return err
		}
	}
	if o.profileSet {
		if _, ok := setupProfiles[strings.ToLower(o.profile)]; !ok {
			return hostsetup.E("QP-INPUT-002").WithWhy("%q is not a profile; use minimal, standard, hifi, industrial or refrigeration.", truncRunes(o.profile, 30))
		}
		o.profile = strings.ToLower(o.profile)
	}
	if o.honeypotsSet {
		if _, _, err := parseHoneypotsAnswer(o.honeypots); err != nil {
			return err
		}
	}
	if o.portSet {
		if _, err := parsePortAnswer(strconv.Itoa(o.port)); err != nil {
			return err
		}
	}
	if o.countrySet {
		if _, err := parseCountryAnswer(o.country); err != nil {
			return err
		}
	}
	if o.databaseSet {
		if _, err := parseDatabaseAnswer(o.database); err != nil {
			return err
		}
	}
	if o.outboundSet {
		if _, err := parseOutboundAnswer(o.outbound); err != nil {
			return err
		}
	}
	src, err := parseDockerSource(firstNonEmptyStr(o.dockerSource, "auto"))
	if err != nil {
		return err
	}
	o.dockerSource = src
	if o.timeout <= 0 {
		o.timeout = 4 * time.Minute
	}
	if o.lockWait <= 0 {
		o.lockWait = 2 * time.Minute
	}
	return nil
}

func firstNonEmptyStr(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func serviceSupported(p hostsetup.Platform, lookPath func(string) (string, error)) *hostsetup.Error {
	if p.GOOS != "linux" {
		return hostsetup.E("QP-SVC-003")
	}
	if _, err := lookPath("systemctl"); err != nil {
		return hostsetup.E("QP-SVC-004")
	}
	if !p.Systemd {
		return hostsetup.E("QP-SVC-001").WithWhy("--service installs a systemd service, but systemd is not running on this system.")
	}
	return nil
}

// settleAnswers decides the instance and its settings: an existing instance
// keeps its own; a new one gets answers from questions, flags and defaults.
func settleAnswers(ctx context.Context, env *setupEnv, ask *prompter, o setupOptions, plat hostsetup.Platform) (setupAnswers, bool, *config.Config, *hostsetup.Error) {
	a := defaultAnswers()
	saved, haveSaved := setupAnswers{}, false
	if ask != nil && !o.instanceSet {
		saved, haveSaved = loadSetupState()
	}
	usedSaved := false
	if haveSaved {
		env.say("\nLast time setup stopped before it finished. Your answers then were:")
		printAnswers(env, saved)
		use, err := ask.confirm("Use these answers again?", true)
		if err != nil {
			return a, false, nil, err
		}
		if use {
			a, usedSaved = saved, true
			o.instanceSet = true
			o.instance = saved.Instance
		}
	}

	// The instance name comes first: an existing instance is used as it is.
	switch {
	case o.instanceSet:
		a.Instance = o.instance
	case ask != nil:
		env.say("\nAn instance is one QPot deployment with its own honeypots, settings and web UI.")
		name, err := ask.ask("Instance name", a.Instance, func(s string) *hostsetup.Error { _, e := parseInstanceAnswer(s); return e })
		if err != nil {
			return a, false, nil, err
		}
		a.Instance = name
	}
	if _, err := os.Stat(config.Default(a.Instance).ConfigPath); err == nil {
		cfg, _, lerr := loadInstance(a.Instance)
		if lerr != nil {
			return a, true, nil, hostsetup.E("QP-INST-002").WithWhy("The settings of instance %q could not be read.", a.Instance).Wrap(lerr)
		}
		a.Honeypots = sortedCopy(cfg.GetEnabledHoneypots())
		a.Bind, a.Port, a.Database = cfg.WebUI.BindAddr, cfg.WebUI.Port, cfg.Database.Type
		a.GeoIP = !o.noGeoIP
		a.Service = o.serviceSet && o.service
		env.say("\nInstance %q already exists; its settings are kept.", termSafe(a.Instance))
		env.say("  Honeypots: %s", termSafe(strings.Join(a.Honeypots, ", ")))
		env.say("  Web UI:    %s", termSafe(net.JoinHostPort(a.Bind, strconv.Itoa(a.Port))))
		env.say("  Change them with: qpot config%s   (or qpot honeypot enable/disable)", iflagFor(a.Instance))
		if o.profileSet || o.honeypotsSet || o.bindSet || o.portSet || o.databaseSet || o.outboundSet {
			env.say("  Note: --profile, --honeypots, --bind, --port, --database and --outbound only apply to a new instance.")
		}
		if err := setMapCountry(cfg, o.country); err != nil {
			return a, true, nil, hostsetup.E("QP-INPUT-006").Wrap(err)
		}
		return a, true, cfg, nil
	}

	// Flags are answers.
	if o.profileSet {
		a.Profile, a.Honeypots = o.profile, append([]string(nil), setupProfiles[o.profile]...)
	}
	if o.honeypotsSet {
		a.Profile, a.Honeypots, _ = parseHoneypotsAnswer(o.honeypots)
	}
	if o.bindSet {
		b, exp, err := parseBindAnswer(o.bind, env.addrs())
		if err != nil {
			return a, false, nil, err
		}
		a.Bind = b
		if exp != bindLocal {
			env.say("[WARN] The web UI will listen on %s: anyone who can reach this computer on that address can try to log in, over plain HTTP.", termSafe(b))
		}
	}
	if o.portSet {
		a.Port = o.port
	}
	if o.countrySet {
		a.Country, _ = parseCountryAnswer(o.country)
	}
	if o.geoipSet {
		a.GeoIP = !o.noGeoIP
	}
	if o.databaseSet {
		a.Database, _ = parseDatabaseAnswer(o.database)
	}
	if o.outboundSet {
		a.Outbound, _ = parseOutboundAnswer(o.outbound)
	}
	if o.serviceSet {
		a.Service = o.service
	}

	if ask != nil && !usedSaved {
		if err := askSettings(env, ask, &a, o, plat); err != nil {
			return a, false, nil, err
		}
	}
	// Whatever the answers, the web UI port must be usable.
	if err := settleWebPort(env, ask, &a, o.portSet || usedSaved); err != nil {
		return a, false, nil, err
	}
	if ask != nil {
		env.say("\nSetup will create instance %q with these settings:", termSafe(a.Instance))
		printAnswers(env, a)
		ok, err := ask.confirm("Go ahead?", true)
		if err != nil {
			return a, false, nil, err
		}
		if !ok {
			return a, false, nil, hostsetup.E("QP-INPUT-013")
		}
	} else {
		env.say("\nNew instance %q:", termSafe(a.Instance))
		printAnswers(env, a)
	}
	return a, false, nil, nil
}

func printAnswers(env *setupEnv, a setupAnswers) {
	country := a.Country
	if country == "" {
		country = "from the time zone"
	}
	if c, ok := geo.Lookup(a.Country); ok {
		country = c.Code
	}
	outbound := "allowed to the internet (your own network is always blocked)"
	if a.Outbound == "block" {
		outbound = "blocked"
	}
	env.say("  Instance:          %s", termSafe(a.Instance))
	env.say("  Honeypots:         %s (%s)", termSafe(strings.Join(a.Honeypots, ", ")), termSafe(a.Profile))
	if a.Profile == "industrial" {
		env.say("  Industrial device: Schneider Modicon M340 (plc_modbus); Modbus/TCP, container port 502")
		env.say("  Device ports:      host ports are allocated; qpot honeypot list shows the mappings")
	}
	if a.Profile == "refrigeration" {
		env.say("  Refrigeration:     legacy supervisor with simulated retail cold storage")
		env.say("  Image:             built locally from bundled Go source; first start needs the build image")
		env.say("  Device ports:      host ports are allocated; qpot honeypot list shows the mappings")
	}
	env.say("  Web UI address:    %s", termSafe(net.JoinHostPort(a.Bind, strconv.Itoa(a.Port))))
	env.say("  Database:          %s", termSafe(a.Database))
	env.say("  Honeypot outbound: %s", outbound)
	env.say("  Attack map place:  %s", termSafe(country))
	env.say("  Country database:  %s", yesNo(a.GeoIP))
	env.say("  Start at boot:     %s", yesNo(a.Service))
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// askSettings asks the questions for a new instance, skipping those a flag
// already answered.
func askSettings(env *setupEnv, ask *prompter, a *setupAnswers, o setupOptions, plat hostsetup.Platform) *hostsetup.Error {
	env.say("\nRecommended settings:")
	printAnswers(env, *a)
	rec, err := ask.confirm("Use the recommended settings?", true)
	if err != nil {
		return err
	}
	if rec {
		return nil
	}
	if !o.profileSet && !o.honeypotsSet {
		env.say("")
		pick, err := ask.choose("Which honeypots should run?", []choice{
			{"minimal", "SSH/Telnet (cowrie) and an SSH tarpit (endlessh): low risk, a good start"},
			{"standard", "minimal + dionaea, heralding, conpot, adbhoney: more services, more traffic"},
			{"hifi", "minimal + real OpenSSH servers behind a broker: high interaction, highest risk"},
			{"industrial", "Industrial control systems: one Schneider Modicon M340 PLC (Modbus/TCP)"},
			{"refrigeration", "Refrigeration supervisor: virtual cold storage, web management and XML control"},
			{"custom", "choose honeypots by name"},
		}, a.Profile)
		if err != nil {
			return err
		}
		if pick == "custom" {
			env.say("Honeypots: %s", strings.Join(knownHoneypots(), ", "))
			var prof string
			var hps []string
			_, err := ask.ask("Honeypot names, separated by commas", strings.Join(a.Honeypots, ","), func(s string) *hostsetup.Error {
				var e *hostsetup.Error
				prof, hps, e = parseHoneypotsAnswer(s)
				return e
			})
			if err != nil {
				return err
			}
			a.Profile, a.Honeypots = prof, hps
		} else {
			a.Profile, a.Honeypots = pick, append([]string(nil), setupProfiles[pick]...)
		}
		for _, h := range a.Honeypots {
			if hp, ok := config.Default("x").Honeypots[h]; ok && (hp.RiskLevel == "high" || hp.RiskLevel == "critical") {
				env.say("  Note: %s is %s risk: it lets attackers interact more deeply. Watch it closely.", h, hp.RiskLevel)
			}
			if len(instance.LLMConfigKeys(h)) > 0 {
				env.say("  Note: %s needs an AI model provider; set it later with: qpot honeypot set %s ...", h, h)
			}
		}
	}
	if !o.bindSet {
		env.say("\nThe web UI is safest on 127.0.0.1 (this computer only; use an SSH tunnel from elsewhere).")
		for {
			var exp bindExposure
			b, err := ask.ask("Web UI address", a.Bind, func(s string) *hostsetup.Error {
				var e *hostsetup.Error
				_, exp, e = parseBindAnswer(s, env.addrs())
				return e
			})
			if err != nil {
				return err
			}
			b, _, _ = parseBindAnswer(b, env.addrs())
			if exp == bindLocal {
				a.Bind = b
				break
			}
			env.say("  Warning: on %s the web UI is reachable from the network over plain HTTP (not", termSafe(b))
			env.say("  encrypted). Anyone who can reach it can try to log in, and your QPot ID crosses")
			env.say("  the network readable to anyone watching. An SSH tunnel is safer.")
			sure, err := ask.confirm("Listen on "+b+" anyway?", false)
			if err != nil {
				return err
			}
			if sure {
				a.Bind = b
				break
			}
		}
	}
	if !o.portSet {
		port, err := ask.ask("Web UI port", strconv.Itoa(a.Port), func(s string) *hostsetup.Error {
			p, e := parsePortAnswer(s)
			if e != nil {
				return e
			}
			return webPortUsable(a.Bind, p, a.Instance, env.euid)
		})
		if err != nil {
			return err
		}
		a.Port, _ = parsePortAnswer(port)
	}
	if !o.databaseSet {
		env.say("")
		db, err := ask.choose("Where should events be stored?", []choice{
			{"clickhouse", "ClickHouse: fast, the default"},
			{"timescaledb", "TimescaleDB (PostgreSQL)"},
		}, a.Database)
		if err != nil {
			return err
		}
		a.Database = db
	}
	if !o.outboundSet {
		env.say("")
		ob, err := ask.choose("May honeypots open connections to the internet? (Your own network is always blocked.)", []choice{
			{"allow", "yes: lets cowrie and others capture the malware attackers download"},
			{"block", "no: nothing leaves the honeypots (safest, captures less)"},
		}, a.Outbound)
		if err != nil {
			return err
		}
		a.Outbound = ob
	}
	if !o.countrySet {
		def := ""
		if c, ok := geo.HostCountry(); ok {
			def = c.Code
		}
		env.say("")
		cc, err := ask.ask("Two-letter country of this sensor, for the attack map (Enter for the time zone's)", def, func(s string) *hostsetup.Error {
			_, e := parseCountryAnswer(s)
			return e
		})
		if err != nil {
			return err
		}
		a.Country, _ = parseCountryAnswer(cc)
	}
	if !o.geoipSet {
		g, err := ask.confirm("Download the free DB-IP country database (about 4 MB, so events show a country)?", a.GeoIP)
		if err != nil {
			return err
		}
		a.GeoIP = g
	}
	if !o.serviceSet && plat.GOOS == "linux" && plat.Systemd {
		s, err := ask.confirm("Start QPot automatically when the computer starts (systemd service)?", a.Service)
		if err != nil {
			return err
		}
		a.Service = s
	}
	return nil
}

// webPortUsable checks a web UI port: allowed for this user, free, and not
// configured by another instance.
func webPortUsable(bind string, port int, instanceName string, euid int) *hostsetup.Error {
	if port < 1024 && euid != 0 && runtime.GOOS == "linux" {
		return hostsetup.E("QP-PORT-004").WithWhy("Port %d is below 1024, which only root may use.", port)
	}
	cfg := config.Default(instanceName)
	cfg.WebUI.BindAddr, cfg.WebUI.Port = bind, port
	if p, ok := freeWebPort(cfg); !ok || p != port {
		e := hostsetup.E("QP-PORT-001").WithWhy("Port %d is already in use on %s (by another program or QPot instance).", port, bind)
		if ok {
			e.WithFix("Choose another port, for example --port %d (free right now), or stop the program that uses port %d.", p, port)
		}
		return e
	}
	return nil
}

// settleWebPort makes sure the chosen web UI port is usable. A port the
// owner chose that is taken is an error (or asked again); the default moves
// to the next free port.
func settleWebPort(env *setupEnv, ask *prompter, a *setupAnswers, chosen bool) *hostsetup.Error {
	err := webPortUsable(a.Bind, a.Port, a.Instance, env.euid)
	if err == nil {
		return nil
	}
	if !chosen || err.Code != "QP-PORT-001" {
		cfg := config.Default(a.Instance)
		cfg.WebUI.BindAddr, cfg.WebUI.Port = a.Bind, a.Port
		if p, ok := freeWebPort(cfg); ok && err.Code == "QP-PORT-001" {
			env.say("[INFO] Web UI port %d is in use; using %d instead.", a.Port, p)
			a.Port = p
			return nil
		}
		if err.Code == "QP-PORT-001" {
			return hostsetup.E("QP-PORT-003").WithWhy("Port %d and the 100 ports after it are all in use.", a.Port)
		}
	}
	if ask == nil {
		return err
	}
	env.say("  %s", termSafe(err.Cause()))
	port, aerr := ask.ask("Web UI port", "", func(s string) *hostsetup.Error {
		p, e := parsePortAnswer(s)
		if e != nil {
			return e
		}
		return webPortUsable(a.Bind, p, a.Instance, env.euid)
	})
	if aerr != nil {
		return aerr
	}
	a.Port, _ = parsePortAnswer(port)
	return nil
}

// ensureDocker detects Docker and, with consent, installs, updates or starts
// it and gives the user access to it.
func ensureDocker(ctx context.Context, env *setupEnv, ask *prompter, o setupOptions, in *hostsetup.Installer, safe *termSafeWriter) *hostsetup.Error {
	env.say("\nChecking Docker...")
	st := hostsetup.DetectDocker(ctx, env.runner, env.lookPath)
	reportDocker(env, st)
	need := hostsetup.NeedFor(st)
	if need.Any() {
		plan, err := in.Plan(ctx, need)
		if err != nil {
			return err
		}
		env.say("")
		in.Describe(safe, plan)
		safe.Flush()
		if o.dryRun {
			if !o.installDocker {
				env.say("\n(To let setup run these, use --install-docker or answer yes in a terminal.)")
			}
			return nil
		}
		if err := consent(ask, o.installDocker, plan, need); err != nil {
			return err
		}
		if plan.Root {
			if err := in.EnsureRoot(ctx, ask != nil); err != nil {
				return err
			}
		}
		env.say("")
		if err := in.Execute(ctx, plan); err != nil {
			return err
		}
		safe.Flush()
		st = hostsetup.DetectDocker(ctx, env.runner, env.lookPath)
		if err := verifyDocker(st); err != nil {
			return err
		}
		if st.PermissionDenied {
			env.say("[OK] Docker is installed and running (Compose %s)", st.ComposeVersion)
		} else {
			env.say("[OK] Docker is ready (engine %s, Compose %s)", st.Server, st.ComposeVersion)
		}
	}
	if st.PermissionDenied && in.P.GOOS == "linux" && in.P.EUID != 0 {
		return grantDockerAccess(ctx, env, ask, o, in, safe)
	}
	return nil
}

func reportDocker(env *setupEnv, st hostsetup.DockerState) {
	switch {
	case !st.CLI:
		env.say("  Docker:  not installed")
	case st.Podman:
		env.say("  Docker:  the docker command is Podman, which QPot does not support")
	case st.PermissionDenied:
		env.say("  Docker:  running, but your user may not use it yet")
	case st.DaemonUp:
		env.say("  Docker:  running, engine %s", st.Server)
	default:
		env.say("  Docker:  installed (%s) but not running", st.Client)
	}
	switch {
	case st.Podman || !st.CLI:
	case st.Compose:
		env.say("  Compose: %s", st.ComposeVersion)
	case st.ComposeV1:
		env.say("  Compose: only the old docker-compose version 1 (QPot needs version 2)")
	default:
		env.say("  Compose: not installed")
	}
}

// consent asks before running a plan, or checks the flag that allows it.
func consent(ask *prompter, flag bool, plan *hostsetup.Plan, need hostsetup.Need) *hostsetup.Error {
	if ask == nil {
		if flag && plan.Desktop && (need.Engine || need.Upgrade) {
			// winget and Homebrew show agreements only a person may accept.
			return hostsetup.E("QP-INPUT-008").WithWhy("Installing Docker Desktop shows agreements that you must answer yourself, and there is no terminal to answer them in.").
				WithFix("Run qpot setup in a terminal, or install Docker Desktop yourself from https://docs.docker.com/desktop/ and run qpot setup again.")
		}
		if flag {
			return nil
		}
		code := "QP-DOCKER-002"
		switch {
		case need.Engine:
			code = "QP-DOCKER-001"
		case need.Upgrade:
			code = "QP-DOCKER-005"
		case need.Compose:
			code = "QP-COMPOSE-001"
		}
		return hostsetup.E(code).WithWhy("Setup is running without questions, so it only changes the system when a flag allows it.").
			WithFix("Run qpot setup again with --install-docker to let it run the commands shown above, or run them yourself.")
	}
	q := "Run these commands now?"
	if plan.Desktop {
		q = "Go ahead (you accept or decline Docker Desktop's terms yourself when it opens)?"
	}
	ok, err := ask.confirm(q, true)
	if err != nil {
		return err
	}
	if !ok {
		return hostsetup.E("QP-PERM-006")
	}
	return nil
}

func verifyDocker(st hostsetup.DockerState) *hostsetup.Error {
	switch {
	case !st.CLI:
		return hostsetup.E("QP-DOCKER-006")
	case st.Podman:
		return hostsetup.E("QP-DOCKER-004")
	case !st.DaemonUp:
		return hostsetup.E("QP-DOCKER-002").WithDetails("%s", st.DaemonDetail)
	case st.EngineOld():
		return hostsetup.E("QP-DOCKER-005").WithWhy("Docker %s is installed; QPot needs %s or newer.", st.Server, hostsetup.MinEngine)
	case st.ComposeMissing():
		return hostsetup.E("QP-COMPOSE-003").WithDetails("%s", st.ComposeDetail)
	}
	return nil
}

// grantDockerAccess adds the user to the docker group, with consent. The
// group only applies to new logins, so setup stops afterwards and says how
// to continue.
func grantDockerAccess(ctx context.Context, env *setupEnv, ask *prompter, o setupOptions, in *hostsetup.Installer, safe *termSafeWriter) *hostsetup.Error {
	plan, err := in.GroupPlan()
	if err != nil {
		return err
	}
	env.say("")
	env.say("Your user (%s) may not use Docker yet. Setup can add it to the 'docker' group.", termSafe(in.P.User))
	env.say("Important: members of the docker group can control Docker, which is the same as")
	env.say("having full root access to this computer. Only agree if this is your own machine.")
	env.say("(The alternative is to run QPot as root, for example: sudo qpot setup)")
	env.say("")
	in.Describe(safe, plan)
	safe.Flush()
	if ask == nil {
		if !o.dockerGroup {
			return hostsetup.E("QP-PERM-004").WithFix("Run qpot setup again with --docker-group to allow it, or run QPot as root.")
		}
	} else {
		ok, aerr := ask.confirm("Add "+in.P.User+" to the docker group?", false)
		if aerr != nil {
			return aerr
		}
		if !ok {
			return hostsetup.E("QP-PERM-004").WithWhy("You chose not to join the docker group, so your user cannot use Docker.").
				WithFix("Run QPot as root (sudo qpot setup), or run qpot setup again and agree.")
		}
	}
	if err := in.EnsureRoot(ctx, ask != nil); err != nil {
		return err
	}
	if err := in.Execute(ctx, plan); err != nil {
		return err
	}
	return hostsetup.E("QP-PERM-005")
}

// checkResources stops on too little memory or disk and warns when low.
func checkResources(env *setupEnv) *hostsetup.Error {
	env.say("\nChecking memory and disk space...")
	if mem := env.memBytes(); mem > 0 {
		g := float64(mem) / float64(gib)
		switch {
		case mem < gib:
			return hostsetup.E("QP-RES-001").WithWhy("This computer has %.1f GiB of memory; QPot needs at least 1 GiB.", g)
		case mem < 2*gib:
			env.say("  [WARN] %.1f GiB of memory: QPot will run, but 2 GiB or more is recommended.", g)
		default:
			env.say("  [OK] %.1f GiB of memory", g)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		if free := env.freeBytes(home); free > 0 {
			g := float64(free) / float64(gib)
			switch {
			case free < 2*gib:
				return hostsetup.E("QP-RES-002").WithWhy("Only %.1f GiB is free in %s; QPot needs at least 2 GiB there.", g, home)
			case free < 5*gib:
				env.say("  [WARN] %.1f GiB free in %s (5 GiB or more is recommended)", g, termSafe(home))
			default:
				env.say("  [OK] %.1f GiB free in %s", g, termSafe(home))
			}
		}
	}
	root := dockerRootDir(env)
	if free := env.freeBytes(root); free > 0 {
		g := float64(free) / float64(gib)
		switch {
		case free < 3*gib:
			return hostsetup.E("QP-RES-003").WithWhy("Only %.1f GiB is free in %s, where Docker keeps images; QPot needs at least 3 GiB.", g, root)
		case free < 10*gib:
			env.say("  [WARN] %.1f GiB free for Docker images in %s (10 GiB or more is recommended)", g, termSafe(root))
		default:
			env.say("  [OK] %.1f GiB free for Docker images", g)
		}
	}
	return nil
}

func dockerRootDir(env *setupEnv) string {
	res := env.runner.Run(context.Background(), hostsetup.Command{Args: []string{"docker", "info", "--format", "{{.DockerRootDir}}"}, Timeout: 20 * time.Second})
	if d := strings.TrimSpace(string(res.Stdout)); res.OK() && filepath.IsAbs(d) {
		return d
	}
	if env.goos == "linux" {
		return "/var/lib/docker"
	}
	return ""
}

// checkSetupPorts checks the honeypots' host ports and the web UI port.
func checkSetupPorts(ctx context.Context, w io.Writer, cfg *config.Config, service bool) *hostsetup.Error {
	mgr, err := instance.NewManager(cfg)
	if err != nil {
		return hostsetup.E("QP-INST-001").Wrap(err)
	}
	var pcs []check
	if !mgr.IsRunning(ctx) {
		pcs = portChecks(cfg)
	}
	if cfg.WebUI.Enabled && !service && runningServePID(cfg) == 0 {
		if werr := webPortFree(cfg); werr != nil {
			pcs = append(pcs, check{Name: "web UI port", Level: "fail", Detail: werr.Error(), Code: "QP-PORT-001"})
		} else {
			pcs = append(pcs, check{Name: "web UI port", Level: "ok", Detail: fmt.Sprintf("%d free", cfg.WebUI.Port)})
		}
	}
	for key, hostPort := range instance.PublishedHostPorts(cfg) {
		if hostPort == cfg.WebUI.Port {
			name, _, _ := strings.Cut(key, "\x00")
			return hostsetup.E("QP-PORT-005").WithWhy("Honeypot %s is set to use port %d, which the web UI uses too.", name, hostPort).
				WithFix("Change the web UI port: qpot config%s (web_ui.port), then run qpot setup%[1]s again.", iflagFor(cfg.InstanceName))
		}
	}
	if len(pcs) > 0 && printChecksTo(w, "Port checks", pcs) {
		for _, c := range pcs {
			if c.Level == "fail" {
				return hostsetup.E(c.Code).WithDetails("%s", c.Detail)
			}
		}
	}
	return nil
}

// realStart starts the instance the way setup always has: a systemd service,
// or the containers plus a background control plane.
func realStart(ctx context.Context, cfg *config.Config, service bool) (string, error) {
	mgr, err := instance.NewManager(cfg)
	if err != nil {
		return "", hostsetup.E("QP-INST-001").Wrap(err)
	}
	if service {
		unit, serr := installService(ctx, cfg)
		if serr != nil {
			return "", serr
		}
		return unit, nil
	}
	// AllRunning, not IsRunning: after an unclean stop docker brings back
	// only some containers (the collector), and attaching to those left the
	// database and the honeypots down. compose up -d starts what is missing
	// and leaves the running ones alone.
	if !mgr.AllRunning(ctx) {
		if err := mgr.Start(ctx, true); err != nil {
			return "", hostsetup.E("QP-INST-003").Wrap(err)
		}
	}
	if _, logPath, err := backgroundServe(cfg); err != nil {
		return "", hostsetup.E("QP-WEB-001").WithDetails("%v\nlog: %s", err, logPath)
	}
	return "", nil
}

func realHealth(ctx context.Context, cfg *config.Config, service bool, timeout time.Duration) []check {
	mgr, err := instance.NewManager(cfg)
	if err != nil {
		return []check{{Name: "containers", Level: "fail", Detail: err.Error(), Code: "QP-INST-001"}}
	}
	return waitHealthy(ctx, cfg, mgr, !service, timeout)
}

// realRuntimes distinguishes requested isolation from the runtime observed on
// this instance's containers. Daemon registration alone proves neither.
func realRuntimes(inspect func(context.Context, *config.Config) (instance.SandboxStatus, error)) func(context.Context, *config.Config, bool) string {
	return func(ctx context.Context, cfg *config.Config, started bool) string {
		if cfg == nil {
			return "isolation not verified (QP-INST-002)"
		}
		sandbox, err := security.NewSandbox(&cfg.Security)
		if err != nil {
			return sandboxSummaryError(err)
		}
		selected, err := sandbox.Selection()
		if err != nil {
			return sandboxSummaryError(err)
		}
		requested := sandboxRuntimeDescription(selected.Runtime)
		if selected.Runtime == "" {
			requested = "Docker default runtime"
		}
		if !started || inspect == nil {
			return "configured " + requested + "; container runtime not yet verified"
		}
		observed, err := inspect(ctx, cfg)
		if err != nil {
			detail := sandboxSummaryError(err)
			runtimes := observedSandboxRuntimes(observed)
			if len(runtimes) > 0 {
				for index, value := range runtimes {
					runtimes[index] = strconv.Quote(value)
				}
				detail += "; observed container runtimes: " + strings.Join(runtimes, ", ")
			}
			return detail
		}
		runtimes := observedSandboxRuntimes(observed)
		if !observed.Verified || observed.Runtime == "" || len(observed.Services) == 0 || len(runtimes) == 0 {
			return "configured " + requested + "; no running honeypot runtime verified"
		}
		actual := sandboxRuntimeDescription(observed.Runtime)
		if len(runtimes) > 1 {
			labels := make([]string, 0, len(runtimes))
			for _, runtime := range runtimes {
				labels = append(labels, sandboxRuntimeDescription(runtime))
			}
			actual = "mixed container runtimes: " + strings.Join(labels, ", ")
		}
		if observed.Fallback {
			return actual + " (explicit Docker fallback; requested " + requested + ")"
		}
		return actual + " (verified on honeypot containers)"
	}
}

func observedSandboxRuntimes(observed instance.SandboxStatus) []string {
	seen := make(map[string]bool)
	for _, runtime := range observed.Services {
		if runtime != "" {
			seen[runtime] = true
		}
	}
	values := make([]string, 0, len(seen))
	for runtime := range seen {
		values = append(values, runtime)
	}
	sort.Strings(values)
	return values
}

func sandboxRuntimeDescription(runtime string) string {
	switch runtime {
	case "runsc":
		return "gVisor (runsc)"
	case "kata-runtime":
		return "Kata Containers (kata-runtime)"
	case "", "runc", "io.containerd.runc.v2":
		return "standard Docker containers (" + runtime + ")"
	default:
		return fmt.Sprintf("Docker runtime %q", runtime)
	}
}

func sandboxSummaryError(err error) string {
	coded := hostsetup.AsError(err)
	return "isolation not verified: " + coded.Entry().Title + " (" + coded.Code + ")"
}

// newSetupEnv builds the environment for a real run. Without a private
// temporary folder it stops: files that root installs are written there
// first, and anywhere else (the current folder, a shared one) another user
// could swap them before root installs them.
func newSetupEnv(cmd interface {
	InOrStdin() io.Reader
	OutOrStdout() io.Writer
}, verbose bool) (*setupEnv, func(), *hostsetup.Error) {
	tmp, terr := os.MkdirTemp("", "qpot-setup-")
	if terr != nil {
		return nil, nil, hostsetup.E("QP-PERM-010").WithWhy("Setup could not make a private folder in %s.", os.TempDir()).Wrap(terr)
	}
	if perr := hostsetup.CheckPrivateDir(tmp); perr != nil {
		_ = os.RemoveAll(tmp)
		return nil, nil, perr
	}
	u := ""
	if cu, err := user.Current(); err == nil {
		u = cu.Username
		if i := strings.LastIndexAny(u, `\`); i >= 0 { // Windows DOMAIN\name
			u = u[i+1:]
		}
	}
	env := &setupEnv{
		stdin: cmd.InOrStdin(), stdout: cmd.OutOrStdout(),
		stdinTTY: isTerminal(os.Stdin), stdoutTTY: isTerminal(os.Stdout),
		goos: runtime.GOOS, goarch: runtime.GOARCH, root: "/", euid: geteuid(), user: u,
		lookPath: exec.LookPath, addrs: localAddrs, memBytes: totalMemoryBytes,
		freeBytes: hostsetup.FreeBytes, geoip: provisionGeoIP, start: realStart, health: realHealth,
	}
	env.tempDir = tmp
	cleanup := []func(){func() { _ = os.RemoveAll(tmp) }}
	var logW io.Writer
	if home, err := os.UserHomeDir(); err == nil {
		dir := filepath.Join(home, ".qpot", "logs")
		if os.MkdirAll(dir, 0o750) == nil {
			p := filepath.Join(dir, "setup.log")
			if f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil { // #nosec G304 -- fixed path under the home directory
				fmt.Fprintf(f, "\n===== qpot setup %s =====\n", time.Now().Format(time.RFC3339))
				env.logPath, logW = p, f
				old := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(f, nil)))
				cleanup = append(cleanup, func() { slog.SetDefault(old); _ = f.Close() })
			}
		}
	}
	// The summary reports configured and observed isolation. Explicit fallback
	// warnings also stay in the setup log.
	warnTo := io.Discard
	if logW != nil {
		warnTo = logW
	}
	prevWarn := security.SetWarningOutput(warnTo)
	cleanup = append(cleanup, func() { security.SetWarningOutput(prevWarn) })
	sudo, _ := exec.LookPath("sudo")
	r := &hostsetup.ExecRunner{EUID: env.euid, Sudo: sudo, NoTTY: !env.stdinTTY, Log: logW,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	if verbose {
		r.Stream = &termSafeWriter{w: env.stdout}
	}
	env.runner = r
	env.runtimes = realRuntimes(func(ctx context.Context, cfg *config.Config) (instance.SandboxStatus, error) {
		manager, err := instance.NewManager(cfg)
		if err != nil {
			return instance.SandboxStatus{}, err
		}
		return manager.SandboxStatus(ctx)
	})
	env.fetcher = &hostsetup.Fetcher{Root: "/", GOOS: runtime.GOOS}
	return env, func() {
		for i := len(cleanup) - 1; i >= 0; i-- {
			cleanup[i]()
		}
	}, nil
}
