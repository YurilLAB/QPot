// Command qpot-sshproxy is the high-interaction SSH proxy ("HiFi") broker. It is
// a transparent Layer-4 TCP splice: it forwards an attacker's connection, byte
// for byte, to a pooled backend running a REAL OpenSSH daemon, so the attacker's
// SSH handshake terminates at genuine OpenSSH and cannot be distinguished from a
// real server by protocol-level fingerprinting (Vetterl & Clayton, WOOT '18).
//
// It speaks no SSH itself (no parser to attack, no SSRF: backends come only from
// configuration), and it must run WITHOUT any host/docker privileges — the only
// genuinely dangerous component is the backend, which the orchestration layer
// isolates and egress-locks. See doc/ssh-hifi-proxy.md.
//
// Configuration is entirely via environment variables (12-factor; no file the
// attacker could influence):
//
//	QPOT_SSHPROXY_LISTEN     listen address           (default ":2222")
//	QPOT_SSHPROXY_NAME       logical honeypot name    (default "ssh-proxy")
//	QPOT_SSHPROXY_BACKENDS   REQUIRED, e.g. "be1=ssh-backend-1:22,be2=ssh-backend-2:22"
//	QPOT_SSHPROXY_LOG        NDJSON session log path  (default "/var/log/ssh-proxy/sessions.json")
//	QPOT_SSHPROXY_HOST_READABLE_LOG optional bool; generated private host storage only
//	QPOT_SSHPROXY_IDLE       idle timeout             (default "15m")
//	QPOT_SSHPROXY_MAXSESSION absolute cell life, from its first connection (default "2h")
//	QPOT_SSHPROXY_CELL_HOLD  how long a source keeps its cell after its last
//	                         connection; "0" resets after every connection (default "30m")
//	QPOT_SSHPROXY_RATE_IP    new conns/sec per IP     (default "5")
//	QPOT_SSHPROXY_BURST_IP   rate burst per IP        (default "10")
//	QPOT_SSHPROXY_CONC_IP    max concurrent per IP    (default "3")
//	QPOT_SSHPROXY_CONC       max concurrent global    (default "128")
//	QPOT_SSHPROXY_RECYCLE    wait for each used backend to be recreated by the
//	                         host before reuse: "on" (default) or "off"
//	QPOT_SSHPROXY_RECYCLE_DOWN  how long to wait for the recreation to start (default "2m")
//	QPOT_SSHPROXY_RECYCLE_UP    how long to wait for the backend to return  (default "3m")
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/qpot/qpot/internal/proxy"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("qpot-sshproxy: %v", err)
	}
}

func run() error {
	listen := env("QPOT_SSHPROXY_LISTEN", ":2222")
	name := env("QPOT_SSHPROXY_NAME", "ssh-proxy")
	backendsSpec := os.Getenv("QPOT_SSHPROXY_BACKENDS")
	logPath := env("QPOT_SSHPROXY_LOG", "/var/log/ssh-proxy/sessions.json")
	hostReadableLog, err := hostReadableSessionLogFromEnv()
	if err != nil {
		return err
	}

	backends, err := proxy.ParseBackends(backendsSpec)
	if err != nil {
		return fmt.Errorf("QPOT_SSHPROXY_BACKENDS: %w", err)
	}

	cfg := proxy.Config{
		Honeypot:        name,
		IdleTimeout:     envDuration("QPOT_SSHPROXY_IDLE", 15*time.Minute),
		MaxSession:      envDuration("QPOT_SSHPROXY_MAXSESSION", 2*time.Hour),
		CellHold:        envHold("QPOT_SSHPROXY_CELL_HOLD", 30*time.Minute),
		RatePerSecPerIP: envFloat("QPOT_SSHPROXY_RATE_IP", 5),
		BurstPerIP:      envFloat("QPOT_SSHPROXY_BURST_IP", 10),
		MaxConcurrentIP: envInt("QPOT_SSHPROXY_CONC_IP", 3),
		MaxConcurrent:   envInt("QPOT_SSHPROXY_CONC", 128),
	}

	logFile, err := openSessionLog(logPath, hostReadableLog)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	defer logFile.Close()
	cfg.Sink = proxy.NewJSONSink(logFile)

	// Backends are reset by RECREATING their container after every session -
	// done by the trusted host-side qpot process, never by this broker, which
	// must have no privilege (a docker socket in an attacker-facing container
	// would be catastrophic). The broker only waits until the recreation is
	// visible before reusing a backend, and quarantines it otherwise, so no
	// attacker ever inherits the previous attacker's changes. See
	// doc/ssh-hifi-proxy.md.
	var reset proxy.ResetFunc
	var gate *proxy.GenerationGate
	if env("QPOT_SSHPROXY_RECYCLE", "on") != "off" {
		// The host recycler records each recreation in this (read-only)
		// directory; requiring it defeats a restart staged from inside a
		// backend. Unset = reachability-only (older deployments).
		if dir := env("QPOT_SSHPROXY_GENERATIONS", ""); dir != "" {
			gate = proxy.NewGenerationGate(dir)
		} else {
			log.Printf("warning: QPOT_SSHPROXY_GENERATIONS unset - a backend restart staged by an attacker can pass as a reset")
		}
		reset = proxy.RecycleReset(proxy.RecycleOptions{
			DownWithin: envDuration("QPOT_SSHPROXY_RECYCLE_DOWN", 2*time.Minute),
			UpWithin:   envDuration("QPOT_SSHPROXY_RECYCLE_UP", 3*time.Minute),
			Gate:       gate,
		})
	} else {
		log.Printf("warning: QPOT_SSHPROXY_RECYCLE=off - backends are reused WITHOUT being reset between attackers")
	}
	pool := startupPool(backends, reset, gate)
	if gate != nil {
		cfg.Gate = gate
	}
	broker := proxy.NewBroker(cfg, pool)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	requestStartupResets(cfg.Sink, name, backends, gate)
	go pool.WatchQuarantined(ctx, 10*time.Second)

	available, _, quarantined := pool.Stats()
	log.Printf("qpot-sshproxy %q listening on %s -> %d configured backend(s); available=%d quarantined=%d; idle=%s maxSession=%s cellHold=%s",
		name, ln.Addr(), len(backends), available, quarantined, cfg.IdleTimeout, cfg.MaxSession, cfg.CellHold)
	err = broker.Serve(ctx, ln)
	if errors.Is(err, context.Canceled) {
		return nil // SIGINT/SIGTERM: a clean, drained shutdown
	}
	return err
}

func hostReadableSessionLogFromEnv() (bool, error) {
	value, present := os.LookupEnv("QPOT_SSHPROXY_HOST_READABLE_LOG")
	if !present {
		return false, nil
	}
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return false, errors.New("QPOT_SSHPROXY_HOST_READABLE_LOG: expected a boolean")
	}
	return enabled, nil
}

// openSessionLog appends without replacing existing evidence. QPot opts into
// host readability only after verifying the generated host storage has a private
// ancestor. A standalone custom log path retains its existing permissions.
func openSessionLog(name string, hostReadable bool) (*os.File, error) {
	if hostReadable && !sessionLogLinksSupported {
		return nil, errors.New("host-readable session logs require verifiable Unix file link counts")
	}
	if name == "" {
		return nil, errors.New("session log path is empty")
	}
	dir, leaf := filepath.Dir(name), filepath.Base(name)
	if !hostReadable {
		if dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("create log dir: %w", err)
			}
		}
		// #nosec G302 -- retain the standalone broker's existing group-readable
		// creation mode and trusted custom-path behavior, including /dev/stdout.
		return os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	parent, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("session log parent is not an ordinary directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	openedParent, err := root.Stat(".")
	if err != nil || !os.SameFile(parent, openedParent) {
		return nil, errors.Join(err, errors.New("session log parent changed while opening"))
	}
	before, err := root.Lstat(leaf)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if before != nil && (!before.Mode().IsRegular() || !sessionLogSingleLink(before)) {
		return nil, errors.New("session log is not a regular single-link file")
	}
	// #nosec G302 -- default group readability is retained; the explicit host
	// opt-in below is confined by QPot's separately verified private host root.
	file, err := root.OpenFile(leaf, os.O_CREATE|os.O_WRONLY|os.O_APPEND|sessionLogOpenFlags, 0o640)
	if err != nil {
		return nil, err
	}
	refuse := func(err error) (*os.File, error) { return nil, errors.Join(err, file.Close()) }
	opened, err := file.Stat()
	if err != nil {
		return refuse(err)
	}
	final, finalErr := root.Lstat(leaf)
	if finalErr != nil || !opened.Mode().IsRegular() || final == nil || !final.Mode().IsRegular() ||
		!os.SameFile(opened, final) || before != nil && !os.SameFile(before, opened) ||
		!sessionLogSingleLink(opened) || !sessionLogSingleLink(final) {
		return refuse(errors.Join(finalErr, errors.New("session log identity, type or link count changed while opening")))
	}
	// Desktop binds may already report0777 and a synthetic foreign owner.
	// Avoid an unnecessary chmod that that owner mapping cannot authorize.
	if opened.Mode().Perm()&0o004 == 0 {
		// #nosec G302 -- explicit host-reader opt-in, inside a verified private
		// host ancestor; no other host user can traverse to this metadata file.
		if err := file.Chmod(0o644); err != nil {
			return refuse(err)
		}
	}
	return file, nil
}

func startupPool(backends []proxy.Backend, reset proxy.ResetFunc, gate *proxy.GenerationGate) *proxy.Pool {
	pool := proxy.NewPool(backends, reset, proxy.PoolOptions{StartQuarantined: gate != nil})
	if gate != nil {
		// A fresh broker has forgotten which backends were dirty. Snapshot every
		// current counter while all are quarantined, then require a newer trusted
		// recreation before any first lease, even when sshd is already reachable.
		for _, backend := range backends {
			gate.OnLease(backend)
		}
		pool.SetLeaseHook(gate.OnLease)
	}
	return pool
}

func requestStartupResets(sink proxy.EventSink, name string, backends []proxy.Backend, gate *proxy.GenerationGate) {
	if gate == nil {
		return
	}
	for _, backend := range backends {
		baseline, ok := gate.BaseGeneration(backend.ID)
		if ok {
			sink.Emit(proxy.Event{EventType: proxy.EventCellReset, Honeypot: name,
				Backend: backend.ID, Generation: &baseline, Reason: proxy.ReasonStartupReset})
		}
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		log.Printf("warning: %s=%q is not a valid positive duration; using %s", key, v, def)
	}
	return def
}

// envHold reads a duration that may be zero: no hold.
func envHold(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			return d
		}
		log.Printf("warning: %s=%q is not a valid duration; using %s", key, v, def)
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
		log.Printf("warning: %s=%q is not a valid non-negative int; using %d", key, v, def)
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			return f
		}
		log.Printf("warning: %s=%q is not a valid non-negative number; using %g", key, v, def)
	}
	return def
}
