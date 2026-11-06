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
//	QPOT_SSHPROXY_IDLE       idle timeout             (default "15m")
//	QPOT_SSHPROXY_MAXSESSION absolute session cap     (default "2h")
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

	backends, err := proxy.ParseBackends(backendsSpec)
	if err != nil {
		return fmt.Errorf("QPOT_SSHPROXY_BACKENDS: %w", err)
	}

	cfg := proxy.Config{
		Honeypot:        name,
		IdleTimeout:     envDuration("QPOT_SSHPROXY_IDLE", 15*time.Minute),
		MaxSession:      envDuration("QPOT_SSHPROXY_MAXSESSION", 2*time.Hour),
		RatePerSecPerIP: envFloat("QPOT_SSHPROXY_RATE_IP", 5),
		BurstPerIP:      envFloat("QPOT_SSHPROXY_BURST_IP", 10),
		MaxConcurrentIP: envInt("QPOT_SSHPROXY_CONC_IP", 3),
		MaxConcurrent:   envInt("QPOT_SSHPROXY_CONC", 128),
	}

	// Session log. Append-only NDJSON the Vector collector ingests like any other
	// honeypot log. Created 0640 under a dir the broker owns.
	if dir := filepath.Dir(logPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create log dir: %w", err)
		}
	}
	// #nosec G302 -- session log is intentionally group-readable for the collector.
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
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
	pool := proxy.NewPool(backends, reset)
	if gate != nil {
		pool.SetLeaseHook(gate.OnLease)
	}
	broker := proxy.NewBroker(cfg, pool)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go pool.WatchQuarantined(ctx, 10*time.Second)

	log.Printf("qpot-sshproxy %q listening on %s -> %d backend(s); idle=%s maxSession=%s",
		name, listen, pool.Size(), cfg.IdleTimeout, cfg.MaxSession)
	err = broker.Serve(ctx, ln)
	if errors.Is(err, context.Canceled) {
		return nil // SIGINT/SIGTERM: a clean, drained shutdown
	}
	return err
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
