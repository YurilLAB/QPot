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
package main

import (
	"context"
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

	// NOTE: ResetFunc is deliberately nil. The broker has NO mechanism (and must
	// have no privilege) to reset backends itself — handing a docker socket to an
	// attacker-facing container would be catastrophic. Backend ephemerality is the
	// orchestration layer's job (external supervisor restarts/rolls back backends
	// between sessions). See doc/ssh-hifi-proxy.md.
	pool := proxy.NewPool(backends, nil)
	broker := proxy.NewBroker(cfg, pool)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("qpot-sshproxy %q listening on %s -> %d backend(s); idle=%s maxSession=%s",
		name, listen, pool.Size(), cfg.IdleTimeout, cfg.MaxSession)
	return broker.Serve(ctx, ln)
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
