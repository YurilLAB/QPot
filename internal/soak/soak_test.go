//go:build unix

package soak

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"golang.org/x/crypto/ssh"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// options are the run's settings, all from the environment.
type options struct {
	bin       string        // QPOT_SOAK_BIN: the qpot binary under test
	instance  string        // QPOT_SOAK_INSTANCE: a name no instance has yet
	duration  time.Duration // QPOT_SOAK_DURATION: how long faults are injected
	rate      float64       // QPOT_SOAK_RATE: connections per second
	gap       time.Duration // QPOT_SOAK_GAP: quiet time between faults
	hold      time.Duration // QPOT_SOAK_HOLD: how long a fault lasts
	reportDir string        // QPOT_SOAK_REPORT: where the report is written
	fillDir   string        // QPOT_SOAK_FILL_DIR: a small filesystem holding the instance, to fill
	sandbox   string        // QPOT_SOAK_SANDBOX: security.sandbox_mode for the instance
	faults    []string      // QPOT_SOAK_FAULTS: names, in order; empty means all
	keep      bool          // QPOT_SOAK_KEEP: leave the instance for inspection
}

func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func loadOptions(t *testing.T) options {
	t.Helper()
	if os.Getenv("QPOT_SOAK") != "1" {
		t.Skip("set QPOT_SOAK=1 (and QPOT_SOAK_BIN) to run the failure soak on real Docker; see doc/reliability.md")
	}
	dur := func(name, fallback string) time.Duration {
		d, err := time.ParseDuration(env(name, fallback))
		if err != nil || d <= 0 {
			t.Fatalf("%s: %q is not a duration", name, os.Getenv(name))
		}
		return d
	}
	rate, err := strconv.ParseFloat(env("QPOT_SOAK_RATE", "4"), 64)
	if err != nil || rate <= 0 || rate > 200 {
		t.Fatalf("QPOT_SOAK_RATE: %q is not a rate between 0 and 200", os.Getenv("QPOT_SOAK_RATE"))
	}
	o := options{
		bin:       os.Getenv("QPOT_SOAK_BIN"),
		instance:  env("QPOT_SOAK_INSTANCE", "soak"),
		duration:  dur("QPOT_SOAK_DURATION", "20m"),
		rate:      rate,
		gap:       dur("QPOT_SOAK_GAP", "3m"),
		hold:      dur("QPOT_SOAK_HOLD", "2m"),
		reportDir: env("QPOT_SOAK_REPORT", t.TempDir()),
		fillDir:   os.Getenv("QPOT_SOAK_FILL_DIR"),
		sandbox:   os.Getenv("QPOT_SOAK_SANDBOX"),
		keep:      os.Getenv("QPOT_SOAK_KEEP") == "1",
	}
	if o.bin == "" {
		t.Fatal("QPOT_SOAK_BIN must name the qpot binary to test")
	}
	if f := strings.TrimSpace(os.Getenv("QPOT_SOAK_FAULTS")); f != "" {
		o.faults = strings.Split(f, ",")
	}
	return o
}

// connection is one banner connection the load made.
type connection struct {
	N        int       `json:"n"`
	Sent     time.Time `json:"sent"`
	Accepted bool      `json:"accepted"` // the honeypot sent its banner and took ours
}

// session is one real SSH login that ran commands.
type session struct {
	N      int       `json:"n"`
	Sent   time.Time `json:"sent"`
	OK     bool      `json:"ok"` // logged in and every command ran
	Domain string    `json:"domain"`
}

// faultResult is what one injected fault did.
type faultResult struct {
	Name        string    `json:"name"`
	What        string    `json:"what"`
	Injected    time.Time `json:"injected"`
	Cleared     time.Time `json:"cleared"`
	HeldSeconds float64   `json:"held_seconds"`
	// RecoverySeconds: from the fault being cleared until every connection
	// accepted before then is in the database, the API answers and the
	// intelligence worker reports "running". -1: not within the limit.
	RecoverySeconds float64 `json:"recovery_seconds"`
	// Accepted counts connections the honeypot took while the fault held;
	// Refused those it did not take (the honeypot itself was down).
	Accepted int `json:"accepted_during"`
	Refused  int `json:"refused_during"`
	// LostDuring and MaxDelaySeconds are filled from the final accounting:
	// accepted connections sent during the fault that never arrived, and the
	// longest wait of one that did.
	LostDuring      int     `json:"lost_during"`
	MaxDelaySeconds float64 `json:"max_delay_seconds"`
	Note            string  `json:"note,omitempty"`
	Error           string  `json:"error,omitempty"`
}

type harness struct {
	t    *testing.T
	opt  options
	dir  string // the instance folder
	cfg  *config.Config
	db   driver.Conn
	qid  string
	port int
	tag  string // unique per run: part of every connection's client version
	web  string
	// childEnv is the environment the instance's own processes get.
	childEnv []string

	mu       sync.Mutex
	conns    []connection
	sessions []session
	burstN   int    // connections the traffic-burst fault has made
	password string // the login the honeypot last accepted
}

// burstBase numbers the traffic-burst fault's connections above the steady
// load's, whose numbers grow with time and so stand for "sent before".
const burstBase = 1_000_000_000

func (h *harness) logf(format string, a ...any) {
	h.t.Helper()
	h.t.Logf("%s  "+format, append([]any{time.Now().Format("15:04:05")}, a...)...)
}

// qpot runs the binary under test and returns its output with the QPot ID
// masked: the test log must never carry it.
func (h *harness) qpot(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.opt.bin, args...)
	cmd.Env = h.childEnv
	out, err := cmd.CombinedOutput()
	return h.mask(string(out)), err
}

func (h *harness) mask(s string) string {
	if h.qid != "" {
		s = strings.ReplaceAll(s, h.qid, "qp_***")
	}
	return s
}

func docker(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (h *harness) container(service string) string { return h.opt.instance + "_" + service }

// setup creates the instance with only cowrie, starts it and finds what the
// load and the measurements need.
func (h *harness) setup(ctx context.Context) {
	t := h.t
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	h.dir = filepath.Join(home, ".qpot", "instances", h.opt.instance)
	if _, err := os.Stat(h.dir); err == nil {
		t.Fatalf("instance %q exists already (%s); the soak only runs on one it creates", h.opt.instance, h.dir)
	}
	if out, err := h.qpot(ctx, 2*time.Minute, "instance", "create", h.opt.instance); err != nil {
		t.Fatalf("instance create: %v\n%s", err, out)
	}
	cfgPath := filepath.Join(h.dir, "config.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(raw, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for name := range cfg.Honeypots {
		if name != "cowrie" {
			_, _ = h.qpot(ctx, time.Minute, "honeypot", "disable", name, "-i", h.opt.instance)
		}
	}
	if out, err := h.qpot(ctx, time.Minute, "honeypot", "enable", "cowrie", "-i", h.opt.instance); err != nil {
		t.Fatalf("enable cowrie: %v\n%s", err, out)
	}
	// Settings the CLI has no command for: read the file as it is now and
	// change single lines, so nothing else about a default instance differs.
	raw, err = os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	replace := func(old, new string) {
		if !strings.Contains(text, old) {
			t.Fatalf("config.yaml has no line %q to change", strings.TrimSpace(old))
		}
		text = strings.Replace(text, old, new, 1)
	}
	if h.opt.sandbox != "" {
		replace("    sandbox_mode: gvisor\n", "    sandbox_mode: "+h.opt.sandbox+"\n")
	}
	replace("    worker_interval: 5m0s\n", "    worker_interval: 1m0s\n")
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}

	id, err := os.ReadFile(filepath.Join(h.dir, "qpot.id"))
	if err != nil {
		t.Fatal(err)
	}
	h.qid = strings.TrimSpace(string(id))

	h.logf("starting instance %q", h.opt.instance)
	if out, err := h.qpot(ctx, 25*time.Minute, "up", "-d", "-i", h.opt.instance); err != nil {
		t.Fatalf("qpot up: %v\n%s", err, tail(out, 30))
	}
	raw, err = os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if h.cfg, err = config.Parse(raw, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.cfg.QPotID = h.qid
	h.web = "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(h.cfg.WebUI.Port))

	out, err := docker(ctx, 20*time.Second, "port", h.container("cowrie"), "22/tcp")
	if err != nil {
		t.Fatalf("cowrie has no published SSH port: %v %s", err, out)
	}
	first := strings.SplitN(out, "\n", 2)[0]
	if h.port, err = strconv.Atoi(first[strings.LastIndexByte(first, ':')+1:]); err != nil {
		t.Fatalf("cowrie port %q: %v", out, err)
	}
	if err := h.connectDB(ctx); err != nil {
		t.Fatalf("database: %v", err)
	}
}

func (h *harness) connectDB(ctx context.Context) error {
	d := h.cfg.DatabaseClient()
	if d.Type != "clickhouse" {
		return fmt.Errorf("the soak measures a ClickHouse instance; this one is %q", d.Type)
	}
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr:        []string{net.JoinHostPort(d.Host, strconv.Itoa(d.Port))},
		Auth:        clickhouse.Auth{Database: d.Database, Username: d.Username, Password: d.Password},
		Settings:    clickhouse.Settings{"max_execution_time": 30},
		DialTimeout: 5 * time.Second, MaxOpenConns: 4, MaxIdleConns: 2, ConnMaxLifetime: 2 * time.Minute,
	})
	if err != nil {
		return err
	}
	h.db = conn
	return nil
}

func (h *harness) versionPrefix() string { return "SSH-2.0-QPotSoak_" + h.tag + "_" }

// connect makes one banner connection: the visit of a scanner that reads the
// server's version and sends its own. Cowrie logs it as cowrie.client.version.
func (h *harness) connect(n int) connection {
	c := connection{N: n, Sent: time.Now()}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(h.port)), 5*time.Second)
	if err != nil {
		return c
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	banner := make([]byte, 256)
	if k, err := conn.Read(banner); err != nil || !bytes.HasPrefix(banner[:k], []byte("SSH-")) {
		return c
	}
	if _, err := fmt.Fprintf(conn, "%s%d\r\n", h.versionPrefix(), n); err != nil {
		return c
	}
	// Read what the server sends next (its key exchange) for a moment
	// before closing: closing with unread data resets the connection, and a
	// reset can discard the line just sent before the honeypot reads it.
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	_, _ = io.Copy(io.Discard, conn)
	c.Accepted = true
	return c
}

// attack logs in over real SSH and runs three commands, one naming a domain
// no other session names: the intelligence worker must record that domain
// as an IOC seen exactly once.
func (h *harness) attack(n int) session {
	s := session{N: n, Sent: time.Now(), Domain: fmt.Sprintf("s%d.%s.qpot-soak.net", n, h.tag)}
	client := h.login()
	if client == nil {
		return s
	}
	defer client.Close()
	for _, cmd := range []string{"uname -a", "echo http://" + s.Domain + "/p.sh > /tmp/.u", "nmap -sV 10.0.0." + strconv.Itoa(n%250)} {
		sess, err := client.NewSession()
		if err != nil {
			return s
		}
		done := make(chan error, 1)
		go func() { _, err := sess.CombinedOutput(cmd); done <- err }()
		select {
		case err := <-done:
			var exit *ssh.ExitError
			if err != nil && !errors.As(err, &exit) {
				sess.Close()
				return s
			}
		case <-time.After(15 * time.Second):
			sess.Close()
			return s
		}
		sess.Close()
	}
	s.OK = true
	return s
}

// login opens an SSH connection as root. The T-Pot Cowrie image lets a
// source in after a random number of tries and then remembers what worked
// for it, as a brute-forcer would experience: try the remembered password
// first, then new ones.
func (h *harness) login() *ssh.Client {
	h.mu.Lock()
	known := h.password
	h.mu.Unlock()
	try := func(password string) *ssh.Client {
		client, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(h.port)), &ssh.ClientConfig{
			User: "root", Auth: []ssh.AuthMethod{ssh.Password(password)},
			// A honeypot on loopback that this test started: there is no
			// host key to compare with.
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- loopback honeypot started by this test
			Timeout:         8 * time.Second,
		})
		if err != nil {
			return nil
		}
		return client
	}
	if known != "" {
		if client := try(known); client != nil {
			return client
		}
	}
	for attempt := range 8 {
		var salt [3]byte
		_, _ = rand.Read(salt[:])
		password := fmt.Sprintf("Soak-%s-%d-%x", h.tag, attempt, salt)
		if client := try(password); client != nil {
			h.mu.Lock()
			h.password = password
			h.mu.Unlock()
			return client
		}
	}
	return nil
}

// load sends connections at the configured rate, and one login session for
// every sessionEvery connections, until ctx ends.
func (h *harness) load(ctx context.Context, wg *sync.WaitGroup) {
	const sessionEvery = 40
	interval := time.Duration(float64(time.Second) / h.opt.rate)
	sem := make(chan struct{}, 64)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for n := 1; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		select {
		case sem <- struct{}{}:
		default:
			n-- // the honeypot is not answering; do not queue without bound
			continue
		}
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			defer func() { <-sem }()
			c := h.connect(n)
			h.mu.Lock()
			h.conns = append(h.conns, c)
			h.mu.Unlock()
			if n%sessionEvery == 0 {
				s := h.attack(n / sessionEvery)
				h.mu.Lock()
				h.sessions = append(h.sessions, s)
				h.mu.Unlock()
			}
		}(n)
	}
}

// api asks the control plane; it returns the decoded object or an error.
func (h *harness) api(ctx context.Context, path string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.web+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-QPot-ID", h.qid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out map[string]any
	return out, json.Unmarshal(body, &out)
}

// progress reports, for the steady load, how many distinct connections
// numbered up to n the database holds, and whether it holds any numbered
// above n.
func (h *harness) progress(ctx context.Context, n int) (backlog uint64, flowing bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var later uint64
	err = h.db.QueryRow(ctx, `SELECT uniqExactIf(v, n <= ?), countIf(n > ? AND n < ?) FROM (
		SELECT metadata['version'] AS v, toUInt64OrZero(substring(v, ?)) AS n FROM events
		WHERE honeypot = 'cowrie' AND event_type = 'cowrie.client.version' AND startsWith(metadata['version'], ?))`,
		uint64(n), uint64(n), uint64(burstBase), uint64(len(h.versionPrefix())+1), h.versionPrefix()).Scan(&backlog, &later)
	return backlog, later > 0, err
}

// steadyUpTo returns the highest steady-load connection number sent by
// `at`, and how many up to it the honeypot accepted.
func (h *harness) steadyUpTo(at time.Time) (n, accepted int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.conns {
		if c.N < burstBase && !c.Sent.After(at) && c.N > n {
			n = c.N
		}
	}
	for _, c := range h.conns {
		if c.N <= n && c.Accepted {
			accepted++
		}
	}
	return n, accepted
}

// healthy reports whether the API answers and the intelligence worker runs.
func (h *harness) healthy(ctx context.Context) (bool, string) {
	summary, err := h.api(ctx, "/api/intelligence")
	if err != nil {
		return false, "API: " + firstLine(err.Error())
	}
	if state, _ := summary["worker_status"].(string); state != "running" {
		return false, "intelligence worker is " + state
	}
	return true, ""
}

// settle waits until the instance has recovered from a fault cleared at
// `cleared`, and returns how long that took from then. Recovered means all
// of: the backlog (connections sent before the fault was cleared) has
// arrived, or has stopped arriving for 20 seconds; a connection sent after
// it is in the database (when needFlow); the API answers; the intelligence
// worker runs. The
// time is that of the last of these to come true, not of the poll that saw
// it. -1 and the reason when limit passes first.
func (h *harness) settle(ctx context.Context, cleared time.Time, limit time.Duration, needFlow bool) (time.Duration, string) {
	n, want := h.steadyUpTo(cleared)
	var (
		last                             uint64
		lastChange, flowingAt, healthyAt time.Time
		lastLog                          time.Time
		why                              = "no answer from the database"
	)
	for start := time.Now(); time.Since(start) < limit; {
		backlog, flowing, err := h.progress(ctx, n)
		now := time.Now()
		switch {
		case err != nil:
			why = "database: " + firstLine(err.Error())
			healthyAt = time.Time{}
		default:
			if lastChange.IsZero() || backlog != last {
				last, lastChange = backlog, now
			}
			if flowing && flowingAt.IsZero() {
				flowingAt = now
			}
			if ok, reason := h.healthy(ctx); !ok {
				why, healthyAt = reason, time.Time{}
			} else if healthyAt.IsZero() {
				healthyAt = now
			}
			drained := int(backlog) >= want || now.Sub(lastChange) >= 20*time.Second
			switch {
			case !drained:
				why = fmt.Sprintf("database has %d of %d connections accepted before the fault cleared", backlog, want)
			case needFlow && flowingAt.IsZero():
				why = "no connection made after the fault cleared has reached the database"
			case !healthyAt.IsZero():
				done := lastChange
				for _, at := range []time.Time{flowingAt, healthyAt} {
					if at.After(done) {
						done = at
					}
				}
				return max(done.Sub(cleared), 0), ""
			}
		}
		if waited := time.Since(cleared); waited > time.Minute && time.Since(lastLog) > time.Minute {
			lastLog = time.Now()
			h.logf("  still recovering after %s: %s", waited.Round(time.Second), why)
		}
		select {
		case <-ctx.Done():
			return -1, "cancelled"
		case <-time.After(2 * time.Second):
		}
	}
	return -1, why
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func tail(s string, lines int) string {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}

// servePID is the control plane's process, from the pid file it writes.
func (h *harness) servePID() int {
	data, err := os.ReadFile(filepath.Join(h.dir, "qpot-serve.pid"))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	if pid <= 0 || syscall.Kill(pid, 0) != nil {
		return 0
	}
	return pid
}

// fault is one way to break the instance: inject, hold, clear.
type fault struct {
	name   string
	what   string
	inject func(ctx context.Context) error
	clear  func(ctx context.Context) error
	// hold overrides the configured hold time when set.
	hold time.Duration
	// skip returns a reason when the fault cannot run here.
	skip func() string
}

func (h *harness) faults() []fault {
	up := func(ctx context.Context) error {
		out, err := h.qpot(ctx, 15*time.Minute, "up", "-d", "-i", h.opt.instance)
		if err != nil {
			return fmt.Errorf("qpot up: %w: %s", err, tail(out, 6))
		}
		return nil
	}
	dockerDo := func(args ...string) func(context.Context) error {
		return func(ctx context.Context) error {
			out, err := docker(ctx, 2*time.Minute, args...)
			if err != nil {
				return fmt.Errorf("docker %s: %w: %s", args[0], err, firstLine(out))
			}
			return nil
		}
	}
	internalNet := h.opt.instance + "_qpot_internal"
	var rival context.CancelFunc
	var rivalDone chan struct{}
	var stopped int
	var filler string

	return []fault{
		{name: "database-stop", what: "the database container is stopped cleanly, then started",
			inject: dockerDo("stop", "--time", "20", h.container("db")), clear: dockerDo("start", h.container("db"))},
		{name: "database-kill", what: "the database is killed (SIGKILL) mid-write, then started",
			inject: dockerDo("kill", h.container("db")), clear: dockerDo("start", h.container("db"))},
		{name: "database-freeze", what: "the database is frozen (docker pause): connections hang instead of failing",
			inject: dockerDo("pause", h.container("db")), clear: dockerDo("unpause", h.container("db"))},
		{name: "collector-kill", what: "the collector is killed (SIGKILL), then started",
			inject: dockerDo("kill", h.container("collector")), clear: dockerDo("start", h.container("collector"))},
		{name: "collector-recreate", what: "the collector's container is removed and created again (its only state is its checkpoints)",
			inject: dockerDo("rm", "-f", h.container("collector")), clear: up},
		{name: "network-partition", what: "the collector is cut off from the database's network while both keep running",
			inject: dockerDo("network", "disconnect", internalNet, h.container("collector")),
			clear:  dockerDo("network", "connect", internalNet, h.container("collector"))},
		{name: "honeypot-kill", what: "the honeypot is killed (SIGKILL) and Docker's restart policy brings it back", hold: 20 * time.Second,
			inject: dockerDo("kill", h.container("cowrie")),
			clear: func(ctx context.Context) error {
				// on-failure restarts it; `up` covers a policy that gave up.
				for range 15 {
					if out, _ := docker(ctx, 10*time.Second, "inspect", "-f", "{{.State.Running}}", h.container("cowrie")); out == "true" {
						return nil
					}
					time.Sleep(2 * time.Second)
				}
				return up(ctx)
			}},
		{name: "honeypot-restart", what: "the honeypot is restarted through qpot (docker restart)", hold: 5 * time.Second,
			inject: func(ctx context.Context) error {
				out, err := h.qpot(ctx, 5*time.Minute, "docker", "restart", "cowrie", "-i", h.opt.instance)
				if err != nil {
					return fmt.Errorf("qpot docker restart: %w: %s", err, tail(out, 4))
				}
				return nil
			},
			clear: func(context.Context) error { return nil }},
		{name: "control-plane-kill", what: "the control plane (web UI, intelligence worker) is killed (SIGKILL), then started",
			inject: func(context.Context) error {
				pid := h.servePID()
				if pid == 0 {
					return errors.New("no control plane process")
				}
				return syscall.Kill(pid, syscall.SIGKILL)
			}, clear: up},
		{name: "worker-takeover", what: "the control plane is frozen (SIGSTOP) past its lease; a second worker takes over; the first is resumed and must stand down",
			hold: 75 * time.Second,
			inject: func(ctx context.Context) error {
				if stopped = h.servePID(); stopped == 0 {
					return errors.New("no control plane process")
				}
				if err := syscall.Kill(stopped, syscall.SIGSTOP); err != nil {
					return err
				}
				// The rival is this process: another "host" (its own lock
				// folder) working on the same database.
				rctx, cancel := context.WithCancel(context.Background())
				rival, rivalDone = cancel, make(chan struct{})
				go func() {
					defer close(rivalDone)
					h.runRivalWorker(rctx)
				}()
				return nil
			},
			clear: func(ctx context.Context) error {
				// Resume the first while the rival still owns the lease: this
				// is the moment a stale worker could write over a newer one.
				err := syscall.Kill(stopped, syscall.SIGCONT)
				time.Sleep(20 * time.Second)
				rival()
				select {
				case <-rivalDone:
				case <-time.After(time.Minute):
				}
				return err
			}},
		{name: "disk-full", what: "the filesystem holding the instance is filled to the last byte, then freed",
			skip: func() string {
				if h.opt.fillDir == "" {
					return "QPOT_SOAK_FILL_DIR is not set (it must be a small filesystem that holds the instance)"
				}
				return ""
			},
			inject: func(context.Context) error {
				filler = filepath.Join(h.opt.fillDir, ".soak-filler")
				f, err := os.OpenFile(filler, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
				if err != nil {
					return err
				}
				defer f.Close()
				block := make([]byte, 1<<20)
				for {
					if _, err := f.Write(block); err != nil {
						if errors.Is(err, syscall.ENOSPC) {
							// The last partial megabyte too.
							for small := block[:4096]; ; {
								if _, err := f.Write(small); err != nil {
									break
								}
							}
							return nil
						}
						return err
					}
				}
			},
			clear: func(context.Context) error { return os.Remove(filler) }},
		{name: "traffic-burst", what: "ten times the normal rate for the hold time, nothing broken",
			inject: func(context.Context) error { return nil }, clear: func(context.Context) error { return nil }},
	}
}

// runRivalWorker runs a second intelligence worker against the instance's
// database until ctx ends, as a control plane on another host would.
func (h *harness) runRivalWorker(ctx context.Context) {
	db, err := database.New(h.cfg.DatabaseClient())
	if err != nil {
		h.logf("rival worker: %v", err)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = db.Connect(cctx)
	cancel()
	if err != nil {
		h.logf("rival worker: connect: %v", firstLine(err.Error()))
		return
	}
	defer db.Close()
	loader := intelligence.NewATTCKLoader(h.cfg.Intelligence.ATTCKDataPath)
	classifier := intelligence.NewClassifier(loader, intelligence.NewTTPBuilder(h.cfg.Intelligence.InactivityWindow))
	w := intelligence.NewWorker(classifier, db, 15*time.Second, h.cfg.Intelligence.WorkerBatchSize)
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()
	owned := false
	for !owned {
		select {
		case <-ctx.Done():
			<-done
			h.logf("rival worker never owned the lease")
			return
		case <-time.After(2 * time.Second):
		}
		if state, _ := w.Status(); state == "running" {
			owned = true
			h.logf("rival worker owns the lease")
		}
	}
	<-done
}

func TestSoak(t *testing.T) {
	opt := loadOptions(t)
	// Another host's worker keeps its lock elsewhere: give this process its
	// own folder, so the rival worker competes for the database lease alone.
	// The instance's own processes keep the environment as it was.
	childEnv := os.Environ()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	tag := make([]byte, 4)
	if _, err := rand.Read(tag); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, opt: opt, tag: hex.EncodeToString(tag), childEnv: childEnv}
	ctx := t.Context()
	if err := os.MkdirAll(opt.reportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	h.setup(ctx)
	if !opt.keep {
		t.Cleanup(func() {
			cctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			_, _ = h.qpot(cctx, 5*time.Minute, "down", "-i", opt.instance)
			if pid := h.servePID(); pid != 0 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			_, _ = h.qpot(cctx, 5*time.Minute, "instance", "remove", opt.instance, "--force")
		})
	}

	loadCtx, stopLoad := context.WithCancel(ctx)
	var loaders sync.WaitGroup
	loaders.Add(1)
	go func() { defer loaders.Done(); h.load(loadCtx, &loaders) }()

	// Warm up and prove the measurement works before breaking anything: a
	// run whose baseline already loses events says nothing about faults.
	h.logf("warm-up: %s of traffic at %.1f connections/s", opt.gap, opt.rate)
	time.Sleep(opt.gap)
	if d, why := h.settle(ctx, time.Now().Add(-10*time.Second), 5*time.Minute, true); d < 0 {
		t.Fatalf("the instance does not keep up before any fault: %s", why)
	}
	baseline := h.account(ctx, time.Now().Add(-10*time.Second))
	h.logf("baseline: %d accepted, %d stored, %d lost, %d duplicated", baseline.Accepted, baseline.Stored, baseline.Lost, baseline.Duplicated)
	if baseline.Lost != 0 || baseline.Duplicated != 0 {
		t.Fatalf("baseline is not clean (lost %d, duplicated %d): the harness or the instance is broken before any fault", baseline.Lost, baseline.Duplicated)
	}

	all := h.faults()
	if len(opt.faults) > 0 {
		byName := map[string]fault{}
		for _, f := range all {
			byName[f.name] = f
		}
		all = nil
		for _, name := range opt.faults {
			f, ok := byName[strings.TrimSpace(name)]
			if !ok {
				t.Fatalf("QPOT_SOAK_FAULTS names %q, which is not a fault", name)
			}
			all = append(all, f)
		}
	}
	var results []faultResult
	deadline := time.Now().Add(opt.duration)
	for round := 0; time.Now().Before(deadline); round++ {
		f := all[round%len(all)]
		if f.skip != nil {
			if why := f.skip(); why != "" {
				if round < len(all) {
					h.logf("skipping %s: %s", f.name, why)
					results = append(results, faultResult{Name: f.name, What: f.what, Note: "skipped: " + why, RecoverySeconds: -1})
				}
				continue
			}
		}
		hold := opt.hold
		if f.hold > 0 {
			hold = f.hold
		}
		r := faultResult{Name: f.name, What: f.what, Injected: time.Now()}
		h.logf("FAULT %s: %s (held %s)", f.name, f.what, hold)
		var burst context.CancelFunc
		if f.name == "traffic-burst" {
			var bctx context.Context
			bctx, burst = context.WithCancel(ctx)
			for range 9 {
				loaders.Add(1)
				go func() { defer loaders.Done(); h.burst(bctx, &loaders) }()
			}
		}
		if err := f.inject(ctx); err != nil {
			r.Error = "inject: " + err.Error()
			h.logf("  inject failed: %v", err)
		}
		time.Sleep(hold)
		if burst != nil {
			burst()
		}
		if err := f.clear(ctx); err != nil {
			r.Error = strings.TrimSpace(r.Error + " clear: " + err.Error())
			h.logf("  clear failed: %v", err)
		}
		r.Cleared = time.Now()
		r.HeldSeconds = r.Cleared.Sub(r.Injected).Seconds()
		d, why := h.settle(ctx, r.Cleared, 15*time.Minute, true)
		if d < 0 {
			r.RecoverySeconds = -1
			r.Note = "not recovered within 15m: " + why
		} else {
			r.RecoverySeconds = d.Seconds()
		}
		h.logf("  recovered in %.0fs %s", r.RecoverySeconds, r.Note)
		results = append(results, r)
		select {
		case <-ctx.Done():
			t.Fatal("cancelled")
		case <-time.After(opt.gap):
		}
	}

	stopLoad()
	loaders.Wait()
	end := time.Now()
	h.logf("load stopped; waiting for the last events and for the worker to classify them")
	// No traffic follows the end: wait for the backlog and a healthy worker.
	h.settle(ctx, end, 10*time.Minute, false)
	time.Sleep(3 * time.Minute) // two worker passes at the soak's 1m interval

	final := h.account(ctx, end)
	final.Faults = h.attribute(ctx, results)
	final.Intelligence = h.intelligence(ctx)
	final.Options = map[string]any{"duration": opt.duration.String(), "rate_per_second": opt.rate, "gap": opt.gap.String(),
		"hold": opt.hold.String(), "sandbox_mode": opt.sandbox, "binary": filepath.Base(opt.bin)}
	if out, err := h.qpot(ctx, time.Minute, "--version"); err == nil {
		final.Options["version"] = strings.TrimSpace(out)
	}
	h.write(final)

	// The run passes on its own terms: a fault may delay events, and may lose
	// the ones in flight inside the honeypot it kills, but nothing may be
	// stored twice and every fault must be recovered from.
	if final.Duplicated != 0 {
		t.Errorf("%d connections are stored more than once", final.Duplicated)
	}
	for _, f := range final.Faults {
		if f.RecoverySeconds < 0 && !strings.HasPrefix(f.Note, "skipped") {
			t.Errorf("%s: %s", f.Name, f.Note)
		}
		if f.LostDuring > 0 && !strings.HasPrefix(f.Name, "honeypot-") && f.Name != "disk-full" {
			t.Errorf("%s lost %d accepted connections", f.Name, f.LostDuring)
		}
	}
	if final.Intelligence.IOCsCountedTwice != 0 || final.Intelligence.DuplicateSessionRows != 0 {
		t.Errorf("duplicated intelligence: %+v", final.Intelligence)
	}
}

// burst is extra load for the traffic-burst fault: the same connections,
// numbered above the steady load's so the two never collide.
func (h *harness) burst(ctx context.Context, wg *sync.WaitGroup) {
	ticker := time.NewTicker(time.Duration(float64(time.Second) / h.opt.rate))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		h.mu.Lock()
		h.burstN++
		n := burstBase + h.burstN
		h.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := h.connect(n)
			h.mu.Lock()
			h.conns = append(h.conns, c)
			h.mu.Unlock()
		}()
	}
}

// report is the run's result, written as JSON and as a Markdown summary.
type report struct {
	Options      map[string]any `json:"options"`
	Started      time.Time      `json:"started"`
	Ended        time.Time      `json:"ended"`
	Sent         int            `json:"connections_sent"`
	Accepted     int            `json:"accepted_by_honeypot"`
	Refused      int            `json:"refused_honeypot_down"`
	Stored       int            `json:"stored_distinct"`
	Lost         int            `json:"lost"`
	Duplicated   int            `json:"duplicated"`
	DelayP50     float64        `json:"delay_p50_seconds"`
	DelayP99     float64        `json:"delay_p99_seconds"`
	DelayMax     float64        `json:"delay_max_seconds"`
	LostSamples  []int          `json:"lost_samples,omitempty"`
	Faults       []faultResult  `json:"faults"`
	Intelligence intelReport    `json:"intelligence"`
	delays       map[int]float64
	lost         map[int]bool
}

type intelReport struct {
	Sessions             int    `json:"login_sessions"`
	SessionsOK           int    `json:"login_sessions_completed"`
	IOCsExpected         int    `json:"iocs_expected"`
	IOCsFound            int    `json:"iocs_found"`
	IOCsMissing          int    `json:"iocs_missing"`
	IOCsCountedTwice     int    `json:"iocs_counted_more_than_once"`
	CommandEvents        int    `json:"command_events_stored"`
	CommandsClassified   int    `json:"command_events_classified"`
	ScannerCommands      int    `json:"scanner_commands_stored"`
	ScannerCommandsWant  int    `json:"scanner_commands_expected"`
	SessionRows          int    `json:"session_rows"`
	DuplicateSessionRows int    `json:"duplicate_session_rows"`
	Unclassified         int    `json:"events_unclassified_at_end"`
	Note                 string `json:"note,omitempty"`
}

// account compares what the honeypot accepted up to `until` with what the
// database holds, connection by connection.
func (h *harness) account(ctx context.Context, until time.Time) report {
	h.mu.Lock()
	conns := append([]connection(nil), h.conns...)
	h.mu.Unlock()
	r := report{Ended: until, delays: map[int]float64{}, lost: map[int]bool{}}
	if len(conns) > 0 {
		r.Started = conns[0].Sent
	}
	sent := map[int]connection{}
	for _, c := range conns {
		if c.Sent.After(until) {
			continue
		}
		r.Sent++
		if c.Accepted {
			r.Accepted++
			sent[c.N] = c
		} else {
			r.Refused++
		}
	}
	qctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	rows, err := h.db.Query(qctx, `SELECT metadata['version'], count(), min(timestamp) FROM events
		WHERE honeypot = 'cowrie' AND event_type = 'cowrie.client.version' AND startsWith(metadata['version'], ?)
		GROUP BY metadata['version']`, h.versionPrefix())
	if err != nil {
		h.t.Fatalf("final accounting: %v", err)
	}
	defer rows.Close()
	seen := map[int]bool{}
	var delays []float64
	for rows.Next() {
		var version string
		var count uint64
		var stored time.Time
		if err := rows.Scan(&version, &count, &stored); err != nil {
			h.t.Fatal(err)
		}
		n, err := strconv.Atoi(strings.TrimPrefix(version, h.versionPrefix()))
		if err != nil {
			continue
		}
		c, ours := sent[n]
		if !ours {
			// Stored though the client never saw the key exchange: the
			// honeypot logged a connection the fault cut. Not lost, and
			// not counted as accepted either.
			continue
		}
		seen[n] = true
		r.Stored++
		if count > 1 {
			r.Duplicated += int(count) - 1
		}
		d := stored.Sub(c.Sent).Seconds()
		r.delays[n] = d
		delays = append(delays, d)
	}
	for n := range sent {
		if !seen[n] {
			r.Lost++
			r.lost[n] = true
			if len(r.LostSamples) < 20 {
				r.LostSamples = append(r.LostSamples, n)
			}
		}
	}
	sort.Ints(r.LostSamples)
	sort.Float64s(delays)
	if len(delays) > 0 {
		r.DelayP50 = delays[len(delays)/2]
		r.DelayP99 = delays[len(delays)*99/100]
		r.DelayMax = delays[len(delays)-1]
	}
	return r
}

// attribute fills each fault's share of the final accounting: connections
// sent while it held (and during its recovery) that were lost, and the
// longest delay among those that arrived.
func (h *harness) attribute(ctx context.Context, faults []faultResult) []faultResult {
	final := h.account(ctx, time.Now())
	h.mu.Lock()
	conns := append([]connection(nil), h.conns...)
	h.mu.Unlock()
	for i := range faults {
		f := &faults[i]
		if f.Injected.IsZero() {
			continue
		}
		until := f.Cleared
		if f.RecoverySeconds > 0 {
			until = until.Add(time.Duration(f.RecoverySeconds * float64(time.Second)))
		}
		for _, c := range conns {
			// A connection sent a moment before the fault is in flight when
			// it hits.
			if c.Sent.Before(f.Injected.Add(-3*time.Second)) || c.Sent.After(until) {
				continue
			}
			if !c.Accepted {
				f.Refused++
				continue
			}
			f.Accepted++
			if final.lost[c.N] {
				f.LostDuring++
			}
			if d, ok := final.delays[c.N]; ok && d > f.MaxDelaySeconds {
				f.MaxDelaySeconds = d
			}
		}
	}
	return faults
}

// intelligence checks the worker's output for the login sessions: each
// session named one domain nobody else named, so that domain must be an IOC
// seen exactly once, however often the worker was killed, replaced or
// replayed its checkpoint.
func (h *harness) intelligence(ctx context.Context) intelReport {
	h.mu.Lock()
	sessions := append([]session(nil), h.sessions...)
	h.mu.Unlock()
	var r intelReport
	want := map[string]bool{}
	for _, s := range sessions {
		r.Sessions++
		if s.OK {
			r.SessionsOK++
			want[s.Domain] = true
		}
	}
	r.IOCsExpected = len(want)
	r.ScannerCommandsWant = r.SessionsOK
	qctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	suffix := "." + h.tag + ".qpot-soak.net"
	rows, err := h.db.Query(qctx, `SELECT value, max(count), count() FROM (SELECT value, count FROM intelligence_iocs FINAL
		WHERE type = 'domain' AND endsWith(value, ?)) GROUP BY value`, suffix)
	if err != nil {
		r.Note = "IOC query: " + firstLine(err.Error())
		return r
	}
	for rows.Next() {
		var value string
		var seenCount, rowCount uint64
		if err := rows.Scan(&value, &seenCount, &rowCount); err != nil {
			break
		}
		if want[value] {
			r.IOCsFound++
			delete(want, value)
		}
		if seenCount > 1 || rowCount > 1 {
			r.IOCsCountedTwice++
		}
	}
	rows.Close()
	r.IOCsMissing = len(want)
	one := func(query string, args ...any) int {
		var n uint64
		if err := h.db.QueryRow(qctx, query, args...).Scan(&n); err != nil {
			r.Note = strings.TrimSpace(r.Note + " " + firstLine(err.Error()))
		}
		return int(n)
	}
	mine := "%" + suffix + "%"
	r.CommandEvents = one(`SELECT count() FROM events WHERE honeypot = 'cowrie' AND command LIKE ?`, mine)
	r.CommandsClassified = one(`SELECT count() FROM events WHERE honeypot = 'cowrie' AND command LIKE ? AND classified = 1`, mine)
	r.ScannerCommands = one(`SELECT count() FROM events WHERE honeypot = 'cowrie' AND event_type = 'cowrie.command.input' AND startsWith(command, 'nmap -sV 10.0.0.')`)
	r.SessionRows = one(`SELECT count() FROM intelligence_sessions FINAL`)
	r.DuplicateSessionRows = one(`SELECT toUInt64(count() - uniqExact(session_id)) FROM intelligence_sessions FINAL`)
	r.Unclassified = one(`SELECT count() FROM events WHERE classified = 0 AND timestamp < now() - INTERVAL 3 MINUTE`)
	return r
}

func (h *harness) write(r report) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	jsonPath := filepath.Join(h.opt.reportDir, "soak-"+h.tag+".json")
	if err := os.WriteFile(jsonPath, data, 0o644); err != nil {
		h.t.Fatal(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# QPot failure soak %s\n\n", h.tag)
	fmt.Fprintf(&b, "%s to %s (%s), %v connections/s, %v.\n\n", r.Started.Format("2006-01-02 15:04"), r.Ended.Format("15:04"),
		r.Ended.Sub(r.Started).Round(time.Minute), r.Options["rate_per_second"], r.Options["version"])
	fmt.Fprintf(&b, "| Connections | Count |\n|---|---|\n| sent | %d |\n| accepted by the honeypot | %d |\n| refused (honeypot down) | %d |\n| stored, distinct | %d |\n| **lost** | **%d** |\n| **stored twice** | **%d** |\n\n",
		r.Sent, r.Accepted, r.Refused, r.Stored, r.Lost, r.Duplicated)
	fmt.Fprintf(&b, "Delay from connection to the collector reading it: median %.1f s, 99th percentile %.1f s, longest %.1f s.\n\n", r.DelayP50, r.DelayP99, r.DelayMax)
	b.WriteString("| Fault | Held | Recovery | Accepted during | Refused during | Lost | Longest collection delay | Note |\n|---|---|---|---|---|---|---|---|\n")
	for _, f := range r.Faults {
		rec := fmt.Sprintf("%.0f s", f.RecoverySeconds)
		if f.RecoverySeconds < 0 {
			rec = "-"
		}
		fmt.Fprintf(&b, "| %s | %.0f s | %s | %d | %d | %d | %.0f s | %s |\n", f.Name, f.HeldSeconds, rec, f.Accepted, f.Refused, f.LostDuring, f.MaxDelaySeconds,
			strings.TrimSpace(f.Note+" "+f.Error))
	}
	i := r.Intelligence
	fmt.Fprintf(&b, "\n| Intelligence | Count |\n|---|---|\n| login sessions completed | %d of %d |\n| IOCs expected (one unique domain per session) | %d |\n| found | %d |\n| missing | %d |\n| **counted more than once** | **%d** |\n| scanner commands stored | %d of %d |\n| session rows | %d |\n| **duplicate session rows** | **%d** |\n| events still unclassified | %d |\n",
		i.SessionsOK, i.Sessions, i.IOCsExpected, i.IOCsFound, i.IOCsMissing, i.IOCsCountedTwice, i.ScannerCommands, i.ScannerCommandsWant, i.SessionRows, i.DuplicateSessionRows, i.Unclassified)
	if i.Note != "" {
		fmt.Fprintf(&b, "\nNote: %s\n", i.Note)
	}
	mdPath := filepath.Join(h.opt.reportDir, "soak-"+h.tag+".md")
	if err := os.WriteFile(mdPath, []byte(b.String()), 0o644); err != nil {
		h.t.Fatal(err)
	}
	h.logf("report: %s and %s", jsonPath, mdPath)
	h.t.Log("\n" + b.String())
}
