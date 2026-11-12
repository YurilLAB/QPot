//go:build unix

package soak

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/qpot/qpot/internal/config"
)

// The HiFi capture soak: live sessions on the real-OpenSSH honeypot
// (ssh-proxy) while the parts that record them are broken. Every command a
// session ran is a line of evidence with a number; afterwards the database
// must hold each one once.
//
// QPOT_SOAK=1 QPOT_SOAK_HIFI=1, with the two HiFi images built locally
// (qpot-local/ssh-proxy:development, qpot-local/ssh-backend:development). The
// other QPOT_SOAK_* settings mean what they mean for TestSoak; RATE is not
// used (the cells set the pace).

const (
	hifiService = "ssh-proxy"
	// hifiCommandEvent is the event the collector stores for a command a
	// visitor ran in a cell.
	hifiCommandEvent = "ssh-proxy.command.start"
	// hifiBackends is the number of cells: one for the session that stays
	// open, the rest for the short ones.
	hifiBackends = 3
)

// hifiCommand is one command a session sent.
type hifiCommand struct {
	N    int       `json:"n"`
	Sent time.Time `json:"sent"`
	// Executed: the cell's shell ran it and its output came back.
	Executed bool `json:"executed"`
	// Long: sent on the connection that stays open across faults.
	Long bool `json:"long"`
}

// hifiLogin is one attempt to open a session.
type hifiLogin struct {
	Sent     time.Time `json:"sent"`
	Admitted bool      `json:"admitted"`
}

type hifiFault struct {
	Name            string    `json:"name"`
	What            string    `json:"what"`
	Injected        time.Time `json:"injected"`
	Cleared         time.Time `json:"cleared"`
	HeldSeconds     float64   `json:"held_seconds"`
	RecoverySeconds float64   `json:"recovery_seconds"`
	// Commands the cells ran while the fault held, and of those how many
	// never reached the database or are in it more than once.
	Executed    int `json:"executed_during"`
	Lost        int `json:"lost_during"`
	StoredTwice int `json:"stored_twice_during"`
	// Logins while the fault held: taken and turned away.
	Admitted int `json:"admitted_during"`
	Refused  int `json:"refused_during"`
	// AdmittedLate counts logins taken more than 45 seconds into a fault
	// that stops the capture: the broker must turn visitors away once the
	// capture heartbeat is 30 seconds old.
	AdmittedLate    int     `json:"admitted_late"`
	MaxDelaySeconds float64 `json:"max_delay_seconds"`
	Note            string  `json:"note,omitempty"`
	Error           string  `json:"error,omitempty"`
}

type hifiReport struct {
	Instance    string         `json:"instance"`
	Started     time.Time      `json:"started"`
	Ended       time.Time      `json:"ended"`
	Options     map[string]any `json:"options"`
	Sent        int            `json:"commands_sent"`
	Executed    int            `json:"commands_executed"`
	Stored      int            `json:"commands_stored"`
	Lost        int            `json:"commands_lost"`
	StoredTwice int            `json:"commands_stored_twice"`
	// NotExecutedStored: commands the client got no output for (its
	// connection died first) that the cell ran and recorded all the same.
	NotExecutedStored int   `json:"stored_without_client_output"`
	Logins            int   `json:"logins"`
	Admitted          int   `json:"logins_admitted"`
	LostNumbers       []int `json:"lost_numbers,omitempty"`
	// TwiceRows describes every row of a command that is stored more than
	// once: when it was sent, and each row's time, ID and where it came from.
	TwiceRows []string `json:"stored_twice_rows,omitempty"`
	// CopiesClearedSeconds is how long after the last session the worker
	// had removed every row the collector sent a second time (a
	// collector-amnesia fault sends all of them again). SecondCopiesLeft
	// is how many it had not removed when the wait ended.
	CopiesClearedSeconds float64     `json:"second_copies_cleared_seconds"`
	SecondCopiesLeft     int         `json:"second_copies_left"`
	Faults               []hifiFault `json:"faults"`
}

// replayWaitMost is how long the run waits, after its last session, for the
// worker to remove the rows a collector-amnesia fault sent again. Until
// then such a row is a copy the worker has yet to look at, not a command
// stored twice.
const replayWaitMost = 90 * time.Minute

// describeMost is how many commands stored more than once are listed row by
// row. Each costs a query over the events table.
const describeMost = 20

type hifiHarness struct {
	*harness
	hport int

	hmu      sync.Mutex
	commands []hifiCommand
	logins   []hifiLogin
	seq      int
}

func (h *hifiHarness) marker(n int) string { return "qs" + h.tag + "x" + strconv.Itoa(n) }

// setupHiFi creates an instance with only the HiFi SSH honeypot and starts it.
func (h *hifiHarness) setupHiFi(ctx context.Context) {
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
		if name != hifiService {
			_, _ = h.qpot(ctx, time.Minute, "honeypot", "disable", name, "-i", h.opt.instance)
		}
	}
	if out, err := h.qpot(ctx, time.Minute, "honeypot", "enable", hifiService, "-i", h.opt.instance); err != nil {
		t.Fatalf("enable %s: %v\n%s", hifiService, err, out)
	}
	// cell_hold_minutes 0: a cell per connection, reset when it ends. Every
	// connection of this test comes from one address (Docker's port proxy),
	// so with a hold they would all share one cell.
	if out, err := h.qpot(ctx, time.Minute, "honeypot", "set", hifiService, "image_source=local",
		"backends="+strconv.Itoa(hifiBackends), "cell_hold_minutes=0", "-i", h.opt.instance); err != nil {
		t.Fatalf("set %s: %v\n%s", hifiService, err, out)
	}
	// The remaining settings have no command: load the file the CLI wrote,
	// change them, and save it the way the CLI does.
	raw, err = os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg, err = config.Parse(raw, cfgPath); err != nil {
		t.Fatal(err)
	}
	if h.opt.sandbox != "" {
		cfg.Security.SandboxMode = h.opt.sandbox
	}
	cfg.Intelligence.WorkerInterval = time.Minute
	if h.opt.fillDir != "" {
		floor := int64(soakGuardFloorMB)
		cfg.Cleanup.MinFreeMB, cfg.Cleanup.ResumeFreeMB = &floor, soakGuardResumeMB
	}
	hp := cfg.Honeypots[hifiService]
	hp.Stealth.CredentialTemplate = "abandoned-vps"
	cfg.Honeypots[hifiService] = hp
	if err := config.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	id, err := os.ReadFile(filepath.Join(h.dir, "qpot.id"))
	if err != nil {
		t.Fatal(err)
	}
	h.qid = strings.TrimSpace(string(id))

	h.logf("starting HiFi instance %q", h.opt.instance)
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
	out, err := docker(ctx, 20*time.Second, "port", h.container(hifiService), "2222/tcp")
	if err != nil {
		t.Fatalf("%s has no published SSH port: %v %s", hifiService, err, out)
	}
	first := strings.SplitN(out, "\n", 2)[0]
	if h.hport, err = strconv.Atoi(first[strings.LastIndexByte(first, ':')+1:]); err != nil {
		t.Fatalf("%s port %q: %v", hifiService, out, err)
	}
	if err := h.connectDB(ctx); err != nil {
		t.Fatalf("database: %v", err)
	}
}

// dial opens an SSH connection to the HiFi honeypot with one of the
// credentials its login template accepts. nil: turned away or unreachable.
func (h *hifiHarness) dial() *ssh.Client {
	h.mu.Lock()
	known := h.password
	h.mu.Unlock()
	try := func(user, password string) *ssh.Client {
		client, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(h.hport)), &ssh.ClientConfig{
			User: user, Auth: []ssh.AuthMethod{ssh.Password(password)},
			// A honeypot on loopback that this test started: there is no
			// host key to compare with.
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- loopback honeypot started by this test
			Timeout:         10 * time.Second,
		})
		if err != nil {
			return nil
		}
		return client
	}
	if user, password, ok := strings.Cut(known, "\x00"); ok {
		if client := try(user, password); client != nil {
			return client
		}
	}
	for _, cred := range h.credentials() {
		if client := try(cred[0], cred[1]); client != nil {
			h.mu.Lock()
			h.password = cred[0] + "\x00" + cred[1]
			h.mu.Unlock()
			return client
		}
	}
	return nil
}

// credentials are the root logins of the "abandoned-vps" login template the
// instance is set up with: the test logs in the way a visitor who guessed
// right would.
func (h *hifiHarness) credentials() [][2]string {
	return [][2]string{{"root", "123456"}, {"root", "toor"}}
}

// run sends one numbered command on client and records whether its output
// came back.
func (h *hifiHarness) run(client *ssh.Client, long bool) bool {
	h.hmu.Lock()
	h.seq++
	n := h.seq
	h.hmu.Unlock()
	c := hifiCommand{N: n, Sent: time.Now(), Long: long}
	defer func() {
		h.hmu.Lock()
		h.commands = append(h.commands, c)
		h.hmu.Unlock()
	}()
	sess, err := client.NewSession()
	if err != nil {
		return false
	}
	defer sess.Close()
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := sess.Output("echo " + h.marker(n))
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		c.Executed = r.err == nil && strings.TrimSpace(string(r.out)) == h.marker(n)
	case <-time.After(20 * time.Second):
	}
	return c.Executed
}

func (h *hifiHarness) login() *ssh.Client {
	l := hifiLogin{Sent: time.Now()}
	client := h.dial()
	l.Admitted = client != nil
	h.hmu.Lock()
	h.logins = append(h.logins, l)
	h.hmu.Unlock()
	return client
}

// longSession keeps one connection open for as long as the honeypot lets it,
// running a command every three seconds, and opens another when it ends: the
// live session a capture outage happens to.
func (h *hifiHarness) longSession(ctx context.Context) {
	for ctx.Err() == nil {
		client := h.login()
		if client == nil {
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
			continue
		}
		failures := 0
		for ctx.Err() == nil && failures < 2 {
			if h.run(client, true) {
				failures = 0
			} else {
				failures++
			}
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
		}
		client.Close()
	}
}

// shortSessions opens a session every 20 seconds: log in, three commands,
// leave. Each one takes a cell that is reset afterwards.
func (h *hifiHarness) shortSessions(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if client := h.login(); client != nil {
			for range 3 {
				if !h.run(client, false) {
					break
				}
			}
			client.Close()
		}
	}
}

// stored returns, for every numbered command in the database, how many rows
// hold it.
func (h *hifiHarness) stored(ctx context.Context) (map[int]int, map[int]time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	prefix := "echo " + h.marker(0)
	prefix = prefix[:len(prefix)-1]
	rows, err := h.db.Query(ctx, `SELECT toUInt64OrZero(substring(command, ?)) AS n, count(), min(timestamp) FROM events
		WHERE honeypot = 'ssh-proxy' AND event_type = ? AND startsWith(command, ?) GROUP BY n`,
		uint64(len(prefix)+1), hifiCommandEvent, prefix)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	counts, at := map[int]int{}, map[int]time.Time{}
	for rows.Next() {
		var n, c uint64
		var first time.Time
		if err := rows.Scan(&n, &c, &first); err != nil {
			return nil, nil, err
		}
		counts[int(n)], at[int(n)] = int(c), first
	}
	return counts, at, rows.Err()
}

// executedUpTo returns the numbers of the commands sent by `at` that ran.
func (h *hifiHarness) executedUpTo(at time.Time) (ran []int, last int) {
	h.hmu.Lock()
	defer h.hmu.Unlock()
	for _, c := range h.commands {
		if c.Sent.After(at) {
			continue
		}
		if c.N > last {
			last = c.N
		}
		if c.Executed {
			ran = append(ran, c.N)
		}
	}
	return ran, last
}

// settleHiFi waits until the instance has recovered from a fault cleared at
// `cleared`: every command that ran before then is stored (or nothing more
// has arrived for 30 seconds), a command sent afterwards is stored too, the
// API answers and the worker runs. It returns the time that took, or -1 and
// why.
func (h *hifiHarness) settleHiFi(ctx context.Context, cleared time.Time, limit time.Duration, needFlow bool) (time.Duration, string) {
	ran, lastBefore := h.executedUpTo(cleared)
	var (
		have                             int
		lastChange, flowingAt, healthyAt time.Time
		why                              = "no answer from the database"
	)
	for start := time.Now(); time.Since(start) < limit; {
		counts, _, err := h.stored(ctx)
		now := time.Now()
		if err != nil {
			why, healthyAt = "database: "+firstLine(err.Error()), time.Time{}
		} else {
			got := 0
			for _, n := range ran {
				if counts[n] > 0 {
					got++
				}
			}
			if lastChange.IsZero() || got != have {
				have, lastChange = got, now
			}
			if flowingAt.IsZero() {
				for n := range counts {
					if n > lastBefore {
						flowingAt = now
						break
					}
				}
			}
			if ok, reason := h.healthy(ctx); !ok {
				why, healthyAt = reason, time.Time{}
			} else if healthyAt.IsZero() {
				healthyAt = now
			}
			drained := got >= len(ran) || now.Sub(lastChange) >= 30*time.Second
			switch {
			case !drained:
				why = fmt.Sprintf("database has %d of the %d commands that ran before the fault cleared", got, len(ran))
			case needFlow && flowingAt.IsZero():
				why = "no command sent after the fault cleared has reached the database"
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
		select {
		case <-ctx.Done():
			return -1, "cancelled"
		case <-time.After(3 * time.Second):
		}
	}
	return -1, why
}

// cellStreamsMost is more commands than one cell keeps with their streams
// for one account (2,048 files, five for a command with its streams): the
// commands after them leave a record in the account's overflow file only.
const cellStreamsMost = 2100

// longStayMost is how far a stay may get before the follower has stopped
// its cell. The follower stops a cell when its capture passes the first
// mark (about 360 commands of one account), and a visitor who never pauses
// is ahead of it by what it writes to disk in the meantime: 2,100 commands
// in the 12 seconds the follower needed on a filesystem that really syncs.
// Left alone, sshd ends the connection at about 17,000 commands (its 64 MiB
// budget), so a stay that gets to 12,000 was not ended by the follower.
const longStayMost = 12000

// longOutageMost is more commands than one connection's capture budget
// records (64 MiB of container log, about 4 kB for a short command): a
// connection the backend has not ended by then is running unrecorded.
const longOutageMost = 40000

// cells lists the instance's running cell containers.
func (h *hifiHarness) cells(ctx context.Context) []string {
	out, err := docker(ctx, 20*time.Second, "ps", "--format", "{{.Names}}", "--filter", "name=^"+h.opt.instance+"_ssh-backend")
	if err != nil {
		return nil
	}
	return strings.Fields(out)
}

func (h *hifiHarness) hifiFaults() []fault {
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
	var stopped int
	var filler string
	hoursOutage, _ := time.ParseDuration(strings.TrimSpace(os.Getenv("QPOT_SOAK_HIFI_OUTAGE")))
	return []fault{
		{name: "long-stay", what: "one visitor stays in one cell and runs commands without a pause until the honeypot ends the stay: a cell keeps only so much recording, and must stop serving before a command would run without a record", hold: 10 * time.Second,
			inject: func(ctx context.Context) error {
				var client *ssh.Client
				for wait := time.Now().Add(time.Minute); client == nil && time.Now().Before(wait) && ctx.Err() == nil; {
					if client = h.login(); client == nil {
						time.Sleep(3 * time.Second)
					}
				}
				if client == nil {
					return errors.New("no cell took the visitor within a minute")
				}
				defer client.Close()
				ran := 0
				for ran < longStayMost && ctx.Err() == nil && h.run(client, false) {
					ran++
				}
				h.logf("  the stay ended after %d commands", ran)
				if ran >= longStayMost {
					return fmt.Errorf("the cell still served after %d commands in one stay: the follower did not stop it when its capture passed the mark", ran)
				}
				return nil
			}, clear: func(context.Context) error { return nil }},
		{name: "long-outage", what: "the control plane is killed and, while it is down, one visitor runs commands in one cell until the honeypot ends the connection: nobody converts the recordings or stops the cell, so every command must wait in the cell's own log and be recorded once the control plane is back", hold: 10 * time.Second,
			inject: func(ctx context.Context) error {
				pid := h.servePID()
				if pid == 0 {
					return errors.New("no control plane process")
				}
				if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
					return err
				}
				// The broker still takes visitors for 30 seconds.
				var client *ssh.Client
				for wait := time.Now().Add(25 * time.Second); client == nil && time.Now().Before(wait) && ctx.Err() == nil; {
					if client = h.login(); client == nil {
						time.Sleep(2 * time.Second)
					}
				}
				if client == nil {
					return errors.New("no cell took the visitor in the 25 seconds after the control plane stopped")
				}
				defer client.Close()
				ran := 0
				for ran < longOutageMost && ctx.Err() == nil && h.run(client, false) {
					ran++
				}
				h.logf("  the visitor ran %d commands with the control plane down", ran)
				if ran >= longOutageMost {
					return fmt.Errorf("the connection was still served after %d commands, more than its capture budget records", ran)
				}
				if ran <= cellStreamsMost {
					return fmt.Errorf("the connection ended after %d commands: too few to pass what a cell keeps for one account, so this run says nothing about the overflow", ran)
				}
				return nil
			}, clear: up},
		{name: "hours-outage", what: "the control plane is killed and stays down for QPOT_SOAK_HIFI_OUTAGE, longer than a cell lives, with a session open: its commands wait in the cell's log, the broker ends the stay when the cell's life is over, and everything is recorded once the control plane is back", hold: hoursOutage,
			skip: func() string {
				if hoursOutage <= 0 {
					return "QPOT_SOAK_HIFI_OUTAGE is not set (for example 2h15m)"
				}
				return ""
			},
			inject: func(context.Context) error {
				pid := h.servePID()
				if pid == 0 {
					return errors.New("no control plane process")
				}
				return syscall.Kill(pid, syscall.SIGKILL)
			}, clear: up},
		{name: "capture-stop", what: "the control plane, which turns the cells' recordings into evidence and tells the broker the capture is alive, is killed (SIGKILL), then started",
			inject: func(context.Context) error {
				pid := h.servePID()
				if pid == 0 {
					return errors.New("no control plane process")
				}
				return syscall.Kill(pid, syscall.SIGKILL)
			}, clear: up},
		{name: "capture-freeze", what: "the control plane is frozen (SIGSTOP), then resumed: the capture stops without anything exiting",
			inject: func(context.Context) error {
				if stopped = h.servePID(); stopped == 0 {
					return errors.New("no control plane process")
				}
				return syscall.Kill(stopped, syscall.SIGSTOP)
			},
			clear: func(context.Context) error { return syscall.Kill(stopped, syscall.SIGCONT) }},
		{name: "collector-kill", what: "the collector is killed (SIGKILL), then started",
			inject: dockerDo("kill", h.container("collector")), clear: dockerDo("start", h.container("collector"))},
		{name: "database-kill", what: "the database is killed (SIGKILL) mid-write, then started",
			inject: dockerDo("kill", h.container("db")), clear: dockerDo("start", h.container("db"))},
		{name: "collector-amnesia", what: "the collector is removed and its checkpoints are deleted: it reads every record again, most of them from the archive folders their cells' resets moved them to",
			inject: h.forgetCheckpoints, clear: up},
		{name: "cell-kill", what: "every cell is killed (SIGKILL) with sessions inside", hold: 20 * time.Second,
			inject: func(ctx context.Context) error {
				cells := h.cells(ctx)
				if len(cells) == 0 {
					return errors.New("no cell is running")
				}
				_, err := docker(ctx, time.Minute, append([]string{"kill"}, cells...)...)
				return err
			}, clear: up},
		{name: "broker-kill", what: "the broker, which every session passes through, is killed (SIGKILL)", hold: 20 * time.Second,
			inject: dockerDo("kill", h.container(hifiService)), clear: up},
		{name: "disk-full", what: "the filesystem holding the instance is filled to the last byte, then freed",
			skip: func() string {
				if h.opt.fillDir == "" {
					return "QPOT_SOAK_FILL_DIR is not set (it must be a small filesystem that holds the instance)"
				}
				return ""
			},
			inject: func(context.Context) error {
				filler = filepath.Join(h.opt.fillDir, ".soak-filler")
				return fillFilesystem(filler, 0)
			},
			clear: func(context.Context) error { return os.Remove(filler) }},
	}
}

// fillFilesystem writes path until the filesystem holding it has at most
// leave bytes free (0: until nothing more can be written).
func fillFilesystem(path string, leave uint64) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	free := func() uint64 {
		var st syscall.Statfs_t
		if syscall.Statfs(filepath.Dir(path), &st) != nil {
			return 0
		}
		return st.Bavail * uint64(st.Bsize) // #nosec G115 -- block size of a mounted filesystem
	}
	block := make([]byte, 1<<20)
	for {
		if leave > 0 && free() <= leave+uint64(len(block)) {
			return nil
		}
		if _, err := f.Write(block); err != nil {
			if errors.Is(err, syscall.ENOSPC) {
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
}

// TestHiFiCapture runs live HiFi sessions through capture outages and counts
// the evidence afterwards.
func TestHiFiCapture(t *testing.T) {
	opt := loadOptions(t)
	if os.Getenv("QPOT_SOAK_HIFI") != "1" {
		t.Skip("set QPOT_SOAK_HIFI=1 (with QPOT_SOAK=1 and the local HiFi images) to run the HiFi capture soak; see doc/reliability.md")
	}
	tag := make([]byte, 4)
	if _, err := rand.Read(tag); err != nil {
		t.Fatal(err)
	}
	h := &hifiHarness{harness: &harness{t: t, opt: opt, tag: hex.EncodeToString(tag), childEnv: os.Environ()}}
	ctx := t.Context()
	if err := os.MkdirAll(opt.reportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	h.setupHiFi(ctx)
	if !opt.keep {
		t.Cleanup(func() {
			cctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			_, _ = h.qpot(cctx, 5*time.Minute, "down", "-i", opt.instance)
			if pid := h.servePID(); pid != 0 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			_, _ = h.qpot(cctx, 5*time.Minute, "instance", "remove", opt.instance)
		})
	}

	loadCtx, stopLoad := context.WithCancel(ctx)
	var loaders sync.WaitGroup
	loaders.Add(2)
	go func() { defer loaders.Done(); h.longSession(loadCtx) }()
	go func() { defer loaders.Done(); h.shortSessions(loadCtx) }()

	h.logf("warm-up: %s of sessions", opt.gap)
	time.Sleep(opt.gap)
	if d, why := h.settleHiFi(ctx, time.Now().Add(-15*time.Second), 6*time.Minute, true); d < 0 {
		t.Fatalf("the instance does not keep up before any fault: %s", why)
	}
	if base := h.accountHiFi(ctx, time.Now().Add(-15*time.Second), nil); base.Lost != 0 || base.StoredTwice != 0 || base.Executed == 0 {
		t.Fatalf("baseline is not clean (ran %d, lost %d, stored twice %d): the harness or the instance is broken before any fault", base.Executed, base.Lost, base.StoredTwice)
	} else {
		h.logf("baseline: %d commands ran, %d stored, none lost or stored twice", base.Executed, base.Stored)
	}

	all := h.hifiFaults()
	if len(opt.faults) > 0 {
		byName := map[string]fault{}
		for _, f := range all {
			byName[f.name] = f
		}
		all = nil
		for _, name := range opt.faults {
			f, ok := byName[strings.TrimSpace(name)]
			if !ok {
				t.Fatalf("QPOT_SOAK_FAULTS names %q, which is not a HiFi fault", name)
			}
			all = append(all, f)
		}
	}
	var results []hifiFault
	deadline := time.Now().Add(opt.duration)
	for round := 0; time.Now().Before(deadline); round++ {
		f := all[round%len(all)]
		if f.skip != nil {
			if why := f.skip(); why != "" {
				if round < len(all) {
					h.logf("skipping %s: %s", f.name, why)
					results = append(results, hifiFault{Name: f.name, What: f.what, Note: "skipped: " + why, RecoverySeconds: -1})
				}
				continue
			}
		}
		hold := opt.hold
		if f.hold > 0 {
			hold = f.hold
		}
		r := hifiFault{Name: f.name, What: f.what, Injected: time.Now()}
		h.logf("FAULT %s: %s (held %s)", f.name, f.what, hold)
		if err := f.inject(ctx); err != nil {
			r.Error = "inject: " + err.Error()
			h.logf("  inject failed: %v", err)
		}
		time.Sleep(hold)
		if err := f.clear(ctx); err != nil {
			r.Error = strings.TrimSpace(r.Error + " clear: " + err.Error())
			h.logf("  clear failed: %v", err)
		}
		r.Cleared = time.Now()
		r.HeldSeconds = r.Cleared.Sub(r.Injected).Seconds()
		d, why := h.settleHiFi(ctx, r.Cleared, 15*time.Minute, true)
		if d < 0 {
			r.RecoverySeconds, r.Note = -1, "not recovered within 15m: "+why
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
	h.logf("sessions stopped; waiting for the last recordings")
	h.settleHiFi(ctx, end, 10*time.Minute, false)
	time.Sleep(time.Minute)
	cleared, left := h.secondCopiesCleared(ctx, end, replayWaitMost)

	final := h.accountHiFi(ctx, end, results)
	final.Started, final.Ended = started, end
	final.CopiesClearedSeconds, final.SecondCopiesLeft = cleared, left
	final.Options = map[string]any{"duration": opt.duration.String(), "gap": opt.gap.String(), "hold": opt.hold.String(),
		"sandbox_mode": opt.sandbox, "cells": hifiBackends, "binary": filepath.Base(opt.bin)}
	if out, err := h.qpot(ctx, time.Minute, "--version"); err == nil {
		final.Options["version"] = strings.TrimSpace(out)
	}
	h.writeHiFi(final)

	if final.StoredTwice != 0 {
		t.Errorf("%d commands are stored more than once", final.StoredTwice)
	}
	if final.SecondCopiesLeft != 0 {
		t.Errorf("%d rows the collector sent again were still there %s after the last session", final.SecondCopiesLeft, replayWaitMost)
	}
	if final.Lost != 0 {
		t.Errorf("%d commands that ran in a cell never reached the database: %v", final.Lost, final.LostNumbers)
	}
	for _, f := range final.Faults {
		if f.RecoverySeconds < 0 && !strings.HasPrefix(f.Note, "skipped") {
			t.Errorf("%s: %s", f.Name, f.Note)
		}
		if f.AdmittedLate > 0 {
			t.Errorf("%s: %d logins were taken although the capture had been down for more than 45 s", f.Name, f.AdmittedLate)
		}
		if (f.Name == "long-stay" || f.Name == "long-outage" || f.Name == "hours-outage") && f.Error != "" {
			t.Errorf("%s: %s", f.Name, f.Error)
		}
	}
}

// accountHiFi compares what ran with what the database holds.
func (h *hifiHarness) accountHiFi(ctx context.Context, until time.Time, faults []hifiFault) hifiReport {
	counts, at, err := h.stored(ctx)
	if err != nil {
		h.t.Fatalf("final count: %v", err)
	}
	h.hmu.Lock()
	commands := append([]hifiCommand(nil), h.commands...)
	logins := append([]hifiLogin(nil), h.logins...)
	h.hmu.Unlock()
	r := hifiReport{Instance: h.opt.instance, Faults: faults}
	during := func(sent time.Time) *hifiFault {
		for i := range r.Faults {
			f := &r.Faults[i]
			if !f.Injected.IsZero() && !sent.Before(f.Injected) && !sent.After(f.Cleared) {
				return f
			}
		}
		return nil
	}
	for _, c := range commands {
		if c.Sent.After(until) {
			continue
		}
		r.Sent++
		n := counts[c.N]
		f := during(c.Sent)
		if n > 0 {
			r.Stored++
			if !c.Executed {
				r.NotExecutedStored++
			}
			if f != nil {
				if d := at[c.N].Sub(c.Sent).Seconds(); d > f.MaxDelaySeconds {
					f.MaxDelaySeconds = d
				}
			}
		}
		if n > 1 {
			r.StoredTwice++
			if f != nil {
				f.StoredTwice++
			}
			if r.StoredTwice <= describeMost {
				r.TwiceRows = append(r.TwiceRows, h.describe(ctx, c)...)
			}
		}
		if c.Executed {
			r.Executed++
			if f != nil {
				f.Executed++
			}
			if n == 0 {
				r.Lost++
				r.LostNumbers = append(r.LostNumbers, c.N)
				if f != nil {
					f.Lost++
				}
			}
		}
	}
	sort.Ints(r.LostNumbers)
	if len(r.LostNumbers) > 200 {
		r.LostNumbers = r.LostNumbers[:200]
	}
	for _, l := range logins {
		if l.Sent.After(until) {
			continue
		}
		r.Logins++
		if l.Admitted {
			r.Admitted++
		}
		if f := during(l.Sent); f != nil {
			if l.Admitted {
				f.Admitted++
				if strings.HasPrefix(f.Name, "capture-") && l.Sent.Sub(f.Injected) > 45*time.Second {
					f.AdmittedLate++
				}
			} else {
				f.Refused++
			}
		}
	}
	return r
}

// secondCopiesCleared waits until no event row shares its ID with another:
// the collector sends a record again after it lost its place, and the
// worker removes that copy when it comes to it. It returns how long after
// `end` that was, and how many copies were left when `limit` passed.
func (h *hifiHarness) secondCopiesCleared(ctx context.Context, end time.Time, limit time.Duration) (float64, int) {
	var (
		copies  uint64
		lastLog time.Time
	)
	for start := time.Now(); ; {
		qctx, cancel := context.WithTimeout(ctx, time.Minute)
		err := h.db.QueryRow(qctx, `SELECT toUInt64(count() - uniqExact(event_id)) FROM events`).Scan(&copies)
		cancel()
		if err == nil && copies == 0 {
			return time.Since(end).Seconds(), 0
		}
		if time.Since(start) >= limit {
			return time.Since(end).Seconds(), int(copies)
		}
		if time.Since(lastLog) >= 2*time.Minute {
			lastLog = time.Now()
			if err != nil {
				h.logf("  counting second copies: %s", firstLine(err.Error()))
			} else {
				h.logf("  %d rows are copies the worker has yet to remove", copies)
			}
		}
		select {
		case <-ctx.Done():
			return time.Since(end).Seconds(), int(copies)
		case <-time.After(10 * time.Second):
		}
	}
}

// describe lists the rows the database holds for one command.
func (h *hifiHarness) describe(ctx context.Context, c hifiCommand) []string {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out := []string{fmt.Sprintf("command %d sent %s (long session: %v)", c.N, c.Sent.UTC().Format("15:04:05.000"), c.Long)}
	rows, err := h.db.Query(ctx, `SELECT toString(timestamp), toString(event_id), metadata['cell'], metadata['generation'],
		metadata['capture_id'], metadata['observed_at'], metadata['stdout_file'] FROM events
		WHERE honeypot = 'ssh-proxy' AND event_type = ? AND command = ? ORDER BY timestamp`, hifiCommandEvent, "echo "+h.marker(c.N))
	if err != nil {
		return append(out, "  query: "+firstLine(err.Error()))
	}
	defer rows.Close()
	for rows.Next() {
		var at, id, cell, generation, capture, observed, file string
		if rows.Scan(&at, &id, &cell, &generation, &capture, &observed, &file) == nil {
			out = append(out, fmt.Sprintf("  stored %s id %s cell %s generation %s capture %s observed %s file %s", at, id, cell, generation, capture, observed, file))
		}
	}
	return out
}

func (h *hifiHarness) writeHiFi(r hifiReport) {
	base := filepath.Join(h.opt.reportDir, "hifi-"+h.tag)
	if data, err := json.MarshalIndent(r, "", "  "); err == nil {
		_ = os.WriteFile(base+".json", data, 0o644)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# HiFi capture soak %s\n\n", h.tag)
	fmt.Fprintf(&b, "%s to %s. Options: %v\n\n", r.Started.Format(time.RFC3339), r.Ended.Format(time.RFC3339), r.Options)
	fmt.Fprintf(&b, "Commands sent %d, ran in a cell %d, stored %d, lost %d, stored twice %d, stored without the client seeing output %d. Logins %d, taken %d.\n\n",
		r.Sent, r.Executed, r.Stored, r.Lost, r.StoredTwice, r.NotExecutedStored, r.Logins, r.Admitted)
	fmt.Fprintf(&b, "The worker had removed every row the collector sent again %.0f s after the last session; %d were left.\n\n",
		r.CopiesClearedSeconds, r.SecondCopiesLeft)
	b.WriteString("| Fault | Held (s) | Recovery (s) | Ran during | Lost | Stored twice | Logins taken / turned away | Taken late | Longest collection delay (s) | Note |\n|---|---|---|---|---|---|---|---|---|---|\n")
	for _, f := range r.Faults {
		fmt.Fprintf(&b, "| %s | %.0f | %.0f | %d | %d | %d | %d / %d | %d | %.0f | %s %s |\n", f.Name, f.HeldSeconds, f.RecoverySeconds,
			f.Executed, f.Lost, f.StoredTwice, f.Admitted, f.Refused, f.AdmittedLate, f.MaxDelaySeconds, f.Note, f.Error)
	}
	if len(r.TwiceRows) > 0 {
		b.WriteString("\nRows of commands stored more than once:\n\n```\n" + strings.Join(r.TwiceRows, "\n") + "\n```\n")
	}
	_ = os.WriteFile(base+".md", []byte(b.String()), 0o644)
	h.logf("report: %s.md", base)
	h.t.Log("\n" + b.String())
}
