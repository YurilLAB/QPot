package hostsetup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout bounds a command that does not set its own.
const DefaultTimeout = 2 * time.Minute

// Command is one external command setup runs. Every command has a time limit.
type Command struct {
	Args        []string      // program and arguments
	Env         []string      // extra KEY=value pairs
	Root        bool          // needs administrator rights (run through sudo when not root)
	Timeout     time.Duration // 0 means DefaultTimeout
	Interactive bool          // connect it to the terminal (installers that ask their own questions)
	// Detached: it starts a program that keeps running (Docker Desktop).
	// The command gets no output pipes, which that program would inherit
	// and hold open, so waiting for the command would wait for it.
	Detached bool
}

// Result is what a command did.
type Result struct {
	Exit     int // exit status; -1 when it did not start or was killed
	Stdout   []byte
	Stderr   []byte
	TimedOut bool
	Canceled bool
	Err      error // the start or wait error, if any
}

// OK reports a zero exit status.
func (r Result) OK() bool { return r.Err == nil && r.Exit == 0 }

// Combined returns stdout and stderr together, for messages.
func (r Result) Combined() string {
	return strings.TrimSpace(string(r.Stdout) + "\n" + string(r.Stderr))
}

// Runner runs commands. Tests use ExecRunner with fake programs on PATH.
type Runner interface {
	Run(ctx context.Context, c Command) Result
	// Argv is the exact command line Run executes for c, for showing it.
	Argv(c Command) []string
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct {
	EUID    int    // the effective user ID; 0 runs root commands directly
	Sudo    string // path of sudo, "" when it is not installed
	NoTTY   bool   // there is no terminal: use `sudo -n` so sudo never waits for a password
	PathEnv string // PATH for the commands; "" keeps the current one
	Log     io.Writer
	Stdin   io.Reader // for Interactive commands
	Stdout  io.Writer
	Stderr  io.Writer
	// Stream, when set, also gets every command's output as it runs
	// (qpot setup --verbose).
	Stream io.Writer
	// Grace is how long a command gets to stop after an interrupt before it
	// is killed (package managers must not be killed mid-write if avoidable).
	Grace time.Duration
}

// maxCapture bounds the output kept from one command (the tail is kept).
const maxCapture = 256 << 10

// Argv returns the exact command line for c: extra variables are set with
// `env` (sudo would otherwise drop them), and the whole line runs under sudo
// when it needs root and this is not root.
func (r *ExecRunner) Argv(c Command) []string {
	var argv []string
	if c.Root && r.EUID != 0 {
		argv = append(argv, "sudo")
		if r.NoTTY {
			argv = append(argv, "-n")
		}
	}
	if len(c.Env) > 0 {
		argv = append(append(argv, "env"), c.Env...)
	}
	return append(argv, c.Args...)
}

// Run runs c and waits for it, within its time limit and ctx.
func (r *ExecRunner) Run(ctx context.Context, c Command) Result {
	if len(c.Args) == 0 {
		return Result{Exit: -1, Err: errors.New("empty command")}
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	argv := r.Argv(c)
	name := argv[0]
	if name == "sudo" && r.Sudo != "" {
		name = r.Sudo
	}
	cmd := exec.CommandContext(cctx, name, argv[1:]...) // #nosec G204 -- argv is built by setup from fixed programs and validated values
	env := os.Environ()
	if r.PathEnv != "" {
		env = append(env, "PATH="+r.PathEnv)
	}
	cmd.Env = env
	if r.PathEnv != "" {
		if p, ok := lookPathIn(name, r.PathEnv); ok {
			cmd.Path = p
			cmd.Err = nil
		}
	}
	grace := r.Grace
	if grace <= 0 {
		grace = 20 * time.Second
	}
	cmd.Cancel = func() error {
		if err := interruptProcess(cmd.Process); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = grace

	var stdout, stderr tailBuffer
	if r.Log != nil {
		_, _ = io.WriteString(r.Log, "\n$ "+ShellJoin(argv)+"\n")
	}
	switch {
	case c.Detached:
		// Stdin, Stdout and Stderr stay nil: the null device.
	case c.Interactive:
		cmd.Stdin, cmd.Stdout, cmd.Stderr = r.Stdin, r.Stdout, r.Stderr
	default:
		outWs, errWs := []io.Writer{&stdout}, []io.Writer{&stderr}
		if r.Log != nil {
			lw := &lockedWriter{w: r.Log}
			outWs, errWs = append(outWs, lw), append(errWs, lw)
		}
		if r.Stream != nil {
			sw := &lockedWriter{w: r.Stream}
			outWs, errWs = append(outWs, sw), append(errWs, sw)
		}
		outW, errW := io.MultiWriter(outWs...), io.MultiWriter(errWs...)
		cmd.Stdout, cmd.Stderr = outW, errW
	}
	err := cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Err: err}
	if cmd.ProcessState != nil {
		res.Exit = cmd.ProcessState.ExitCode()
	} else {
		res.Exit = -1
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.Err = nil // a non-zero exit is reported through Exit
	}
	switch {
	case ctx.Err() != nil:
		res.Canceled = true
	case cctx.Err() == context.DeadlineExceeded:
		res.TimedOut = true
	}
	if res.Exit != 0 && res.Err == nil && (res.Canceled || res.TimedOut) {
		res.Err = cctx.Err()
	}
	if r.Log != nil {
		_, _ = io.WriteString(r.Log, "(exit "+strconv.Itoa(res.Exit)+")\n")
	}
	return res
}

// lookPathIn finds an executable called name in the PATH list path, without
// touching this process's own PATH.
func lookPathIn(name, path string) (string, bool) {
	if strings.ContainsRune(name, os.PathSeparator) || strings.ContainsRune(name, '/') {
		return name, true
	}
	exts := []string{""}
	if runtime.GOOS == "windows" {
		exts = []string{".exe", ".bat", ".cmd", ""}
	}
	for _, dir := range filepath.SplitList(path) {
		for _, ext := range exts {
			p := filepath.Join(dir, name+ext)
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() &&
				(runtime.GOOS == "windows" || fi.Mode()&0o111 != 0) {
				return p, true
			}
		}
	}
	return "", false
}

// tailBuffer keeps the last maxCapture bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > maxCapture {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-maxCapture:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) Bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return bytes.Clone(t.buf)
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// ShellJoin quotes argv so the line can be pasted into a POSIX shell.
func ShellJoin(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = shellQuote(a)
	}
	return strings.Join(out, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=,+@%", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// LastLines returns the last n non-empty lines of s, for error details.
func LastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	var keep []string
	for i := len(lines) - 1; i >= 0 && len(keep) < n; i-- {
		if l := strings.TrimRight(lines[i], "\r "); strings.TrimSpace(l) != "" {
			keep = append([]string{l}, keep...)
		}
	}
	return strings.Join(keep, "\n")
}
