package sshbackend

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxSessionBytes = 8 << 20
	maxUserLogBytes = 64 << 20
	maxLogFiles     = 2048
)

// SessionEvent is the bounded JSONL record consumed by the existing collector.
// Raw binary output is retained separately; a valid read-only broker context
// supplies the ingress source, while peer_ip preserves the daemon's actual peer.
type SessionEvent struct {
	Timestamp        string  `json:"timestamp"`
	EventType        string  `json:"event_type"`
	Phase            string  `json:"phase"`
	Session          string  `json:"session"`
	SessionID        string  `json:"session_id,omitempty"`
	Generation       *uint64 `json:"generation,omitempty"`
	PeerIP           string  `json:"peer_ip,omitempty"`
	PeerPort         int     `json:"peer_port,omitempty"`
	Attribution      string  `json:"attribution"`
	AttributionError string  `json:"attribution_error,omitempty"`
	Username         string  `json:"username"`
	UID              int     `json:"uid"`
	Hostname         string  `json:"hostname"`
	SrcIP            string  `json:"src_ip,omitempty"`
	SrcPort          int     `json:"src_port,omitempty"`
	Input            string  `json:"input,omitempty"`
	CommandTruncated bool    `json:"command_truncated,omitempty"`
	PTY              bool    `json:"pty"`
	ExitCode         *int    `json:"exit_code,omitempty"`
	DurationMS       int64   `json:"duration_ms"`
	StdoutFile       string  `json:"stdout_file"`
	StderrFile       string  `json:"stderr_file,omitempty"`
	InputFile        string  `json:"input_file,omitempty"`
	StdinRecorded    bool    `json:"stdin_recorded"`
	TimingFile       string  `json:"timing_file,omitempty"`
	Stdout           string  `json:"stdout,omitempty"`
	Stderr           string  `json:"stderr,omitempty"`
	Truncated        bool    `json:"truncated,omitempty"`
	CaptureError     string  `json:"capture_error,omitempty"`
}

type recordOptions struct {
	LogDir  string
	Command *string
	PTY     bool
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// Record executes the genuine shell/command and returns its real exit status.
// OpenSSH invokes this login shell with -c for exec, external subsystems, and
// authorized-key commands. The no-argument SSH_ORIGINAL_COMMAND convention is
// retained for older ForceCommand deployments. No command is re-quoted here.
func Record(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	var command *string
	if len(args) != 0 {
		if len(args) != 2 || args[0] != "-c" {
			return 126, errors.New("invalid login shell arguments")
		}
		command = &args[1]
	} else if value, ok := os.LookupEnv("SSH_ORIGINAL_COMMAND"); ok {
		command = &value
	}
	return record(recordOptions{LogDir: LogDirectory, Command: command, PTY: os.Getenv("SSH_TTY") != "", Stdin: stdin, Stdout: stdout, Stderr: stderr})
}

func record(opts recordOptions) (int, error) {
	start := time.Now()
	dir := filepath.Join(opts.LogDir, "uid-"+strconv.Itoa(os.Getuid()))
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return 126, fmt.Errorf("prepare private session directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || fileUID(info) != os.Getuid() {
		return 126, errors.New("session directory is not a private owned directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return 126, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return 126, err
	}
	id := hex.EncodeToString(random[:])
	prefix := filepath.Join(dir, start.UTC().Format("20060102T150405Z")+"-"+id)
	limit, release, err := reserveCapture(dir, filepath.Base(prefix))
	if err != nil {
		return 126, err
	}
	defer release()
	files := make(map[string]*os.File)
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	for _, suffix := range []string{"json", "out", "err", "in", "timing"} {
		file, err := os.OpenFile(prefix+"."+suffix, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return 126, err
		}
		files[suffix] = file
	}
	hostname, _ := os.Hostname()
	username := strconv.Itoa(os.Getuid())
	if current, err := user.Current(); err == nil {
		username = current.Username
	}
	event := SessionEvent{Timestamp: start.UTC().Format(time.RFC3339Nano), EventType: "ssh_backend_command", Session: id, Username: username, UID: os.Getuid(), Hostname: hostname, PTY: opts.PTY, StdoutFile: filepath.Base(prefix) + ".out", StderrFile: filepath.Base(prefix) + ".err", InputFile: filepath.Base(prefix) + ".in"}
	event.StdinRecorded = true
	if opts.PTY {
		event.TimingFile = filepath.Base(prefix) + ".timing"
	}
	if opts.Command != nil {
		event.Input = *opts.Command
		if len(event.Input) > 16<<10 {
			event.Input = event.Input[:16<<10]
			event.CommandTruncated = true
		}
	}
	parts := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(parts) == 4 && net.ParseIP(parts[0]) != nil {
		event.SrcIP = parts[0]
		event.SrcPort, _ = strconv.Atoi(parts[1])
	}
	attribute(&event, contextDirectory)
	// Persist the command before starting any child. Abrupt teardown retains
	// admission/input evidence without inventing a completed exit status.
	event.Phase = "start"
	event.EventType = "ssh_backend_command_start"
	if err := json.NewEncoder(files["json"]).Encode(event); err != nil {
		return 126, err
	}
	if err := files["json"].Sync(); err != nil {
		return 126, err
	}
	budget := &captureBudget{remaining: limit}
	var cmd *exec.Cmd
	var captureReaders []*os.File
	var captureWriters []*os.File
	var captureDone sync.WaitGroup
	var input *inputCapture
	if opts.PTY {
		for _, suffix := range []string{"in", "timing"} {
			reader, writer, err := os.Pipe()
			if err != nil {
				return 126, err
			}
			captureReaders = append(captureReaders, reader)
			captureWriters = append(captureWriters, writer)
			captureDone.Add(1)
			go func() {
				defer captureDone.Done()
				_, _ = io.Copy(&captureWriter{budget: budget, file: files[suffix]}, reader)
			}()
		}
		defer func() {
			for _, reader := range captureReaders {
				_ = reader.Close()
			}
			for _, writer := range captureWriters {
				_ = writer.Close()
			}
		}()
		args := []string{"-q", "-e", "-f", "--force", "--log-out", "/dev/null", "--log-in", "/proc/self/fd/3", "--log-timing", "/proc/self/fd/4"}
		command := "/bin/bash -l"
		if opts.Command != nil {
			command = *opts.Command
		}
		args = append(args, "-c", command)
		cmd = exec.Command("/usr/bin/script", args...)
		cmd.ExtraFiles = captureWriters
		event.StdinRecorded = true
		cmd.Stdin = opts.Stdin
		cmd.Stdout = io.MultiWriter(opts.Stdout, &captureWriter{budget: budget, file: files["out"]})
		cmd.Stderr = io.MultiWriter(opts.Stderr, &captureWriter{budget: budget, file: files["err"]})
		event.TimingFile = filepath.Base(prefix) + ".timing"
	} else {
		args := []string{"-l"}
		if opts.Command != nil {
			args = []string{"-c", *opts.Command}
		}
		cmd = exec.Command("/bin/bash", args...)
		input, err = prepareInputCapture(opts.Stdin, &captureWriter{budget: budget, file: files["in"]})
		if err != nil {
			return 126, err
		}
		defer input.stop()
		// Keep os/exec's stdin as a descriptor. Our separately cancellable pump
		// must not make Wait depend on a client sending EOF after child exit.
		cmd.Stdin = input.reader
		cmd.Stdout = io.MultiWriter(opts.Stdout, &captureWriter{budget: budget, file: files["out"]})
		cmd.Stderr = io.MultiWriter(opts.Stderr, &captureWriter{budget: budget, file: files["err"]})
	}
	// script uses SHELL to choose its command interpreter. The login shell is
	// this recorder, so select the genuine shell explicitly to avoid recursion.
	cmd.Env = shellEnvironment(os.Environ())
	cmd.WaitDelay = time.Second
	setProcessGroup(cmd, opts.PTY)
	code := 126
	if err = cmd.Start(); err == nil {
		if input != nil {
			input.start()
		}
		for _, writer := range captureWriters {
			_ = writer.Close()
		}
		signals := make(chan os.Signal, 8)
		signal.Notify(signals, processSignals()...)
		done := make(chan struct{})
		go func() {
			for {
				select {
				case sig := <-signals:
					forwardSignal(cmd, sig, opts.PTY)
				case <-done:
					return
				}
			}
		}()
		err = cmd.Wait()
		signal.Stop(signals)
		close(done)
		code = processExitCode(cmd.ProcessState)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			err = nil
		}
	}
	if input != nil {
		inputErr := input.stop()
		if inputErr != nil {
			budget.mu.Lock()
			budget.err = errors.Join(budget.err, inputErr)
			budget.truncated = true
			budget.mu.Unlock()
		}
	}
	for _, writer := range captureWriters {
		_ = writer.Close()
	}
	pipesDone := make(chan struct{})
	go func() { captureDone.Wait(); close(pipesDone) }()
	select {
	case <-pipesDone:
	case <-time.After(time.Second):
		for _, reader := range captureReaders {
			_ = reader.Close()
		}
		<-pipesDone
		budget.mu.Lock()
		budget.truncated = true
		budget.mu.Unlock()
	}
	event.EventType = "ssh_backend_command"
	event.Phase = "finish"
	event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	event.ExitCode = &code
	event.DurationMS = time.Since(start).Milliseconds()
	budget.mu.Lock()
	event.Truncated = budget.truncated
	captureErr := budget.err
	budget.mu.Unlock()
	if err != nil || captureErr != nil {
		event.CaptureError = errors.Join(err, captureErr).Error()
	}
	for _, suffix := range []string{"out", "err", "in", "timing"} {
		_ = files[suffix].Sync()
	}
	event.Stdout = preview(prefix + ".out")
	event.Stderr = preview(prefix + ".err")
	if opts.Command == nil {
		event.Input = preview(prefix + ".in")
	}
	if err := json.NewEncoder(files["json"]).Encode(event); err != nil {
		return code, fmt.Errorf("write session record: %w", err)
	}
	if err := files["json"].Sync(); err != nil {
		return code, err
	}
	return code, nil
}

func shellEnvironment(environ []string) []string {
	result := make([]string, 0, len(environ)+1)
	for _, value := range environ {
		if !strings.HasPrefix(value, "SHELL=") {
			result = append(result, value)
		}
	}
	return append(result, "SHELL=/bin/bash")
}

type inputCapture struct {
	reader   *os.File
	writer   *os.File
	source   io.Reader
	cancel   func()
	archive  io.Writer
	done     chan error
	stopOnce sync.Once
	err      error
}

func prepareInputCapture(source io.Reader, archive io.Writer) (*inputCapture, error) {
	var cancel func()
	switch value := source.(type) {
	case *os.File:
		var err error
		source, cancel, err = cancellableFileInput(value)
		if err != nil {
			return nil, fmt.Errorf("prepare cancellable stdin: %w", err)
		}
	case io.ReadCloser:
		cancel = func() { _ = value.Close() }
	case nil:
		source = strings.NewReader("")
		cancel = func() {}
	case *bytes.Buffer, *bytes.Reader, *strings.Reader:
		cancel = func() {}
	default:
		return nil, errors.New("stdin reader must support cancellation or be an in-memory reader")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		cancel()
		return nil, err
	}
	return &inputCapture{reader: reader, writer: writer, source: source, cancel: cancel, archive: archive}, nil
}

func (input *inputCapture) start() {
	_ = input.reader.Close()
	input.done = make(chan error, 1)
	go func() {
		_, err := io.Copy(input.writer, io.TeeReader(input.source, input.archive))
		_ = input.writer.Close()
		input.done <- err
	}()
}

func (input *inputCapture) stop() error {
	input.stopOnce.Do(func() {
		_ = input.reader.Close()
		_ = input.writer.Close()
		input.cancel()
		if input.done != nil {
			input.err = <-input.done
			if errors.Is(input.err, os.ErrClosed) || errors.Is(input.err, io.ErrClosedPipe) || inputPipeClosed(input.err) {
				input.err = nil
			}
		}
	})
	return input.err
}

type captureBudget struct {
	mu        sync.Mutex
	remaining int64
	truncated bool
	err       error
}
type captureWriter struct {
	budget *captureBudget
	file   *os.File
}

func (w *captureWriter) Write(data []byte) (int, error) {
	w.budget.mu.Lock()
	defer w.budget.mu.Unlock()
	n := len(data)
	keep := int64(n)
	if keep > w.budget.remaining {
		keep = w.budget.remaining
		w.budget.truncated = true
	}
	if keep > 0 {
		written, err := w.file.Write(data[:int(keep)])
		w.budget.remaining -= int64(written)
		if err != nil {
			w.budget.err = err
			w.budget.truncated = true
		}
	}
	// Capture exhaustion must not corrupt or block the real SSH byte stream.
	return n, nil
}
func preview(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, 4096))
	return string(data)
}
