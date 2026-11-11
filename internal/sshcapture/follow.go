package sshcapture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// AuthLog is the name of sshd's own log beside the command records.
const AuthLog = "sshd.log"

// maxLogLine bounds one line of sshd's error stream; longer lines are skipped.
const maxLogLine = 64 << 10

// maxAuthLog bounds sshd's own log kept for one container. A password-guessing
// flood fills it honestly, and guest root can write to sshd's error stream;
// past the limit one note says the rest was not kept.
const maxAuthLog = 32 << 20

// authLogFull is the note that ends a full sshd log.
const authLogFull = "qpot: sshd log limit reached; its later lines were not kept\n"

// writeAuthLine appends one sshd log line while the container's log stays
// within maxAuthLog; written counts what this replay has kept so far.
func writeAuthLine(f *os.File, line []byte, written *int64) {
	if *written >= maxAuthLog {
		return
	}
	if *written+int64(len(line)) > maxAuthLog {
		_, _ = f.WriteString(authLogFull)
		*written = maxAuthLog
		return
	}
	_, _ = f.Write(line)
	*written += int64(len(line))
}

// Target is one backend service whose capture is converted.
type Target struct {
	Service   string
	Container string                 // Docker container name
	Dir       func() (string, error) // the service's current log folder
	Attribute Attributor
}

// Stream opens a container's log. sshd runs with -e, so its error stream
// carries its own log lines and, between them, the capture records; its
// output stream carries nothing of sshd's and is discarded. With follow it
// runs until the container stops.
type Stream func(ctx context.Context, id string, follow bool) (stdout, stderr io.ReadCloser, wait func() error, err error)

// Container is what Inspect reports about a container.
type Container struct {
	ID      string
	Created time.Time
	Running bool
}

// Inspect reports a container. A missing container has an empty ID and no
// error.
type Inspect func(ctx context.Context, name string) (Container, error)

// Lock serializes writers to the cell log folders with resets that archive
// them; it returns the release.
type Lock func(ctx context.Context) (func(), error)

// Retire stops a running container at once. The follower calls it when the
// container's capture is inside the reserve of a limit (Writer.Full): a
// backend that could soon run sessions without a record must stop serving.
// Its visitor's connection ends as on a host that went down, the broker has
// the cell recreated, and the visitor's next connection gets a fresh one.
type Retire func(ctx context.Context, id string) error

// Converter reads backend captures through Docker and writes evidence files.
type Converter struct {
	Stream  Stream
	Inspect Inspect
	Lock    Lock
	Retire  Retire // nil: a full capture is only reported
	Poll    time.Duration
	Logger  *slog.Logger
}

// DockerConverter uses the docker CLI.
func DockerConverter(lock Lock) *Converter {
	return &Converter{Stream: dockerStream, Inspect: dockerInspect, Lock: lock, Retire: dockerKill, Poll: 2 * time.Second, Logger: slog.Default()}
}

// Follow converts the target's capture while its containers run, until ctx
// ends. Each container is replayed from its first line, so restarting the
// control plane never loses or duplicates evidence. A reset that drains and
// archives the folder ends that container's follow.
func (c *Converter) Follow(ctx context.Context, t Target) {
	done := map[string]bool{}
	for ctx.Err() == nil {
		ct, err := c.Inspect(ctx, t.Container)
		if err != nil || ct.ID == "" || (done[ct.ID] && !ct.Running) {
			sleep(ctx, c.Poll)
			continue
		}
		if err := c.follow(ctx, t, ct); err != nil && ctx.Err() == nil {
			c.Logger.Warn("SSH session capture interrupted", "service", t.Service, "error", err)
		}
		if now, err := c.Inspect(ctx, t.Container); err == nil && !now.Running {
			done[ct.ID] = true
		}
		sleep(ctx, c.Poll)
	}
}

func (c *Converter) follow(ctx context.Context, t Target, ct Container) error {
	dir, err := t.Dir()
	if err != nil {
		return err
	}
	identity, err := os.Stat(dir)
	if err != nil {
		return err
	}
	stdout, stderr, wait, err := c.Stream(ctx, ct.ID, true)
	if err != nil {
		return err
	}
	lines := streamLines(stdout, stderr)

	var out *Writer
	var authBytes int64
	authStarted, stale := false, false
	full, retired, warned := "", !ct.Running, false
	defer func() {
		if out != nil {
			out.Discard() // an error path: the next replay rewrites everything
		}
	}()
	apply := func(batch []streamLine, last bool) error {
		release, err := c.Lock(ctx)
		if err != nil {
			return err
		}
		defer release()
		if now, err := os.Stat(dir); err != nil || !os.SameFile(identity, now) {
			stale = true // drained and archived by a reset
			return nil
		}
		if out == nil {
			if out, err = NewWriter(dir, ct.ID, ct.Created, t.Attribute); err != nil {
				return err
			}
		}
		auth, err := openAuthLog(dir, authStarted)
		if err != nil {
			return err
		}
		authStarted = true
		defer auth.Close()
		for _, l := range batch {
			if l.record {
				if err := out.Apply(l.data); err != nil {
					return err
				}
			} else {
				writeAuthLine(auth, l.data, &authBytes)
			}
		}
		full = out.Full()
		if last {
			err := out.Finish()
			out = nil
			return err
		}
		// Hold nothing in the folder between batches: a reset archives it.
		return out.Flush()
	}
	// retire stops the container once its capture is inside a reserve. A
	// failure is tried again with the next lines the container writes.
	retire := func() {
		if full == "" || retired {
			return
		}
		if c.Retire == nil {
			retired = true
			c.Logger.Warn("An SSH cell is close to its capture limit; past it, its sessions leave no record", "service", t.Service, "limit", full)
			return
		}
		err := c.Retire(ctx, ct.ID)
		if err != nil {
			if now, ierr := c.Inspect(ctx, t.Container); ierr == nil && (now.ID != ct.ID || !now.Running) {
				err = nil // it stopped by itself, or a reset replaced it
			}
		}
		if err != nil {
			if !warned {
				warned = true
				c.Logger.Error("An SSH cell is close to its capture limit and could not be stopped; past the limit its sessions leave no record", "service", t.Service, "limit", full, "error", err)
			}
			return
		}
		retired = true
		c.Logger.Warn("An SSH cell came close to its capture limit and was stopped; its visitor's next connection gets a fresh cell", "service", t.Service, "limit", full)
	}
	var batch []streamLine
	for l := range lines {
		batch = append(batch, l)
		if len(lines) > 0 && len(batch) < 512 {
			continue
		}
		if !stale {
			if err := apply(batch, false); err != nil {
				_ = wait()
				return err
			}
			retire()
		}
		batch = batch[:0]
	}
	werr := wait()
	if stale {
		return nil
	}
	return errors.Join(apply(batch, true), werr)
}

// Drain replays a stopped container's whole capture into the target's folder.
// The caller holds the cells lock, so no follower writes meanwhile; the
// files are then complete for the archive that follows.
func (c *Converter) Drain(ctx context.Context, t Target) error {
	ct, err := c.Inspect(ctx, t.Container)
	if err != nil || ct.ID == "" {
		return err
	}
	dir, err := t.Dir()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	stdout, stderr, wait, err := c.Stream(ctx, ct.ID, false)
	if err != nil {
		return err
	}
	out, err := NewWriter(dir, ct.ID, ct.Created, t.Attribute)
	if err != nil {
		return errors.Join(err, wait())
	}
	auth, err := openAuthLog(dir, false)
	if err != nil {
		return errors.Join(err, out.Finish(), wait())
	}
	defer auth.Close()
	var applyErr error
	var authBytes int64
	for l := range streamLines(stdout, stderr) {
		if !l.record {
			writeAuthLine(auth, l.data, &authBytes)
		} else if applyErr == nil {
			applyErr = out.Apply(l.data)
		}
	}
	return errors.Join(applyErr, out.Finish(), wait())
}

// streamLine is one line of sshd's error stream: a capture record without
// its newline, or a log line with one.
type streamLine struct {
	data   []byte
	record bool
}

// streamLines reads the error stream and discards the output stream; the
// channel closes once both have ended.
func streamLines(stdout, stderr io.ReadCloser) <-chan streamLine {
	lines := make(chan streamLine, 256)
	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		_, _ = io.Copy(io.Discard, stdout)
		_ = stdout.Close()
	}()
	go readLines(stderr, lines, &readers)
	go func() { readers.Wait(); close(lines) }()
	return lines
}

// readLines splits sshd's error stream into lines and tells records from log
// lines. A record is one write ending in a bare newline; sshd ends each log
// line with a carriage return too, which no record may contain, so a log
// line never passes for a record. Lines longer than maxLogLine are skipped.
func readLines(r io.ReadCloser, out chan<- streamLine, done *sync.WaitGroup) {
	defer done.Done()
	defer r.Close()
	br := bufio.NewReaderSize(r, maxLogLine+1)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err != nil {
				return
			}
			continue
		}
		if len(line) > 0 {
			data := append([]byte(nil), line...)
			if err == nil {
				if _, perr := ParseRecord(data[:len(data)-1]); perr == nil {
					out <- streamLine{data: data[:len(data)-1], record: true}
					continue
				}
			} else {
				data = append(data, '\n') // a final line without its newline
			}
			out <- streamLine{data: data}
		}
		if err != nil {
			return
		}
	}
}

// openAuthLog opens sshd's log for writing: a replay rewrites it from the
// container's first line, later batches append.
func openAuthLog(dir string, appending bool) (*os.File, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if appending {
		flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}
	return root.OpenFile(AuthLog, flag, 0o600)
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func dockerStream(ctx context.Context, id string, follow bool) (io.ReadCloser, io.ReadCloser, func() error, error) {
	args := []string{"logs"}
	if follow {
		args = append(args, "--follow")
	}
	cmd := exec.CommandContext(ctx, "docker", append(args, "--", id)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}
	return stdout, stderr, cmd.Wait, nil
}

// dockerKill stops a container with SIGKILL. Docker does not restart a
// container killed through it, whatever its restart policy.
func dockerKill(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "kill", "--", id).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker kill: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func dockerInspect(ctx context.Context, name string) (Container, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--type", "container", "--format", "{{.Id}} {{.Created}} {{.State.Running}}", "--", name).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "No such") {
			return Container{}, nil
		}
		return Container{}, fmt.Errorf("inspect %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return parseInspect(name, string(out))
}

func parseInspect(name, out string) (Container, error) {
	fields := strings.Fields(out)
	if len(fields) != 3 || len(fields[0]) < 12 {
		return Container{}, fmt.Errorf("inspect %s: unexpected output", name)
	}
	created, err := time.Parse(time.RFC3339Nano, fields[1])
	if err != nil {
		return Container{}, fmt.Errorf("inspect %s: creation time: %w", name, err)
	}
	return Container{ID: fields[0], Created: created, Running: fields[2] == "true"}, nil
}
