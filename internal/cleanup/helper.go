package cleanup

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/vectorstate"
)

// Helper removes or empties files this process may not change. On Linux the
// honeypots' and the collector's own users own what they write, so a QPot
// running as an ordinary user (in the docker group) cannot empty their logs
// or remove the collector's backup days itself.
type Helper interface {
	// Remove removes the named files and folders, relative to dir.
	Remove(ctx context.Context, dir string, rels []string) error
	// Empty empties each named file, relative to dir, that still holds no
	// more than upTo[i] bytes (what the collector has delivered of it).
	Empty(ctx context.Context, dir string, rels []string, upTo []int64) error
	// FirstLines reads each named file's first line, newline included, as
	// the collector fingerprints it: nil for one it could not read or that
	// has no whole first line within the collector's longest line.
	FirstLines(ctx context.Context, dir string, rels []string) ([][]byte, error)
}

// helperBatch bounds the paths one helper container is given;
// firstLinesBatch those it reads first lines of (each up to 200 kB of
// output), and maxHelperOutput what is read back from one.
const (
	helperBatch     = 200
	firstLinesBatch = 16
	maxHelperOutput = 4 << 20
)

// helperTimeout bounds one helper container.
const helperTimeout = 2 * time.Minute

// emptyScript empties each file named in its arguments, given as pairs of a
// path and the most bytes it may hold: one written to since is left alone.
// stat and truncate run back to back, a few milliseconds apart.
const emptyScript = `rc=0
while [ "$#" -ge 2 ]; do
  if [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %s -- "$1")" -le "$2" ]; then
    truncate -c -s 0 -- "$1" || rc=1
  fi
  shift 2
done
exit "$rc"`

// firstLinesScript prints, one output line per file named in its arguments,
// the file's first line in hex (nothing for a file it cannot read), reading
// no more of it than the collector's longest line.
var firstLinesScript = vectorstate.FirstLinesScript

// DockerHelper does it in a short-lived container that mounts only dir, with
// no network, a read-only root and every capability dropped but the two that
// let its root change other users' files. dir is always a folder no honeypot
// can replace (a volume folder its container has mounted, or the backup
// folder), and the paths are resolved inside the container: a symlink a
// honeypot planted leads within that folder or into the helper's own
// throwaway filesystem, never anywhere else on the host.
type DockerHelper struct {
	// Image provides sh, stat, rm and truncate (the collector's image,
	// already pulled).
	Image string
	// Run runs docker with args and returns what it printed (nil: the
	// docker CLI).
	Run func(ctx context.Context, args ...string) ([]byte, error)
}

// Remove implements Helper.
func (d *DockerHelper) Remove(ctx context.Context, dir string, rels []string) error {
	_, err := d.do(ctx, dir, rels, helperBatch, nil, "rm", "-rf", "--")
	return err
}

// FirstLines implements Helper.
func (d *DockerHelper) FirstLines(ctx context.Context, dir string, rels []string) ([][]byte, error) {
	outs, err := d.do(ctx, dir, rels, firstLinesBatch, nil, "sh", "-c", firstLinesScript, "sh")
	if err != nil {
		return nil, err
	}
	lines := make([][]byte, 0, len(rels))
	for _, out := range outs {
		for _, h := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
			b, err := hex.DecodeString(h)
			if err != nil || len(b) == 0 {
				b = nil
			}
			lines = append(lines, b)
		}
	}
	if len(lines) != len(rels) {
		return nil, fmt.Errorf("cleanup helper: %d first lines for %d files", len(lines), len(rels))
	}
	return lines, nil
}

// Empty implements Helper.
func (d *DockerHelper) Empty(ctx context.Context, dir string, rels []string, upTo []int64) error {
	if len(upTo) != len(rels) {
		return fmt.Errorf("cleanup helper: %d sizes for %d files", len(upTo), len(rels))
	}
	_, err := d.do(ctx, dir, rels, helperBatch, func(i int) []string { return []string{strconv.FormatInt(upTo[i], 10)} },
		"sh", "-c", emptyScript, "sh")
	return err
}

// do runs cmd once per batch of rels, each path inside the container followed
// by extra(i) when extra is set, and returns what each run printed.
func (d *DockerHelper) do(ctx context.Context, dir string, rels []string, batch int, extra func(i int) []string, cmd ...string) ([][]byte, error) {
	if !filepath.IsAbs(dir) || strings.ContainsAny(dir, ",\n\x00") {
		return nil, fmt.Errorf("cleanup helper: %q cannot be mounted", dir)
	}
	run := d.Run
	if run == nil {
		run = dockerRun
	}
	var outs [][]byte
	for start := 0; start < len(rels); start += batch {
		end := min(len(rels), start+batch)
		args := []string{"run", "--rm", "--network", "none", "--read-only",
			"--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
			"--security-opt", "no-new-privileges", "--pids-limit", "16", "--memory", "64m",
			"--user", "0:0", "--mount", "type=bind,source=" + dir + ",target=/c",
			"--entrypoint", cmd[0], d.Image}
		args = append(args, cmd[1:]...)
		for i := start; i < end; i++ {
			rel := rels[i]
			if !filepath.IsLocal(filepath.FromSlash(rel)) || strings.ContainsRune(rel, 0) {
				return nil, fmt.Errorf("cleanup helper: %q is not a path inside %s", rel, dir)
			}
			args = append(args, "/c/"+rel)
			if extra != nil {
				args = append(args, extra(i)...)
			}
		}
		cctx, cancel := context.WithTimeout(ctx, helperTimeout)
		out, err := run(cctx, args...)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("cleanup helper (%s): %w", cmd[0], err)
		}
		outs = append(outs, out)
	}
	return outs, nil
}

// limitedBuffer keeps at most max bytes and reports what it dropped.
type limitedBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); len(p) > room {
		b.over = true
		p = p[:max(room, 0)]
	}
	b.Buffer.Write(p)
	return len(p), nil
}

func dockerRun(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	stdout := &limitedBuffer{max: maxHelperOutput}
	stderr := &limitedBuffer{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[len(msg)-300:]
		}
		return nil, fmt.Errorf("%w: %s", err, msg)
	}
	if stdout.over {
		return nil, fmt.Errorf("output over %d bytes", maxHelperOutput)
	}
	return stdout.Bytes(), nil
}

// SSHInventory reads only the native record tree, never identities or trusted
// contexts. It does not mutate files, and an incomplete/oversized response
// cannot authorize removal. The temporary helper remains network isolated.
func (d *DockerHelper) SSHInventory(ctx context.Context, dir string) ([]sshEvidenceFile, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || strings.ContainsAny(dir, ",\n\x00") {
		return nil, fmt.Errorf("cleanup helper: invalid native inventory root")
	}
	run := d.Run
	if run == nil {
		run = dockerRun
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := []string{"run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges", "--pids-limit", "16", "--memory", "64m", "--user", "0:0", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=1m", "--mount", "type=bind,source=" + dir + ",target=/c,readonly", "--entrypoint", "sh", d.Image, "-c", sshInventoryScript}
	out, err := run(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("SSH inventory helper: %w", err)
	}
	if len(out) > maxHelperOutput {
		return nil, fmt.Errorf("SSH inventory helper output limit reached")
	}
	return decodeSSHInventory(out)
}

// find never follows a symbolic link. Every entry consumes the finite budget;
// a directory at the depth bound, nonordinary object, or multiply linked file
// prevents a complete result. Paths and first lines use hex, so tabs, newlines
// and arbitrary guest-controlled filenames never change the record framing.
var sshInventoryScript = `set -eu
mkfifo /tmp/inventory
find /c -xdev -maxdepth 25 -print0 > /tmp/inventory &
scan=$!
 n=0
 while IFS= read -r -d '' f; do
   n=$((n+1)); [ "$n" -le ` + strconv.Itoa(maxSSHArchiveEntries) + ` ] || exit 71
   [ ! -L "$f" ] || continue
   rel="${f#/c/}"
   [ "$f" != /c ] || continue
   if [ -d "$f" ]; then
     depth="$(printf '%s' "$rel" | tr -cd / | wc -c)"
     [ "$depth" -lt 24 ] || exit 72
     continue
   fi
   [ -f "$f" ] || exit 73
   [ "$(stat -c %h -- "$f")" -eq 1 ] || exit 74
   stamp="$(stat -c '%d:%i:%s:%y:%z:%h:%F' -- "$f")"
   name="$(printf '%s' "$rel" | od -A n -v -t x1 | tr -d ' \n')"
   size="$(stat -c %s -- "$f")"
   blocks="$(stat -c %b -- "$f")"
   first=-
   case "$rel" in
     *.json) first="$(timeout 2 sh -ec '
       f="$1"; expected="$2"
       exec 3< "$f"
       [ "$(stat -Lc "%d:%i:%s:%y:%z:%h:%F" /proc/self/fd/3)" = "$expected" ]
       [ ! -L "$f" ]
       head -c ` + strconv.Itoa(vectorstate.MaxLine+1) + ` <&3 > /tmp/first
       [ "$(stat -Lc "%d:%i:%s:%y:%z:%h:%F" /proc/self/fd/3)" = "$expected" ]
       [ "$(stat -c "%d:%i:%s:%y:%z:%h:%F" -- "$f")" = "$expected" ]
       head -n 1 /tmp/first | od -A n -v -t x1 | tr -d " \n"
     ' sh "$f" "$stamp")" || exit 75 ;;
   esac
   [ "$(stat -c '%d:%i:%s:%y:%z:%h:%F' -- "$f")" = "$stamp" ] || exit 76
   printf '%s %s %s %s\n' "$name" "$size" "$blocks" "$first"
 done < /tmp/inventory
 wait "$scan"
 echo complete
`
