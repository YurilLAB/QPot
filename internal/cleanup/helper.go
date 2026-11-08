package cleanup

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Helper removes or empties files this process may not change. On Linux the
// honeypots' and the collector's own users own what they write, so a QPot
// running as an ordinary user (in the docker group) cannot empty their logs
// or remove the collector's backup days itself.
type Helper interface {
	// Remove removes the named files and folders, relative to dir.
	Remove(ctx context.Context, dir string, rels []string) error
	// Empty empties the named files, relative to dir.
	Empty(ctx context.Context, dir string, rels []string) error
}

// helperBatch bounds the paths one helper container is given.
const helperBatch = 200

// helperTimeout bounds one helper container.
const helperTimeout = 2 * time.Minute

// DockerHelper does it in a short-lived container that mounts only dir, with
// no network, a read-only root and every capability dropped but the two that
// let its root change other users' files. dir is always a folder no honeypot
// can replace (a volume folder its container has mounted, or the backup
// folder), and the paths are resolved inside the container: a symlink a
// honeypot planted leads within that folder or into the helper's own
// throwaway filesystem, never anywhere else on the host.
type DockerHelper struct {
	// Image provides rm and truncate (the collector's image, already pulled).
	Image string
	// Run runs docker with args (nil: the docker CLI).
	Run func(ctx context.Context, args ...string) error
}

// Remove implements Helper.
func (d *DockerHelper) Remove(ctx context.Context, dir string, rels []string) error {
	return d.do(ctx, dir, "rm", []string{"-rf", "--"}, rels)
}

// Empty implements Helper.
func (d *DockerHelper) Empty(ctx context.Context, dir string, rels []string) error {
	return d.do(ctx, dir, "truncate", []string{"-c", "-s", "0", "--"}, rels)
}

func (d *DockerHelper) do(ctx context.Context, dir, tool string, flags, rels []string) error {
	if !filepath.IsAbs(dir) || strings.ContainsAny(dir, ",\n\x00") {
		return fmt.Errorf("cleanup helper: %q cannot be mounted", dir)
	}
	run := d.Run
	if run == nil {
		run = dockerRun
	}
	for start := 0; start < len(rels); start += helperBatch {
		batch := rels[start:min(len(rels), start+helperBatch)]
		args := []string{"run", "--rm", "--network", "none", "--read-only",
			"--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
			"--security-opt", "no-new-privileges", "--pids-limit", "16", "--memory", "64m",
			"--user", "0:0", "--mount", "type=bind,source=" + dir + ",target=/c",
			"--entrypoint", tool, d.Image}
		args = append(args, flags...)
		for _, rel := range batch {
			if !filepath.IsLocal(filepath.FromSlash(rel)) || strings.ContainsRune(rel, 0) {
				return fmt.Errorf("cleanup helper: %q is not a path inside %s", rel, dir)
			}
			args = append(args, "/c/"+rel)
		}
		cctx, cancel := context.WithTimeout(ctx, helperTimeout)
		err := run(cctx, args...)
		cancel()
		if err != nil {
			return fmt.Errorf("cleanup helper (%s): %w", tool, err)
		}
	}
	return nil
}

func dockerRun(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[len(msg)-300:]
		}
		return fmt.Errorf("%w: %s", err, msg)
	}
	return nil
}
