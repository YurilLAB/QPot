package instance

// scrub.go removes the QPot ID from log backups written by earlier versions.
//
// Until this change the collector stamped the QPot ID - the API credential -
// into every event, so each line of backup/logs/<date>/<honeypot>.log carries
// it. The collector no longer has the ID; this replaces what it already wrote
// with the sensor ID, which has the same length and is not a credential (see
// config.SensorIDFor). It runs once per instance, at `qpot up`, with the
// collector stopped so no file is open while it is rewritten.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// scrubMarker records, in the instance folder, that the backups were checked.
const scrubMarker = ".backup-credential-scrubbed"

// scrubHelperTimeout bounds the helper container that rewrites backups this
// process may not change.
const scrubHelperTimeout = 10 * time.Minute

// scrubHelperScript reads the two IDs from its input, never from its
// arguments or environment, where `ps` and `docker inspect` would show them.
// It rewrites only regular files, in /c (the backup folder alone is mounted).
const scrubHelperScript = `IFS= read -r old; IFS= read -r new
[ ${#old} -eq 27 ] && [ ${#new} -eq 27 ] || exit 64
find /c -type f -name '*.log' -exec grep -lF -- "$old" {} + | while IFS= read -r f; do
  sed -i "s/$old/$new/g" "$f" || exit 65
done`

// scrubHelper runs the helper container; a variable so tests can stand in.
var scrubHelper = func(ctx context.Context, dir, oldID, newID string) error {
	if !filepath.IsAbs(dir) || strings.ContainsAny(dir, ",\n\x00") {
		return fmt.Errorf("backup folder %q cannot be mounted", dir)
	}
	ctx, cancel := context.WithTimeout(ctx, scrubHelperTimeout)
	defer cancel()
	// As internal/cleanup's helper: no network, read-only root, only the
	// capabilities that let its root rewrite the collector's files.
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--network", "none", "--read-only",
		"--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--cap-add", "CHOWN",
		"--security-opt", "no-new-privileges", "--pids-limit", "32", "--memory", "128m",
		"--user", "0:0", "--mount", "type=bind,source="+dir+",target=/c",
		"--entrypoint", "sh", CollectorImage, "-c", scrubHelperScript)
	cmd.Stdin = strings.NewReader(oldID + "\n" + newID + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[len(msg)-300:]
		}
		return fmt.Errorf("backup scrub helper: %w: %s", err, msg)
	}
	return nil
}

// scrubStopCollector stops the collector so no backup file is open; a
// variable so tests can stand in. A collector that does not exist yet is
// not an error.
var scrubStopCollector = func(ctx context.Context, cfg *config.Config) error {
	if _, err := os.Stat(cfg.GetDockerComposePath()); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", cfg.GetDockerComposePath(), "stop", "--timeout", "20", "collector")
	cmd.Dir = cfg.DataPath
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("stop the collector: %w: %s", err, firstLineOf(out))
	}
	return nil
}

func firstLineOf(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// backupScan is what one pass over the backup folder found.
type backupScan struct {
	carrying []string // files, relative to the folder, that contain the ID
	unread   int      // files that could not be read
}

// scanBackups lists the backup logs that contain id. It walks inside an
// os.Root, so nothing outside the backup folder is ever opened.
func scanBackups(root *os.Root, id string) (backupScan, error) {
	var scan backupScan
	needle := []byte(id)
	err := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				scan.unread++
				return nil
			}
			return err
		}
		if !d.Type().IsRegular() || !strings.HasSuffix(p, ".log") {
			return nil
		}
		has, err := fileContains(root, p, needle)
		switch {
		case errors.Is(err, fs.ErrPermission):
			scan.unread++
		case err != nil:
			return err
		case has:
			scan.carrying = append(scan.carrying, p)
		}
		return nil
	})
	return scan, err
}

// fileContains reports whether the file holds needle, reading it in pieces
// that overlap by the needle's length.
func fileContains(root *os.Root, rel string, needle []byte) (bool, error) {
	f, err := root.Open(rel)
	if err != nil {
		return false, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	buf := make([]byte, 0, (1<<20)+len(needle))
	for {
		chunk := buf[len(buf):cap(buf)]
		n, err := r.Read(chunk[:cap(buf)-len(buf)])
		buf = buf[:len(buf)+n]
		if bytes.Contains(buf, needle) {
			return true, nil
		}
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if keep := len(needle) - 1; len(buf) > keep {
			copy(buf, buf[len(buf)-keep:])
			buf = buf[:keep]
		}
	}
}

// overwriteInFile replaces every oldID in the file with newID where it
// stands. The two have the same length, so no byte moves and the file is
// never truncated or renamed.
func overwriteInFile(root *os.Root, rel string, oldID, newID []byte) error {
	if len(oldID) != len(newID) {
		return fmt.Errorf("replacement is not the length of what it replaces")
	}
	f, err := root.OpenFile(rel, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	const window = 1 << 20
	buf := make([]byte, window+len(oldID))
	var offset int64
	carry := 0
	for {
		n, err := f.ReadAt(buf[carry:], offset+int64(carry))
		have := carry + n
		for i := 0; ; {
			j := bytes.Index(buf[i:have], oldID)
			if j < 0 {
				break
			}
			if _, werr := f.WriteAt(newID, offset+int64(i+j)); werr != nil {
				return werr
			}
			copy(buf[i+j:], newID)
			i += j + len(oldID)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		keep := min(len(oldID)-1, have)
		copy(buf, buf[have-keep:have])
		offset += int64(have - keep)
		carry = keep
	}
	return f.Sync()
}

// BackupsScrubbed reports whether this instance's log backups have been
// checked for the QPot ID (always true for an instance created after the
// collector stopped stamping it).
func BackupsScrubbed(cfg *config.Config) bool {
	_, err := os.Stat(filepath.Join(cfg.DataPath, scrubMarker))
	return err == nil
}

// scrubLogBackups replaces the QPot ID in this instance's log backups with
// its sensor ID, once. It is called with the deployment lock held, before
// `compose up`: the collector it stops is started again by that.
func (m *Manager) scrubLogBackups(ctx context.Context) error {
	cfg := m.config
	if cfg.QPotID == "" || BackupsScrubbed(cfg) {
		return nil
	}
	done := func() error {
		return os.WriteFile(filepath.Join(cfg.DataPath, scrubMarker),
			[]byte("log backups carry the sensor ID, not the QPot ID\n"), 0o600)
	}
	dir := filepath.Join(cfg.DataPath, "backup")
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return done()
	}
	if err != nil {
		return err
	}
	defer root.Close()
	scan, err := scanBackups(root, cfg.QPotID)
	if err != nil {
		return err
	}
	if len(scan.carrying) == 0 && scan.unread == 0 {
		return done()
	}
	slog.Info("Removing the QPot ID from log backups an earlier version wrote",
		"files", len(scan.carrying), "unreadable", scan.unread)
	if err := scrubStopCollector(ctx, cfg); err != nil {
		return err
	}
	sensor := cfg.SensorID()
	needHelper := scan.unread > 0
	for _, rel := range scan.carrying {
		err := overwriteInFile(root, rel, []byte(cfg.QPotID), []byte(sensor))
		switch {
		case errors.Is(err, fs.ErrPermission):
			needHelper = true // the collector's root wrote it
		case err != nil:
			return fmt.Errorf("rewrite backup %s: %w", rel, err)
		}
	}
	if needHelper {
		if runtime.GOOS == "windows" {
			return fmt.Errorf("log backups under %s cannot be rewritten by this account", dir)
		}
		if err := scrubHelper(ctx, dir, cfg.QPotID, sensor); err != nil {
			return err
		}
	}
	after, err := scanBackups(root, cfg.QPotID)
	if err != nil {
		return err
	}
	if len(after.carrying) != 0 || after.unread != 0 {
		return fmt.Errorf("%d log backups under %s still carry the QPot ID (%d unreadable)", len(after.carrying), dir, after.unread)
	}
	return done()
}
