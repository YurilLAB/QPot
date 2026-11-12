package instance

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/vectorstate"
)

// Bounds on what the log reader lists and reads back.
const (
	seedMaxFiles   = 100_000
	seedMaxDepth   = 24
	seedLinesBatch = 16 // first lines per helper run: each is up to 200 kB of hex
)

// seedListScript prints "<size> <path>" for every regular file named *.log
// or *.json under /c (no collector source reads anything else), never
// following a symlink, and one line more than the limit when there are more.
var seedListScript = `find /c -maxdepth ` + strconv.Itoa(seedMaxDepth+1) + ` -type f \( -name '*.log' -o -name '*.json' \) -exec stat -c '%s %n' -- {} + | head -n ` + strconv.Itoa(seedMaxFiles+1)

// collectorLogReader lists a collector source's logs and reads their first
// lines as root in short-lived containers that mount only that folder, read
// only, with no network and only the capability to read other users' files.
// It is a variable so tests can stand in. It uses the collector's image,
// which `qpot up` needs in any case; Docker pulls it when it is not there yet.
var collectorLogReader vectorstate.Privileged = func(dir string, read func(rel string) bool) ([]vectorstate.LogFile, error) {
	if !filepath.IsAbs(dir) || strings.ContainsAny(dir, ",\n\x00") {
		return nil, fmt.Errorf("folder %q cannot be mounted", dir)
	}
	run := func(timeout time.Duration, script string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		full := append([]string{"run", "--rm", "--network", "none", "--read-only",
			"--cap-drop", "ALL", "--cap-add", "DAC_READ_SEARCH",
			"--security-opt", "no-new-privileges", "--pids-limit", "32", "--memory", "128m",
			"--user", "0:0", "--mount", "type=bind,source=" + dir + ",target=/c,readonly",
			"--entrypoint", "sh", CollectorImage, "-c", script, "sh"}, args...)
		cmd := exec.CommandContext(ctx, "docker", full...) // #nosec G204 -- fixed program, image and scripts; dir is checked above and the paths come from the listing
		out, err := cmd.Output()
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return nil, fmt.Errorf("log reader container: %w: %s", err, firstLineOf(exit.Stderr))
			}
			return nil, fmt.Errorf("log reader container: %w", err)
		}
		return out, nil
	}
	// The first run may have to pull the image.
	listing, err := run(15*time.Minute, seedListScript)
	if err != nil {
		return nil, err
	}
	var files []vectorstate.LogFile
	for _, line := range strings.Split(strings.TrimSuffix(string(listing), "\n"), "\n") {
		size, name, ok := strings.Cut(line, " ")
		rel, inside := strings.CutPrefix(name, "/c/")
		n, perr := strconv.ParseInt(size, 10, 64)
		// A name with a newline in it comes out as lines that do not parse
		// or do not name a file below the folder: such a log is left out,
		// and the collector reads it from its start.
		if !ok || !inside || perr != nil || n < 0 || !filepath.IsLocal(filepath.FromSlash(rel)) || !read(rel) {
			continue
		}
		files = append(files, vectorstate.LogFile{Rel: rel, Size: n})
	}
	if len(files) > seedMaxFiles {
		return nil, fmt.Errorf("more than %d logs in %s", seedMaxFiles, dir)
	}
	for start := 0; start < len(files); start += seedLinesBatch {
		end := min(start+seedLinesBatch, len(files))
		args := make([]string, 0, end-start)
		for _, f := range files[start:end] {
			args = append(args, "/c/"+f.Rel)
		}
		out, err := run(2*time.Minute, vectorstate.FirstLinesScript, args...)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
		if len(lines) != end-start {
			return nil, fmt.Errorf("log reader container: %d first lines for %d logs", len(lines), end-start)
		}
		for i, h := range lines {
			// A whole first line ends in its newline; a log still without one
			// has no fingerprint yet.
			if b, err := hex.DecodeString(h); err == nil && len(b) > 0 && b[len(b)-1] == '\n' {
				files[start+i].FirstLine = b
			}
		}
	}
	return files, nil
}
