package instance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/vectorstate"
)

// TestCollectorLogReaderLive runs the real log reader against a honeypot's
// log folder as Docker leaves it on Linux: the log belongs to the container's
// user and this process may not open it. That is the state of an instance
// QPot 1.0.1 ran, whose collector kept no checkpoints: without marking those
// logs as collected, the upgraded collector stored every old event again.
func TestCollectorLogReaderLive(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a log this process may not read")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker not available")
	}
	if exec.Command(docker, "image", "inspect", CollectorImage).Run() != nil {
		t.Skip("collector image not present locally")
	}
	data := t.TempDir()
	logs := filepath.Join(data, "honeypots", "cowrie", "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	const own = "{\"own\":1}\n{\"own\":2}\n"
	if err := os.WriteFile(filepath.Join(logs, "own.log"), []byte(own), 0o644); err != nil {
		t.Fatal(err)
	}
	// What a container's user leaves: a log only it may read, a folder only
	// it may enter, a recording the collector never reads, a file without a
	// whole first line and a link out of the folder.
	const theirs = `{"eventid":"cowrie.session.connect","n":1}` + "\n" + `{"eventid":"cowrie.session.connect","n":2}` + "\n"
	script := `set -e
cd /c
printf '%s' "$1" > cowrie.json
mkdir -p private tty
printf '{"deep":1}\n' > private/deep.json
printf 'recording\n' > tty/rec.log
printf '{"no newline"' > partial.json
ln -s /etc/hostname link.json
chown -R 2000:2000 cowrie.json private tty partial.json
chmod 0640 cowrie.json partial.json
chmod 0700 private`
	uid, gid := os.Getuid(), os.Getgid()
	t.Cleanup(func() {
		out, err := exec.Command(docker, "run", "--rm", "--network", "none", "--user", "0:0", "--entrypoint", "chown",
			"-v", logs+":/c", CollectorImage, "-R", fmt.Sprintf("%d:%d", uid, gid), "/c").CombinedOutput()
		if err != nil {
			t.Logf("hand the files back: %v %s", err, out)
		}
	})
	if out, err := exec.Command(docker, "run", "--rm", "--network", "none", "--user", "0:0", "--entrypoint", "sh",
		"-v", logs+":/c", CollectorImage, "-c", script, "sh", theirs).CombinedOutput(); err != nil {
		t.Fatalf("prepare the folder: %v %s", err, out)
	}
	if _, err := os.ReadFile(filepath.Join(logs, "cowrie.json")); err == nil {
		t.Skip("this process may read another user's 0640 file here")
	}

	src := vectorstate.Source{Name: vectorstate.HoneypotSource("cowrie"), Dir: "honeypots/cowrie/logs", Read: func(rel string) bool {
		if rel == "tty" || strings.HasPrefix(rel, "tty/") {
			return false
		}
		return strings.HasSuffix(rel, ".log") || strings.HasSuffix(rel, ".json")
	}}
	files, err := collectorLogReader(logs, src.Read)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]vectorstate.LogFile{}
	for _, f := range files {
		got[f.Rel] = f
	}
	for rel, want := range map[string]string{"own.log": own, "cowrie.json": theirs, "private/deep.json": "{\"deep\":1}\n"} {
		f, ok := got[rel]
		first := want[:strings.IndexByte(want, '\n')+1]
		if !ok || f.Size != int64(len(want)) || string(f.FirstLine) != first {
			t.Errorf("%s: found %v, size %d, first line %q; want size %d, first line %q", rel, ok, f.Size, f.FirstLine, len(want), first)
		}
	}
	if f, ok := got["partial.json"]; !ok || f.FirstLine != nil {
		t.Errorf("a log without a whole first line: found %v, first line %q", ok, f.FirstLine)
	}
	for _, rel := range []string{"tty/rec.log", "link.json"} {
		if _, ok := got[rel]; ok {
			t.Errorf("%s was listed", rel)
		}
	}

	// Seeding now covers all three logs; without the reader it refuses.
	if _, err := vectorstate.Seed(data, src, time.Now(), nil); err == nil {
		t.Fatal("seeding without the reader did not fail")
	}
	n, err := vectorstate.Seed(data, src, time.Now(), collectorLogReader)
	if err != nil || n != 3 {
		t.Fatalf("Seed = %d %v, want the three logs", n, err)
	}
	delivered := vectorstate.Load(data, src.Name)
	fp, _ := vectorstate.Fingerprint(strings.NewReader(theirs))
	if delivered[fp] != int64(len(theirs)) {
		t.Errorf("the container's log is marked collected up to %d, want its size %d", delivered[fp], len(theirs))
	}
}
