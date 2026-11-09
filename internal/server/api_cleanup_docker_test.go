//go:build linux

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/qpot/qpot/internal/cleanup"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/security"
	"github.com/qpot/qpot/internal/vectorstate"
)

// writerScript runs as the honeypot's user and holds its log open for good,
// as a honeypot does. Asked through /ctl/burst, it writes that many lines of
// about 1.1 kB, numbered from 0, then says in /ctl/written how many it has
// written in all.
const writerScript = `exec 3>>/logs/cowrie.json
pad=$(head -c 1100 /dev/zero | tr '\0' x)
n=0
while :; do
  if [ -e /ctl/burst ]; then
    k=$(cat /ctl/burst); rm -f /ctl/burst
    i=0
    while [ "$i" -lt "$k" ]; do
      printf '{"eventid":"cowrie.command.input","seq":%d,"pad":"%s"}\n' "$n" "$pad" >&3
      n=$((n+1)); i=$((i+1))
    done
    echo "$n" > /ctl/written.tmp && mv /ctl/written.tmp /ctl/written
  fi
  sleep 0.1
done`

const receiverConfig = `sources:
  in:
    type: http_server
    address: 0.0.0.0:8080
    decoding: {codec: json}
    framing: {method: newline_delimited}
sinks:
  out:
    type: file
    inputs: [in]
    path: /out/received.log
    encoding: {codec: json}
`

// realDocker skips unless QPOT_TEST_DOCKER=1; it needs Docker, the collector
// image and an ordinary user in the docker group, as QPot runs.
func realDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("QPOT_TEST_DOCKER") != "1" {
		t.Skip("set QPOT_TEST_DOCKER=1 to run cleanup against real containers")
	}
	if out, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", instance.CollectorImage).CombinedOutput(); err != nil {
		t.Fatalf("QPOT_TEST_DOCKER=1 needs Docker and the collector image: %v: %s", err, out)
	}
	if os.Geteuid() == 0 {
		t.Fatal("QPOT_TEST_DOCKER=1 must run as an ordinary user in the docker group, as QPot does")
	}
}

// TestCollectorAndCleanupWithRealDocker: a honeypot holds its log open and
// writes to it; the real collector (Vector, with QPot's own file source)
// reads it and delivers to a receiver that is away at first. Cleanup asks
// docker compose whether the collector runs and empties the log through the
// helper container, only once the collector has delivered all of it. The
// collector is recreated and stopped along the way. Every line written
// arrives, once.
func TestCollectorAndCleanupWithRealDocker(t *testing.T) {
	realDocker(t)
	a := newAPITestServer(t, "cleanup-docker", func(c *config.Config) { c.Cleanup.MaxLogMB = 1 })
	a.s.api.runner = nil // the real manager: docker compose ps
	mgr, err := instance.NewManager(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.s.manager = mgr
	data := a.cfg.DataPath

	// The collector's file source exactly as QPot generates it.
	sb, err := security.NewSandbox(&a.cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	vc, err := (&instance.ComposeGenerator{Config: a.cfg, Sandbox: sb}).GenerateVectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	var gen struct {
		Sources map[string]any `yaml:"sources"`
	}
	if err := yaml.Unmarshal([]byte(vc), &gen); err != nil {
		t.Fatal(err)
	}
	source := vectorstate.HoneypotSource("cowrie")
	if gen.Sources[source] == nil {
		t.Fatalf("no %s source in the generated config", source)
	}
	collectorCfg, err := yaml.Marshal(map[string]any{
		"data_dir": "/var/lib/vector",
		"sources":  map[string]any{source: gen.Sources[source]},
		"sinks": map[string]any{"out": map[string]any{
			"type": "http", "inputs": []string{source}, "uri": "http://receiver:8080/",
			"encoding":         map[string]any{"codec": "json"},
			"framing":          map[string]any{"method": "newline_delimited"},
			"request":          map[string]any{"retry_max_duration_secs": 1},
			"acknowledgements": map[string]any{"enabled": true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	logs := filepath.Join(data, "honeypots", "cowrie", "logs")
	ctl := filepath.Join(data, "ctl")
	out := filepath.Join(data, "received")
	state := filepath.Join(data, vectorstate.Dir)
	for _, d := range []string{logs, ctl, out, state} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{logs, ctl} { // the honeypot's user writes here
		if err := os.Chmod(d, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string][]byte{"collector.yaml": collectorCfg, "receiver.yaml": []byte(receiverConfig)} {
		if err := os.WriteFile(filepath.Join(data, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	compose := a.cfg.GetDockerComposePath()
	project := fmt.Sprintf("qpot-cleanup-docker-%d", os.Getpid())
	spec, err := yaml.Marshal(map[string]any{
		"name": project,
		"services": map[string]any{
			"collector": map[string]any{
				"image": instance.CollectorImage, "command": []string{"--config", "/etc/vector/vector.yaml"},
				"stop_grace_period": "2s",
				"volumes": []string{data + "/collector.yaml:/etc/vector/vector.yaml:ro",
					data + "/honeypots:/data/honeypots:ro", state + ":/var/lib/vector"},
			},
			"receiver": map[string]any{
				"image": instance.CollectorImage, "command": []string{"--config", "/etc/vector/receiver.yaml"},
				"stop_grace_period": "2s",
				"volumes":           []string{data + "/receiver.yaml:/etc/vector/receiver.yaml:ro", out + ":/out"},
			},
			"cowrie": map[string]any{
				"image": instance.CollectorImage, "user": "2000:2000", "network_mode": "none",
				// $$: compose would otherwise substitute the script's $ itself.
				"entrypoint": []string{"sh", "-c", strings.ReplaceAll(writerScript, "$", "$$")}, "stop_grace_period": "1s",
				"volumes": []string{logs + ":/logs", ctl + ":/ctl"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(compose, spec, 0o600); err != nil {
		t.Fatal(err)
	}
	dc := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-f", compose}, args...)...)
		cmd.Dir = data
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("docker compose %s: %v: %s", strings.Join(args, " "), err, b)
		}
	}
	t.Cleanup(func() {
		dc("down", "--remove-orphans", "--timeout", "1")
		// What the containers wrote belongs to their users: give it back so
		// the temp folder can be removed.
		b, err := exec.Command("docker", "run", "--rm", "--network", "none", "--user", "0:0",
			"--mount", "type=bind,source="+data+",target=/w", "--entrypoint", "chown", instance.CollectorImage,
			"-R", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "/w").CombinedOutput()
		if err != nil {
			t.Errorf("chown: %v: %s", err, b)
		}
	})

	log := filepath.Join(logs, "cowrie.json")
	written := 0
	burst := func(n int) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(ctl, "burst"), []byte(strconv.Itoa(n)), 0o666); err != nil {
			t.Fatal(err)
		}
		written += n
		until(t, time.Minute, fmt.Sprintf("the honeypot to write %d lines", written), func() bool {
			b, err := os.ReadFile(filepath.Join(ctl, "written"))
			return err == nil && strings.TrimSpace(string(b)) == strconv.Itoa(written)
		})
	}
	seqRe := regexp.MustCompile(`\\"seq\\":(\d+)`)
	received := func() map[int]int {
		got := map[int]int{}
		b, _ := os.ReadFile(filepath.Join(out, "received.log"))
		for _, m := range seqRe.FindAllSubmatch(b, -1) {
			n, _ := strconv.Atoi(string(m[1]))
			got[n]++
		}
		return got
	}
	run := func() cleanup.Report {
		t.Helper()
		rec := a.do(http.MethodPost, "/api/cleanup/run", `{}`)
		var rep cleanup.Report
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rep) != nil {
			t.Fatalf("POST /api/cleanup/run: %d %s", rec.Code, rec.Body.String())
		}
		if len(rep.Errors) != 0 {
			t.Fatalf("cleanup errors: %q", rep.Errors)
		}
		return rep
	}
	// emptied runs cleanup until it empties the log: the collector writes
	// its checkpoint a moment after the receiver has the lines.
	emptied := func() {
		t.Helper()
		until(t, 30*time.Second, "cleanup to empty the delivered log", func() bool { return run().Emptied == 1 })
	}
	allReceived := func() {
		t.Helper()
		until(t, 90*time.Second, fmt.Sprintf("the receiver to get %d lines", written), func() bool { return len(received()) == written })
	}

	// Nothing created yet: the collector does not run.
	if a.s.collectorRunning(context.Background()) {
		t.Fatal("collector reported running before it was created")
	}
	// 0. The log already holds lines from before the collector kept its
	// state (an upgrade): QPot seeds the state, so they are not sent again.
	var old strings.Builder
	for i := range 50 {
		fmt.Fprintf(&old, `{"eventid":"before-the-upgrade","n":%d}`+"\n", i)
	}
	if err := os.WriteFile(log, []byte(old.String()), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(log, 0o666); err != nil { // the honeypot's user appends to it
		t.Fatal(err)
	}
	seeded := false
	sources, err := instance.CollectorSources(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range sources {
		if src.Name == source {
			n, err := vectorstate.Seed(data, src, time.Now())
			if err != nil || n != 1 {
				t.Fatalf("seed: %d %v", n, err)
			}
			seeded = true
		}
	}
	if !seeded {
		t.Fatalf("CollectorSources has no %s", source)
	}
	dc("up", "-d", "collector", "cowrie")
	until(t, time.Minute, "the collector to run", func() bool { return a.s.collectorRunning(context.Background()) })
	// The collector found the log (still empty) before the first lines.
	if err := os.WriteFile(filepath.Join(ctl, "burst"), []byte("0"), 0o666); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)

	// 1. Delayed ingestion: the receiver is away, so the collector reads but
	// cannot deliver; the log is never emptied meanwhile.
	burst(1000)
	before, err := os.Stat(log)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		time.Sleep(2 * time.Second)
		if rep := run(); rep.Emptied != 0 || !strings.Contains(strings.Join(rep.Notes, " "), "not yet delivered") {
			t.Fatalf("emptied a log the collector could not deliver: %+v", rep)
		}
	}
	if fi, _ := os.Stat(log); fi.Size() != before.Size() {
		t.Fatalf("the log changed while undelivered: %d bytes, was %d", fi.Size(), before.Size())
	}
	// The receiver is back: once delivered, the log is emptied in place.
	dc("up", "-d", "receiver")
	allReceived()
	emptied()
	if fi, err := os.Stat(log); err != nil || fi.Size() != 0 || !os.SameFile(before, fi) {
		t.Fatalf("the log was not emptied in place: %v %v", fi, err)
	}

	// 2. A long outage: the receiver goes away again, the honeypot writes,
	// and the collector is recreated meanwhile (an upgrade, a reboot). What
	// it read but could not deliver is read again; the log is kept.
	dc("stop", "--timeout", "2", "receiver")
	burst(1000)
	time.Sleep(3 * time.Second)
	dc("up", "-d", "--force-recreate", "collector")
	until(t, time.Minute, "the recreated collector to run", func() bool { return a.s.collectorRunning(context.Background()) })
	time.Sleep(3 * time.Second)
	if rep := run(); rep.Emptied != 0 {
		t.Fatalf("emptied a log the collector could not deliver: %+v", rep)
	}
	dc("start", "receiver")
	allReceived()
	emptied()

	// 3. The collector is stopped while the honeypot writes.
	dc("stop", "--timeout", "2", "collector")
	if rep := run(); rep.Collector || rep.Emptied != 0 {
		t.Fatalf("collector stopped: %+v", rep)
	}
	burst(1000)
	dc("start", "collector")
	allReceived()
	emptied()

	// The writer still writes to the file at the log's path.
	burst(10)
	allReceived()
	if fi, err := os.Stat(log); err != nil || !os.SameFile(before, fi) {
		t.Fatalf("the log at %s is not the file the honeypot writes: %v", log, err)
	}
	got := received()
	for i := range written {
		if got[i] != 1 {
			t.Errorf("line %d arrived %d times", i, got[i])
		}
	}
	if b, _ := os.ReadFile(filepath.Join(out, "received.log")); strings.Contains(string(b), "before-the-upgrade") {
		t.Error("lines from before the collector kept its state were sent again")
	}
}

func until(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("gave up waiting for %s", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
