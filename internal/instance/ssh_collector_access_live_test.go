//go:build linux

package instance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// TestSSHCollectorPrivateLogsLive exercises real bind mounts and Vector's file
// source, not a stdin substitute. It never opens a network or changes modes to
// make private recordings readable by the host test process. A cell database
// still writes its own log through such a mount; backend sessions are written
// by the control plane, but the collector must read private files either way.
func TestSSHCollectorPrivateLogsLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_SSH_COLLECTOR") != "1" {
		t.Skip("set QPOT_TEST_SSH_COLLECTOR=1 for actual private log mounts")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	backend := "qpot-local/ssh-backend:development"
	for _, image := range []string{backend, CollectorImage} {
		if output, err := conpotLiveDocker(10*time.Second, "image", "inspect", image); err != nil {
			t.Fatalf("required cached image %s: %v %s", image, err, output)
		}
	}
	data := t.TempDir()
	cfg := config.Default("private-evidence-fixture")
	cfg.DataPath = data
	cfg.QPotID = "qp_privateevidencefixture0001"
	prepareSSHStoreForTest(t, cfg)
	services := []string{"ssh-backend-1", "ssh-backend-1-db"}
	for _, service := range services {
		if err := prepareSSHLogDir(data, service); err != nil {
			t.Fatal(err)
		}
	}
	logs, err := sshStoreRecordRoot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The test owner maps to container1000 on this rootless development engine.
	// Determine the inverse mapping, rather than assuming a daemon UID layout.
	owner := collectorMappedOwner(t, backend)
	t.Cleanup(func() {
		if output, err := conpotLiveDocker(30*time.Second, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges", "--entrypoint", "/usr/bin/chown", "--mount", "type=bind,src="+logs+",dst=/target", backend, "-R", "--no-dereference", owner, "/target"); err != nil {
			t.Errorf("restore only this fixture's mapped ownership: %v %s", err, output)
		}
	})
	seed := func(service, uid, marker string) {
		t.Helper()
		current := requireSSHLogDirAt(t, data, service)
		command := `set -eu; mkdir -p /target/uid-` + uid + `; printf '%s\n' '{"marker":"` + marker + `"}' > /target/uid-` + uid + `/events.json; chmod 700 /target/uid-` + uid + `; chmod 600 /target/uid-` + uid + `/events.json; chown -R ` + uid + `:` + uid + ` /target/uid-` + uid
		if output, err := conpotLiveDocker(20*time.Second, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges", "--entrypoint", "/bin/sh", "--mount", "type=bind,src="+current+",dst=/target", backend, "-c", command); err != nil {
			t.Fatalf("seed private synthetic recording: %v %s", err, output)
		}
	}
	seed(services[0], "1000", "archived-app")
	seed(services[1], "999", "archived-db")
	guest := func(service, command string) (string, error) {
		return conpotLiveDocker(20*time.Second, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges", "--entrypoint", "/bin/sh", "--mount", "type=bind,src="+requireSSHLogDirAt(t, data, service)+",dst=/var/log/session", backend, "-c", command)
	}
	if output, err := guest(services[0], "cat /var/log/session/uid-1000/events.json"); err != nil || !strings.Contains(output, "archived-app") {
		t.Fatalf("old visitor did not see its own bytes: %v %s", err, output)
	}
	if err := archiveSSHCellLogs(data, services, 7); err != nil {
		t.Fatal(err)
	}
	for _, service := range services {
		if output, err := guest(service, `set -eu; test -z "$(ls -A /var/log/session)"; test ! -e /var/log/session/../archive-g7; test ! -e /var/log/session/uid-1000/events.json; test ! -e /var/log/session/uid-999/events.json`); err != nil {
			t.Fatalf("new visitor accessed previous log mount: %v %s", err, output)
		}
		archives, _ := filepath.Glob(filepath.Join(filepath.Dir(requireSSHLogDirAt(t, data, service)), "archive-g7-*"))
		if len(archives) != 1 {
			t.Fatal("stopped visitor archive missing")
		}
		if info, err := os.Stat(archives[0]); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatal("archive parent must remain host private0700")
		}
	}
	seed(services[0], "1000", "current-app")
	seed(services[1], "999", "current-db")
	config := `data_dir: /var/lib/vector
sources:
  private:
    type: file
    include:
      - /data/honeypots/ssh-proxy/logs/cells/*/current/**/*.json
      - /data/honeypots/ssh-proxy/logs/cells/*/archive-g*/logs/**/*.json
    read_from: beginning
sinks:
  output:
    type: console
    inputs: [private]
    encoding:
      codec: json
`
	configFile := filepath.Join(data, "vector.yaml")
	if err := os.WriteFile(configFile, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("qpot-collector-private-%d", time.Now().UnixNano())
	// Match collector's production root/default capabilities plus its explicit
	// DAC_READ_SEARCH, and mount all sensor evidence read-only.
	args := []string{"run", "-d", "--name", name, "--network", "none", "--cap-add", "DAC_READ_SEARCH", "--mount", "type=bind,src=" + logs + ",dst=/data/honeypots/ssh-proxy/logs,readonly", "--mount", "type=bind,src=" + configFile + ",dst=/etc/vector/vector.yaml,readonly", "--tmpfs", "/var/lib/vector:rw,nosuid,nodev,size=16m", CollectorImage, "--config", "/etc/vector/vector.yaml"}
	if output, err := conpotLiveDocker(30*time.Second, args...); err != nil {
		t.Fatalf("start exact collector security: %v %s", err, output)
	}
	t.Cleanup(func() { _, _ = conpotLiveDocker(15*time.Second, "rm", "-f", "--volumes", name) })
	var output string
	for until := time.Now().Add(20 * time.Second); time.Now().Before(until); {
		output, _ = conpotLiveDocker(5*time.Second, "logs", name)
		if strings.Contains(output, "archived-app") && strings.Contains(output, "archived-db") && strings.Contains(output, "current-app") && strings.Contains(output, "current-db") {
			t.Log("actual collector read all four private current/archive records; fresh guest mounts excluded prior visitor bytes")
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("collector could not read private current/archive evidence: %s", output)
}

func collectorMappedOwner(t *testing.T, image string) string {
	t.Helper()
	var ids []string
	for _, item := range []struct {
		name string
		host int
	}{{"uid", os.Getuid()}, {"gid", os.Getgid()}} {
		output, err := conpotLiveDocker(20*time.Second, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--entrypoint", "/bin/cat", image, "/proc/self/"+item.name+"_map")
		if err != nil {
			t.Fatalf("read collector fixture mapping: %v %s", err, output)
		}
		mapped := -1
		for _, line := range strings.Split(output, "\n") {
			var inside, outside, count int
			if n, _ := fmt.Sscanf(line, "%d %d %d", &inside, &outside, &count); n == 3 && item.host >= outside && item.host-outside < count {
				mapped = inside + item.host - outside
				break
			}
		}
		if mapped < 0 {
			t.Fatal("host test owner is not mapped by Docker")
		}
		ids = append(ids, fmt.Sprint(mapped))
	}
	return strings.Join(ids, ":")
}
