package instance

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestCowrieMachineState checks action sequences across existing/new channels
// using the production adapter and protocol constructor, with framework-only
// dependencies replaced. Image integration exercises the full Cowrie modules.
func TestCowrieMachineState(t *testing.T) {
	py := python(t)
	patch := t.TempDir()
	for _, name := range []string{"qpot_state.py", "protocol.py"} {
		content, err := os.ReadFile(filepath.Join("honeypotfiles", "cowrie", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(patch, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(py, "-I", filepath.Join("testdata", "cowrie_stateful.py"), "--unit", patch)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("production machine-state sequences: %v\n%s", err, output)
	} else {
		t.Logf("%s", output)
	}
}

func TestCowrieActorPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the patched Cowrie runs in its Linux container; Windows Python has no os.O_ACCMODE")
	}
	py := python(t)
	patch, err := filepath.Abs(filepath.Join("honeypotfiles", "cowrie"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(py, "-I", filepath.Join("testdata", "cowrie_permissions.py"), patch)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actor permission sequences: %v\n%s", err, output)
	} else {
		t.Logf("%s", output)
	}
}

// TestCowrieStatefulImage imports the real image's renderer, filesystem and
// package commands under the exact production patch mounts. It supplements
// SSH wire tests; only command progress sleeps and transport stdio are adapted.
func TestCowrieStatefulImage(t *testing.T) {
	if os.Getenv("QPOT_TEST_COWRIE_STATEFUL") != "1" {
		t.Skip("set QPOT_TEST_COWRIE_STATEFUL=1 for actual-image state integration")
	}
	image := GetHoneypotImage("cowrie")
	if out, err := conpotLiveDocker(15*time.Second, "image", "inspect", image, "--format", "{{.Id}}"); err != nil {
		t.Fatalf("pull the configured Cowrie image before opting in: %v\n%s", err, out)
	} else {
		t.Logf("actual Cowrie image: %s", strings.TrimSpace(out))
	}
	_, mounts := cowrieStatefulMounts(t)
	// Every supported persona must agree with its finite OS/app-version facts.
	// Four representative package families also exercise full mutable state.
	for _, profile := range CowriePersonaIDs() {
		mode := "--facts"
		switch profile {
		case "debian-bookworm", "rhel-9", "centos-7", "openwrt":
			mode = "--image"
		}
		t.Run(profile, func(t *testing.T) {
			name := fmt.Sprintf("qpot-cowrie-state-%s-%d", profile, time.Now().UnixNano())
			t.Cleanup(func() {
				// The name is unique to this test; cleanup never targets another service.
				_, _ = conpotLiveDocker(15*time.Second, "rm", "-f", name)
			})
			args := []string{"run", "--rm", "--name", name, "--network", "none", "--read-only", "--user", "2000:2000",
				// The pinned interpreter carries NET_BIND_SERVICE as a file capability;
				// production Cowrie also needs it for its privileged SSH/Telnet ports.
				"--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges:true", "--memory", "512m", "--pids-limit", "128", "--cpus", "1",
				"--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,uid=2000,gid=2000,mode=1777", "-e", "PYTHONDONTWRITEBYTECODE=1"}
			args = append(args, mounts...)
			args = append(args, "--entrypoint", "python3", image, "/qpot-stateful-test/harness.py", mode, profile)
			if out, err := conpotLiveDocker(2*time.Minute, args...); err != nil {
				t.Fatalf("actual-image state sequence failed: %v\n%s", err, out)
			} else {
				t.Logf("%s", strings.TrimSpace(out))
			}
		})
	}
}

func cowrieStatefulMounts(t *testing.T) (string, []string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	harness, err := os.ReadFile(filepath.Join("testdata", "cowrie_stateful.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "harness.py"), harness, 0o644); err != nil {
		t.Fatal(err)
	}
	// These disposable source-only fixtures must remain readable by image UID
	// 2000 even when the host process has a restrictive creation umask.
	if err := os.Chmod(filepath.Join(root, "harness.py"), 0o644); err != nil {
		t.Fatal(err)
	}
	mounts := []string{"--mount", "type=bind,src=" + root + ",dst=/qpot-stateful-test,readonly"}
	for _, volume := range cowriePatchVolumes() {
		if volume.ContainerPath == "" {
			continue // Operator-only notices/source archives have no runtime mount.
		}
		path := filepath.Join(root, volume.HostSubdir)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, volume.Content, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		mounts = append(mounts, "--mount", "type=bind,src="+path+",dst="+volume.ContainerPath+",readonly")
	}
	return root, mounts
}

// TestCowrieStatefulSSH starts the real persona launcher/Twisted SSH service
// and follows modifications across SSH channels. The client stays inside the
// network-none namespace; no host port or external connection is available.
func TestCowrieStatefulSSH(t *testing.T) {
	if os.Getenv("QPOT_TEST_COWRIE_STATEFUL") != "1" {
		t.Skip("set QPOT_TEST_COWRIE_STATEFUL=1 for actual SSH state integration")
	}
	image := GetHoneypotImage("cowrie")
	architecture, err := conpotLiveDocker(15*time.Second, "image", "inspect", image, "--format", "{{.Architecture}}")
	if err != nil {
		t.Fatalf("configured Cowrie image unavailable: %v\n%s", err, architecture)
	}
	root, mounts := cowrieStatefulMounts(t)
	client := filepath.Join(root, "ssh-client")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-o", client,
		filepath.Join("testdata", "cowrie_ssh_client.go"))
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+strings.TrimSpace(architecture))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile actual SSH client: %v\n%s", err, out)
	}
	if err := os.Chmod(client, 0o755); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("qpot-cowrie-ssh-state-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = conpotLiveDocker(15*time.Second, "rm", "-f", name)
	})
	args := []string{"run", "-d", "--name", name, "--network", "none", "--read-only", "--user", "2000:2000",
		"--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges:true",
		"--memory", "512m", "--pids-limit", "128", "--cpus", "1",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,uid=2000,gid=2000,mode=1777",
		"--tmpfs", "/home/cowrie/cowrie/etc:rw,nosuid,nodev,size=16m,uid=2000,gid=2000,mode=0700",
		"--tmpfs", "/home/cowrie/cowrie/log:rw,nosuid,nodev,size=16m,uid=2000,gid=2000,mode=0750",
		"--tmpfs", "/home/cowrie/cowrie/dl:rw,nosuid,nodev,size=16m,uid=2000,gid=2000,mode=0750",
		"-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "COWRIE_PERSONA=debian-bookworm", "-e", "COWRIE_PERSONA_ROTATION=365",
		"-e", "COWRIE_HONEYPOT_AUTH_CLASS=AuthRandom", "-e", "COWRIE_HONEYPOT_AUTH_CLASS_PARAMETERS=1,1,100",
		"-e", "COWRIE_SSH_LISTEN_ENDPOINTS=tcp:22:interface=127.0.0.1", "-e", "COWRIE_SSH_SFTP_ENABLED=true", "-e", "COWRIE_TELNET_ENABLED=false"}
	args = append(args, mounts...)
	args = append(args, "--entrypoint", "/usr/local/bin/start-cowrie-persona", image)
	if out, err := conpotLiveDocker(time.Minute, args...); err != nil {
		t.Fatalf("start isolated Cowrie SSH fixture: %v\n%s", err, out)
	}
	// Production manager initialization creates the capture subdirectories before
	// starting Cowrie. This fixture keeps captures wholly inside private tmpfs.
	if out, err := conpotLiveDocker(10*time.Second, "exec", name, "python3", "-c",
		`from pathlib import Path;Path("/home/cowrie/cowrie/log/tty").mkdir(mode=0o750,exist_ok=True)`); err != nil {
		t.Fatalf("prepare fixture capture directory: %v\n%s", err, out)
	}
	deadline := time.Now().Add(45 * time.Second)
	var ready string
	for time.Now().Before(deadline) {
		ready, err = conpotLiveDocker(5*time.Second, "exec", name, "python3", "-c",
			`import socket;s=socket.create_connection(("127.0.0.1",22),1);assert s.recv(80).startswith(b"SSH-2.0-");s.close()`)
		if err == nil {
			break
		}
		state, _ := conpotLiveDocker(5*time.Second, "inspect", name, "--format", "{{.State.Status}}")
		if strings.TrimSpace(state) != "running" {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		logs, _ := conpotLiveDocker(10*time.Second, "logs", name)
		t.Fatalf("actual SSH readiness failed: %v\n%s\n%s", err, ready, logs)
	}
	if out, err := conpotLiveDocker(2*time.Minute, "exec", name, "/qpot-stateful-test/ssh-client"); err != nil {
		logs, _ := conpotLiveDocker(10*time.Second, "logs", name)
		t.Fatalf("real SSH action sequences failed: %v\n%s\n%s", err, out, logs)
	} else {
		t.Logf("%s", strings.TrimSpace(out))
	}
	logCheck := `import json,pathlib
rows=[json.loads(line) for line in pathlib.Path("/home/cowrie/cowrie/log/cowrie.json").read_text().splitlines()]
commands=[row.get("input","") for row in rows if row.get("eventid")=="cowrie.command.input"]
for text in ("hostname maintenance01","useradd -m","apt-get remove","chown analystqa"):
 assert any(text in command for command in commands),text
print(json.dumps({"attack_commands_logged":len(commands),"required_mutation_inputs_captured":True}))`
	if out, err := conpotLiveDocker(15*time.Second, "exec", name, "python3", "-c", logCheck); err != nil {
		t.Fatalf("real SSH command telemetry missing: %v\n%s", err, out)
	} else {
		t.Logf("%s", strings.TrimSpace(out))
	}
}
