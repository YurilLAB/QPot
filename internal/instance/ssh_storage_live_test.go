package instance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This is a metadata-only proof with a real native image and genuine procfs.
// It makes no SSH connection and grants no guest capabilities or host network.
func TestSSHStoreNativeMountMetadataLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_DOCKER") != "1" {
		t.Skip("set QPOT_TEST_DOCKER=1 for real kernel mount metadata")
	}
	cfg := unreservedSSHStoreConfig(t)
	cfg.DataPath = filepath.Join(t.TempDir(), ".qpot", "instances", "metadata")
	if err := os.MkdirAll(cfg.DataPath, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	prepareSSHStoreForTest(t, cfg)
	store, err := sshStoreAt(cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	current := store.current("ssh-backend-1")
	contextDir := store.context("ssh-backend-1")
	keys := store.keys(false)
	for _, dir := range []string{current, contextDir, keys} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(filepath.Dir(current), "archive-g1-123", "logs")
	if err := os.MkdirAll(archive, 0o700); err != nil {
		t.Fatal(err)
	}
	image := os.Getenv("QPOT_TEST_SSH_BACKEND_IMAGE")
	if image == "" {
		image = "qpot-local/ssh-backend:development"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", image).CombinedOutput()
	if err != nil {
		t.Fatalf("native image required: %v %s", err, id)
	}
	mounts := map[string]string{current: "/var/log/audit", contextDir: "/run/audit-context", keys: "/run/sshd/bootstrap/keys"}
	args := []string{"run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"}
	for _, host := range []string{current, contextDir, keys} {
		mount := "type=bind,source=" + host + ",target=" + mounts[host]
		if host != current {
			mount += ",readonly"
		}
		args = append(args, "--mount", mount)
	}
	args = append(args, "--entrypoint", "/bin/cat", image, "/proc/self/mountinfo")
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("actual native metadata read: %v %s", err, output)
	}
	observed := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		for host, target := range mounts {
			if fields[4] != target {
				continue
			}
			observed[target] = line
			if !strings.Contains(line, filepath.ToSlash(host)) || strings.Contains(strings.ToLower(fields[3]), "qpot") || strings.Contains(strings.ToLower(fields[3]), "honeypot") || strings.Contains(line, "ssh-backend-1") || strings.Contains(line, "archive-g") || strings.Contains(line, store.Namespace) {
				t.Fatalf("native bind source still exposes generated identity: %s", line)
			}
			readonly := strings.Contains(","+fields[5]+",", ",ro,")
			if readonly != (host != current) {
				t.Fatalf("wrong actual bind trust mode: %s", line)
			}
		}
	}
	if len(observed) != len(mounts) {
		t.Fatalf("missing actual mounts: %v", observed)
	}
	record := struct {
		ImageID, Root string
		Mounts        map[string]string
		Observed      map[string]string
	}{strings.TrimSpace(string(id)), store.Root, mounts, observed}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
	if evidence := os.Getenv("QPOT_TEST_EVIDENCE_DIR"); evidence != "" {
		if !filepath.IsAbs(evidence) {
			t.Fatal("evidence directory must be absolute")
		}
		if err := os.MkdirAll(evidence, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(evidence, "mountinfo-after.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSSHStorePrivateRecordingRemovalLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_DOCKER") != "1" {
		t.Skip("set QPOT_TEST_DOCKER=1 for private guest UID cleanup")
	}
	if os.Geteuid() == 0 {
		t.Skip("private UID helper regression requires an ordinary host user")
	}
	cfg := unreservedSSHStoreConfig(t)
	prepareSSHStoreForTest(t, cfg)
	store, err := sshStoreAt(cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	current := store.current("ssh-backend-1")
	if err := os.MkdirAll(current, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(current, 0o777); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// All fixture containers exit before removal acquires the lifecycle lock.
	args := []string{"run", "--rm", "--network", "none", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--user", "0:0", "--mount", "type=bind,source=" + current + ",target=/w", "--entrypoint", "sh", CollectorImage, "-ec", `mkdir -p /w/private; printf 'retained evidence\n' >/w/private/events.json; chmod 0700 /w/private; chown -R 2000:2000 /w/private`}
	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("private fixture: %v %s", err, out)
	}
	t.Cleanup(func() {
		if info, err := os.Lstat(store.area()); err != nil || !info.IsDir() {
			return
		}
		_ = exec.Command("docker", "run", "--rm", "--network", "none", "--user", "0:0", "--mount", "type=bind,source="+store.area()+",target=/c", "--entrypoint", "chown", CollectorImage, "-R", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "/c").Run()
	})
	if _, err := os.ReadDir(filepath.Join(current, "private")); err == nil {
		t.Fatal("fixture did not require privileged scoped cleanup")
	}
	lock, err := lockSSHCells(ctx, cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := removeSSHStore(ctx, cfg.DataPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(store.Root); !os.IsNotExist(err) {
		t.Fatalf("verified private recording store remains: %v", err)
	}
}
