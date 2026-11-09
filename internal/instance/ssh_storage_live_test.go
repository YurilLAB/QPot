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

	"gopkg.in/yaml.v3"
)

// This is a metadata-only proof with a real native image and genuine procfs:
// a backend started as Compose starts it mounts nothing from the host, so its
// mount table names no folder of the instance, its store or its secret
// namespace. It makes no SSH connection and grants no guest capabilities.
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
	var doc struct {
		Services map[string]struct {
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(renderComposeCfg(t, cfg)), &doc); err != nil {
		t.Fatal(err)
	}
	for _, service := range allSSHCellServiceNames(cfg) {
		if sshCaptureService(service) && len(doc.Services[service].Volumes) != 0 {
			t.Fatalf("%s mounts host folders: %v", service, doc.Services[service].Volumes)
		}
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
	output, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", "/bin/cat", image, "/proc/self/mountinfo").CombinedOutput()
	if err != nil {
		t.Fatalf("actual native metadata read: %v %s", err, output)
	}
	lines := 0
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		lines++
		lower := strings.ToLower(line)
		if strings.Contains(line, filepath.ToSlash(cfg.DataPath)) || strings.Contains(line, filepath.ToSlash(store.Root)) || strings.Contains(line, store.Namespace) ||
			strings.Contains(lower, "qpot") || strings.Contains(lower, "honeypot") || strings.Contains(line, "ssh-backend") || strings.Contains(line, "archive-g") {
			t.Fatalf("the guest's mount table names the instance: %s", line)
		}
	}
	if lines == 0 {
		t.Fatalf("no mount table read: %s", output)
	}
	record := struct {
		ImageID, Root string
		Mounts        int
	}{strings.TrimSpace(string(id)), store.Root, lines}
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
