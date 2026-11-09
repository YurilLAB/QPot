package instance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"gopkg.in/yaml.v3"
)

func TestCollectorCheckpointsPersistOutsideGuestMounts(t *testing.T) {
	for _, mode := range []string{"idle", "sensor", "ordinary", "hifi"} {
		t.Run(mode, func(t *testing.T) {
			cfg := collectorTestConfig(nil)
			cfg.Collector.IngestSuricata, cfg.Collector.IngestP0f, cfg.Collector.IngestFatt = false, false, false
			switch mode {
			case "idle":
				enableOnly(cfg)
			case "sensor":
				enableOnly(cfg)
				cfg.Collector.IngestSuricata = true
			case "hifi":
				enableOnly(cfg, sshProxyHoneypot)
			}
			volumes, vectorConfig := collectorVolumes(t, cfg)
			state := cfg.DataPath + "/collector"
			if volumes[state] != "/var/lib/vector" || !strings.Contains(vectorConfig, `data_dir: "/var/lib/vector"`) {
				t.Fatal("collector checkpoints are not persisted read-write at the configured data_dir")
			}
			if volumes[cfg.DataPath+"/honeypots"] != "/data/honeypots:ro" {
				t.Fatal("checkpoint persistence made captured logs writable")
			}
			var doc struct {
				Services map[string]struct{ Volumes []string }
			}
			if err := yaml.Unmarshal([]byte(renderComposeCfg(t, cfg)), &doc); err != nil {
				t.Fatal(err)
			}
			for name, service := range doc.Services {
				if name == "collector" {
					continue
				}
				for _, mount := range service.Volumes {
					if strings.HasPrefix(mount, state+":") {
						t.Fatalf("checkpoint state exposed to %s", name)
					}
				}
			}
		})
	}
}

func TestInitializePreservesPrivateCollectorCheckpoints(t *testing.T) {
	cfg := config.Default("checkpoint-init")
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	enableOnly(cfg)
	organizationFakeDocker(t)
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(cfg.DataPath, "collector")
	checkpoint := filepath.Join(state, "checkpoint.json")
	if err := os.WriteFile(checkpoint, []byte("retained file cursor"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := manager.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(state)
	if err != nil || !info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o750) {
		t.Fatalf("checkpoint directory not private: %v", err)
	}
	contents, err := os.ReadFile(checkpoint)
	if err != nil || string(contents) != "retained file cursor" {
		t.Fatal("initialization discarded file checkpoints")
	}
}

// Real file-source cursors survive replacement of the Vector process. A fresh
// cursor directory intentionally demonstrates the archived-event replay risk.
func TestVectorFileCheckpointPersistenceLive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file checkpoint flush fixture requires Unix process signals")
	}
	dir := t.TempDir()
	runner := vectorRunner(t, dir)
	input := filepath.Join(dir, "logs", "cells", "ssh-backend-1", "archive-g7-123456789", "logs", "uid-0", "events.json")
	if err := os.MkdirAll(filepath.Dir(input), 0o750); err != nil {
		t.Fatal(err)
	}
	first := `{"event_type":"ssh_backend_command","session":"retained-capture-1","input":"hostname"}` + "\n"
	second := `{"event_type":"ssh_backend_command","session":"retained-capture-2","input":"id"}` + "\n"
	if err := os.WriteFile(input, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(name, state string, want int) []string {
		t.Helper()
		if err := os.MkdirAll(state, 0o750); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(dir, name+".json")
		harness := map[string]any{"data_dir": state,
			"sources": map[string]any{"ssh_backend_logs": map[string]any{"type": "file", "include": []string{input}, "read_from": "beginning"}},
			"sinks":   map[string]any{"out": map[string]any{"type": "file", "inputs": []string{"ssh_backend_logs"}, "path": output, "encoding": map[string]any{"codec": "json"}}},
		}
		data, err := yaml.Marshal(harness)
		if err != nil {
			t.Fatal(err)
		}
		configuration := filepath.Join(dir, name+".yaml")
		if err := os.WriteFile(configuration, data, 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, runner[0], append(runner[1:], "--quiet", "--config", configuration)...)
		var diagnostics bytes.Buffer
		cmd.Stderr = &diagnostics
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		stopped := false
		stop := func() {
			if !stopped {
				_ = cmd.Process.Kill()
				<-done
				stopped = true
			}
		}
		defer stop()
		deadline := time.Now().Add(6 * time.Second)
		for {
			contents, _ := os.ReadFile(output)
			if bytes.Count(contents, []byte("\n")) >= want {
				break
			}
			select {
			case err := <-done:
				stopped = true
				t.Fatalf("Vector ended before capturing evidence: %v %s", err, diagnostics.String())
			default:
			}
			if time.Now().After(deadline) {
				stop()
				t.Fatalf("Vector did not capture%d observations: %s", want, diagnostics.String())
			}
			time.Sleep(25 * time.Millisecond)
		}
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			stopped = true
			if err != nil {
				t.Fatalf("Vector checkpoint shutdown failed: %v %s", err, diagnostics.String())
			}
		case <-ctx.Done():
			t.Fatal("Vector did not flush file checkpoints")
		}
		contents, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		var messages []string
		for _, line := range bytes.Split(bytes.TrimSpace(contents), []byte("\n")) {
			var event struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(line, &event); err != nil {
				t.Fatal(err)
			}
			messages = append(messages, event.Message)
		}
		if len(messages) != want {
			t.Fatalf("%s: got%d events, want%d", name, len(messages), want)
		}
		return messages
	}
	state := filepath.Join(dir, "persisted-state")
	if messages := run("first", state, 1); !strings.Contains(messages[0], "retained-capture-1") {
		t.Fatal("initial archived event missing")
	}
	file, err := os.OpenFile(input, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString(second)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("append evidence: %v %v", writeErr, closeErr)
	}
	if messages := run("replacement-persisted", state, 1); !strings.Contains(messages[0], "retained-capture-2") {
		t.Fatal("replacement replayed old evidence or lost appended command")
	}
	if messages := run("replacement-fresh", filepath.Join(dir, "fresh-state"), 2); !strings.Contains(strings.Join(messages, "\n"), "retained-capture-1") {
		t.Fatal("fresh checkpoint control did not demonstrate archive replay")
	}
}
