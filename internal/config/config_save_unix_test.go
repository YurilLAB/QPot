//go:build unix

package config

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Exercise actual short writes and EFBIG without filling a shared disk. Only
// the child changes its soft file-size limit, and cleanup restores the limit
// before Go's coverage exit hook writes metadata and counters.
func TestSavePartialWriteFailurePreservesPreviousConfig(t *testing.T) {
	const helperEnv = "QPOT_SAVE_WRITE_FAILURE_HELPER"
	if os.Getenv(helperEnv) == "1" {
		cfg := Default("save-partial-write")
		cfg.DataPath = t.TempDir()
		cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
		previous := []byte("previous complete config\n")
		if err := os.WriteFile(cfg.ConfigPath, previous, 0600); err != nil {
			t.Fatal(err)
		}
		before, _ := cfg.GetHoneypotConfig("conpot")
		var original syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
			t.Fatal(err)
		}
		wasIgnored := signal.Ignored(syscall.SIGXFSZ)
		signal.Ignore(syscall.SIGXFSZ)
		t.Cleanup(func() {
			if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
				t.Errorf("restore child file-size limit before coverage exit: %v", err)
			}
			if !wasIgnored {
				signal.Reset(syscall.SIGXFSZ)
			}
		})
		for _, size := range []uint64{1024, 0} {
			limited := original
			limited.Cur = min(size, original.Cur)
			if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
				t.Fatal(err)
			}
			err := Save(cfg)
			if size == 0 && !errors.Is(err, syscall.EFBIG) {
				t.Fatalf("zero file-size limit did not produce EFBIG: %v", err)
			}
			if !errors.Is(err, syscall.EFBIG) && !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("file-size limit did not reject the staged write: %v", err)
			}
			data, err := os.ReadFile(cfg.ConfigPath)
			if err != nil || !bytes.Equal(data, previous) {
				t.Fatalf("partial write damaged existing config: %q, %v", data, err)
			}
			after, _ := cfg.GetHoneypotConfig("conpot")
			if after.DeviceProfile != before.DeviceProfile {
				t.Fatal("partial write adopted an unsaved device profile")
			}
			staged, err := filepath.Glob(filepath.Join(cfg.DataPath, ".qpot-config-*.tmp"))
			if err != nil || len(staged) != 0 {
				t.Fatalf("partial write left staged config files: %v, %v", staged, err)
			}
		}
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run", "^TestSavePartialWriteFailurePreservesPreviousConfig$", "-test.v")
	command.Env = append(os.Environ(), helperEnv+"=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bounded child write test failed: %v\n%s", err, output)
	}
}
