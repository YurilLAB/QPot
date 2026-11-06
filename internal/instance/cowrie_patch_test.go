package instance

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// TestCowriePatchPinned: the patch layer replaces whole files of one image
// release; a TPotVersion bump must re-check them before they are mounted over
// a different image.
func TestCowriePatchPinned(t *testing.T) {
	if cowriePatchVersion != TPotVersion {
		t.Fatalf("cowrie patch files were made from %s, the images are now %s: compare them with the new image",
			cowriePatchVersion, TPotVersion)
	}
}

// TestCowriePatchMounts: every patched file is mounted read-only at the
// image's own path, with its content written by setup.
func TestCowriePatchMounts(t *testing.T) {
	want := map[string][]byte{
		cowrieSource + "/shell/protocol.py":     cowrieProtocolPy,
		cowrieSource + "/commands/ping.py":      cowriePingPy,
		cowrieSource + "/commands/coreutils.py": cowrieCoreutilsPy,
		cowrieSource + "/commands/__init__.py":  cowrieCommandsInitPy,
	}
	d := deployProfile(config.Default("cowrie-patch"), "cowrie")
	for _, v := range d.Volumes {
		content, ok := want[v.ContainerPath]
		if !ok {
			continue
		}
		if !v.File || !v.ReadOnly || !bytes.Equal(v.Content, content) || len(content) == 0 {
			t.Errorf("%s: file=%v ro=%v content %d bytes", v.ContainerPath, v.File, v.ReadOnly, len(v.Content))
		}
		delete(want, v.ContainerPath)
	}
	for path := range want {
		t.Errorf("%s is not mounted", path)
	}

	cfg := config.Default("cowrie-patch-compose")
	enableOnly(cfg, "cowrie")
	svc, _, _ := publishedPorts(t, cfg, "cowrie")
	for _, line := range []string{
		"/honeypots/cowrie/patch/protocol.py:" + cowrieSource + "/shell/protocol.py:ro\n",
		"/honeypots/cowrie/patch/ping.py:" + cowrieSource + "/commands/ping.py:ro\n",
		"/honeypots/cowrie/patch/coreutils.py:" + cowrieSource + "/commands/coreutils.py:ro\n",
		"/honeypots/cowrie/patch/commands_init.py:" + cowrieSource + "/commands/__init__.py:ro\n",
	} {
		if !strings.Contains(svc, line) {
			t.Errorf("cowrie service lacks %q", strings.TrimSpace(line))
		}
	}
}

// TestCowriePatchFiles checks what the files must hold to work at all: the
// module list loads coreutils last (so its commands win), and protocol.py is
// the image's with its T-Pot changes kept.
func TestCowriePatchFiles(t *testing.T) {
	init := string(cowrieCommandsInitPy)
	last := strings.LastIndex(init, `"coreutils",`)
	if last < 0 || strings.Count(init, `"coreutils",`) != 1 || last < strings.LastIndex(init, `"yum",`) {
		t.Errorf("commands/__init__.py does not load coreutils last")
	}
	for _, module := range []string{`"base",`, `"bash",`, `"ping",`, `"netstat",`, `"uname",`} {
		if !strings.Contains(init, module) {
			t.Errorf("commands/__init__.py lost %s", module)
		}
	}
	protocol := string(cowrieProtocolPy)
	for _, kept := range []string{"def tpot_history_size", "def tpot_commands", "class HoneyPotInteractiveProtocol",
		"TPOT_LINE_MAX", "def qpot_line_change", "\\x1b[?2004h"} {
		if !strings.Contains(protocol, kept) {
			t.Errorf("protocol.py lacks %q", kept)
		}
	}
	// The terminal insert mode was the tell; nothing may switch it on again.
	if strings.Contains(protocol, "insults.modes.IRM") {
		t.Error("protocol.py sets the terminal's insert mode")
	}
	for name, content := range map[string][]byte{"protocol.py": cowrieProtocolPy, "ping.py": cowriePingPy,
		"coreutils.py": cowrieCoreutilsPy, "commands_init.py": cowrieCommandsInitPy} {
		if bytes.Contains(content, []byte("\r")) {
			t.Errorf("%s has CR bytes", name)
		}
	}
}

// TestCowriePatchWritten: Initialize writes the files the mounts need.
func TestCowriePatchWritten(t *testing.T) {
	cfg := config.Default("cowrie-patch-files")
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	enableOnly(cfg, "cowrie")
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	for name, content := range map[string][]byte{"protocol.py": cowrieProtocolPy, "ping.py": cowriePingPy,
		"coreutils.py": cowrieCoreutilsPy, "commands_init.py": cowrieCommandsInitPy} {
		got, err := os.ReadFile(filepath.Join(cfg.DataPath, "honeypots", "cowrie", "patch", name))
		if err != nil || !bytes.Equal(got, content) {
			t.Errorf("patch/%s not written (err %v, %d bytes)", name, err, len(got))
		}
	}
}
