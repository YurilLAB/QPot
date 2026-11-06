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
		cowrieSource + "/commands/ssh.py":       cowrieSSHPy,
		cowrieSource + "/commands/awscli.py":    cowrieAWSCLIPy,
		cowrieSource + "/core/honeyfs.py":       cowrieHoneyfsPy,
		cowrieSource + "/core/qpot_bait.py":     cowrieQPotBaitPy,
		cowrieSource + "/commands/find.py":      cowrieFindPy,
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
		"/honeypots/cowrie/patch/ssh.py:" + cowrieSource + "/commands/ssh.py:ro\n",
		"/honeypots/cowrie/patch/awscli.py:" + cowrieSource + "/commands/awscli.py:ro\n",
		"/honeypots/cowrie/patch/honeyfs.py:" + cowrieSource + "/core/honeyfs.py:ro\n",
		"/honeypots/cowrie/patch/qpot_bait.py:" + cowrieSource + "/core/qpot_bait.py:ro\n",
		"/honeypots/cowrie/patch/find.py:" + cowrieSource + "/commands/find.py:ro\n",
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
	for _, module := range []string{`"base",`, `"bash",`, `"ping",`, `"netstat",`, `"uname",`, `"ssh",`} {
		if !strings.Contains(init, module) {
			t.Errorf("commands/__init__.py lost %s", module)
		}
	}
	if aws := strings.Index(init, `"awscli",`); aws < 0 || aws > last {
		t.Errorf("commands/__init__.py does not load awscli (before coreutils)")
	}
	// the bait: honeyfs plants it once when it loads the tree, a broken plan
	// never stops the tree from loading; the history file is read at login;
	// ssh times out on the bait's hosts and logs what is typed at its prompts
	honeyfs := string(cowrieHoneyfsPy)
	plant := strings.Index(honeyfs, "qpot_bait.plant(tree)")
	if plant < 0 || !strings.Contains(honeyfs[:plant], "try:") || !strings.Contains(honeyfs[plant:], "except Exception") ||
		!strings.Contains(honeyfs, "@functools.cache\ndef _tree()") {
		t.Errorf("honeyfs.py does not plant the bait once, guarded")
	}
	if !strings.Contains(string(cowrieQPotBaitPy), `PLAN_PATH = "`+baitPlanPath+`"`) {
		t.Errorf("qpot_bait.py reads the plan from elsewhere than it is mounted")
	}
	if p := string(cowrieProtocolPy); !strings.Contains(p, "self.qpot_read_history()") || !strings.Contains(p, "QPOT_HISTFILE_MAX") {
		t.Errorf("protocol.py does not read the history file at login")
	}
	sshPy := string(cowrieSSHPy)
	for _, want := range []string{"qpot_bait.internal_host(host)", `"cowrie.command.input"`, `realm="ssh"`, "def handle_CTRL_C",
		"self.qpot_log_identities(optlist, user, host)"} {
		if !strings.Contains(sshPy, want) {
			t.Errorf("ssh.py lacks %q", want)
		}
	}
	if !strings.Contains(string(cowrieAWSCLIPy), `"cowrie.credentials.use"`) {
		t.Errorf("awscli.py does not log the credentials it uses")
	}
	if !strings.Contains(string(cowrieCoreutilsPy), "(Command_zcat, qpot_bin(\"zcat\"))") {
		t.Errorf("coreutils.py does not answer zcat")
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
		"coreutils.py": cowrieCoreutilsPy, "commands_init.py": cowrieCommandsInitPy, "ssh.py": cowrieSSHPy,
		"awscli.py": cowrieAWSCLIPy, "honeyfs.py": cowrieHoneyfsPy, "qpot_bait.py": cowrieQPotBaitPy,
		"find.py": cowrieFindPy} {
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
		"coreutils.py": cowrieCoreutilsPy, "commands_init.py": cowrieCommandsInitPy, "ssh.py": cowrieSSHPy,
		"awscli.py": cowrieAWSCLIPy, "honeyfs.py": cowrieHoneyfsPy, "qpot_bait.py": cowrieQPotBaitPy,
		"find.py": cowrieFindPy} {
		got, err := os.ReadFile(filepath.Join(cfg.DataPath, "honeypots", "cowrie", "patch", name))
		if err != nil || !bytes.Equal(got, content) {
			t.Errorf("patch/%s not written (err %v, %d bytes)", name, err, len(got))
		}
	}
	plan, err := os.ReadFile(filepath.Join(cfg.DataPath, "honeypots", "cowrie", "bait", "plan.json"))
	if err != nil || !bytes.Equal(plan, cowrieBaitJSON(cfg)) {
		t.Errorf("bait/plan.json not written (err %v, %d bytes)", err, len(plan))
	}
}
