package instance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// TestCowriePatchPinned: the patch layer replaces whole files of one image
// release; a TPotVersion bump must re-check them before they are mounted over
// a different image.
func TestCowriePatchPinned(t *testing.T) {
	if cowriePatchVersion != TPotVersion {
		t.Fatalf("cowrie patch files were made from %s, the images are now %s: compare them with the new image",
			cowriePatchVersion, TPotVersion)
	}
	index, err := os.ReadFile("testdata/cowrie-image-index.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("sha256:%x", sha256.Sum256(index)); got != cowrieImageDigest {
		t.Fatalf("reviewed Cowrie image index digest %s differs from production %s", got, cowrieImageDigest)
	}
	var manifest struct {
		MediaType string `json:"mediaType"`
		Manifests []struct {
			Platform struct{ OS, Architecture string } `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(index, &manifest); err != nil {
		t.Fatal(err)
	}
	platforms := map[string]bool{}
	for _, entry := range manifest.Manifests {
		if entry.Platform.OS == "linux" {
			platforms[entry.Platform.Architecture] = true
		}
	}
	if manifest.MediaType != "application/vnd.oci.image.index.v1+json" || !platforms["amd64"] || !platforms["arm64"] {
		t.Fatal("reviewed Cowrie pin must support linux/amd64 and linux/arm64")
	}
	want := "ghcr.io/telekom-security/cowrie:" + cowriePatchVersion + "@" + cowrieImageDigest
	if got := GetHoneypotImage("cowrie"); got != want {
		t.Fatalf("Cowrie patch runtime uses %q, want immutable %q", got, want)
	}
	ci, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	hifiScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "test-hifi.sh"))
	if err != nil {
		t.Fatal(err)
	}
	ci = append(ci, hifiScript...)
	for _, image := range []string{want, CollectorImage, sshOrganizationDBImage} {
		if !bytes.Contains(ci, []byte("docker pull "+image)) {
			t.Fatalf("live CI does not pull the production image %s", image)
		}
	}
}

// TestCowriePatchMounts: every patched file is mounted read-only at the
// image's own path, with its content written by setup.
func TestCowriePatchMounts(t *testing.T) {
	want := map[string][]byte{
		cowrieSource + "/shell/protocol.py":        cowrieProtocolPy,
		cowrieSource + "/commands/ping.py":         cowriePingPy,
		cowrieSource + "/commands/coreutils.py":    cowrieCoreutilsPy,
		cowrieSource + "/commands/__init__.py":     cowrieCommandsInitPy,
		cowrieSource + "/commands/ssh.py":          cowrieSSHPy,
		cowrieSource + "/commands/awscli.py":       cowrieAWSCLIPy,
		cowrieSource + "/core/honeyfs.py":          cowrieHoneyfsPy,
		cowrieSource + "/core/qpot_bait.py":        cowrieQPotBaitPy,
		cowrieSource + "/commands/find.py":         cowrieFindPy,
		cowrieSource + "/commands/searchutils.py":  cowrieSearchutilsPy,
		cowrieSource + "/shell/bashparse.py":       cowrieBashparsePy,
		cowrieSource + "/commands/curl.py":         cowrieCurlPy,
		cowrieSource + "/commands/wget.py":         cowrieWgetPy,
		cowrieSource + "/commands/ls.py":           cowrieLsPy,
		cowrieSource + "/core/qpot_state.py":       cowrieStatePy,
		cowrieSource + "/commands/adduser.py":      cowrieAdduserPy,
		cowrieSource + "/commands/su.py":           cowrieSuPy,
		cowrieSource + "/commands/opkg.py":         cowrieOpkgPy,
		cowrieSource + "/core/qpot_permissions.py": cowriePermissionsPy,
		cowrieSource + "/commands/sudo.py":         cowrieSudoPy,
		cowrieSource + "/output/jsonlog.py":        cowrieJSONLogPy,
		cowrieSource + "/core/checkers.py":         cowrieCheckersPy,
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
		"/honeypots/cowrie/patch/searchutils.py:" + cowrieSource + "/commands/searchutils.py:ro\n",
		"/honeypots/cowrie/patch/bashparse.py:" + cowrieSource + "/shell/bashparse.py:ro\n",
		"/honeypots/cowrie/patch/curl.py:" + cowrieSource + "/commands/curl.py:ro\n",
		"/honeypots/cowrie/patch/wget.py:" + cowrieSource + "/commands/wget.py:ro\n",
		"/honeypots/cowrie/patch/ls.py:" + cowrieSource + "/commands/ls.py:ro\n",
		"/honeypots/cowrie/patch/qpot_state.py:" + cowrieSource + "/core/qpot_state.py:ro\n",
		"/honeypots/cowrie/patch/adduser.py:" + cowrieSource + "/commands/adduser.py:ro\n",
		"/honeypots/cowrie/patch/su.py:" + cowrieSource + "/commands/su.py:ro\n",
		"/honeypots/cowrie/patch/opkg.py:" + cowrieSource + "/commands/opkg.py:ro\n",
		"/honeypots/cowrie/patch/qpot_permissions.py:" + cowrieSource + "/core/qpot_permissions.py:ro\n",
		"/honeypots/cowrie/patch/sudo.py:" + cowrieSource + "/commands/sudo.py:ro\n",
		"/honeypots/cowrie/patch/checkers.py:" + cowrieSource + "/core/checkers.py:ro\n",
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
	if users := strings.Index(init, `"adduser",`); users < strings.Index(init, `"groups",`) || users > last ||
		strings.Count(init, `"adduser",`) != 1 {
		t.Error("commands/__init__.py must load the VFS-backed account commands after canned identity commands")
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
	// pathname expansion runs on every word that may glob, with one bound for the whole command;
	// fnmatch's cache of compiled patterns is capped when the parser loads
	bashparse := string(cowrieBashparsePy)
	for _, want := range []string{"qpot_budget = [self.QPOT_GLOB_SCAN, self.QPOT_GLOB_BYTES]", "split=not whole, qpot_budget=qpot_budget)",
		"self.qpot_pathnames(text, mask, qpot_budget)", "masked = self.qpot_split_masked(pieces, qpot_globbing)",
		"\n\nqpot_cap_fnmatch_cache()\n"} {
		if strings.Count(bashparse, want) != 1 {
			t.Errorf("bashparse.py lacks %q", want)
		}
	}
	if !strings.Contains(string(cowrieAWSCLIPy), `"cowrie.credentials.use"`) {
		t.Errorf("awscli.py does not log the credentials it uses")
	}
	if !strings.Contains(string(cowrieCoreutilsPy), "(Command_zcat, qpot_bin(\"zcat\"))") {
		t.Errorf("coreutils.py does not answer zcat")
	}
	// the shell expands patterns; a command that did it again would expand a quoted one
	if strings.Contains(string(cowrieCoreutilsPy), "fnmatch") {
		t.Errorf("coreutils.py matches patterns of its own")
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
		"find.py": cowrieFindPy, "searchutils.py": cowrieSearchutilsPy, "bashparse.py": cowrieBashparsePy, "curl.py": cowrieCurlPy,
		"wget.py": cowrieWgetPy, "ls.py": cowrieLsPy, "qpot_state.py": cowrieStatePy,
		"adduser.py": cowrieAdduserPy, "su.py": cowrieSuPy, "opkg.py": cowrieOpkgPy, "qpot_permissions.py": cowriePermissionsPy, "sudo.py": cowrieSudoPy, "jsonlog.py": cowrieJSONLogPy, "checkers.py": cowrieCheckersPy} {
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
		"find.py": cowrieFindPy, "searchutils.py": cowrieSearchutilsPy, "bashparse.py": cowrieBashparsePy, "curl.py": cowrieCurlPy,
		"wget.py": cowrieWgetPy, "ls.py": cowrieLsPy, "qpot_state.py": cowrieStatePy,
		"adduser.py": cowrieAdduserPy, "su.py": cowrieSuPy, "opkg.py": cowrieOpkgPy, "qpot_permissions.py": cowriePermissionsPy, "sudo.py": cowrieSudoPy, "jsonlog.py": cowrieJSONLogPy, "checkers.py": cowrieCheckersPy} {
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

// deception=stock is the control arm of a comparison: the image's Cowrie as
// shipped. Nothing of QPot's may be mounted over its source, and no bait.
func TestCowrieStockIsTheImageAsShipped(t *testing.T) {
	cfg := config.Default("cowrie-stock")
	enableOnly(cfg, "cowrie")
	overSource := func(d honeypotDeploy) (n int, bait bool) {
		for _, v := range d.Volumes {
			if strings.HasPrefix(v.ContainerPath, cowrieSource+"/") {
				n++
			}
			if v.ContainerPath == baitPlanPath {
				bait = true
			}
		}
		return n, bait
	}
	// Control: the default mounts the patch layer and the bait plan.
	if n, bait := overSource(deployProfile(cfg, "cowrie")); n != len(cowriePatchVolumes()) || !bait || !baitOn(cfg) {
		t.Fatalf("default cowrie: %d patch mounts (want %d), bait plan %v, bait on %v", n, len(cowriePatchVolumes()), bait, baitOn(cfg))
	}

	hp := cfg.Honeypots["cowrie"]
	hp.CustomConfig = map[string]string{cowrieDeceptionSetting: "stock"}
	cfg.Honeypots["cowrie"] = hp
	d := deployProfile(cfg, "cowrie")
	if n, bait := overSource(d); n != 0 || bait {
		t.Errorf("stock cowrie still has %d mounts over the image's source (bait plan %v)", n, bait)
	}
	if baitOn(cfg) {
		t.Error("stock cowrie still counts as carrying bait")
	}
	have := map[string]bool{}
	for _, v := range d.Volumes {
		have[v.ContainerPath] = true
	}
	for _, need := range []string{"/home/cowrie/cowrie/etc", "/home/cowrie/cowrie/log", "/home/cowrie/cowrie/dl"} {
		if !have[need] {
			t.Errorf("stock cowrie lost the mount %s it needs to run and be collected", need)
		}
	}
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	compose, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(compose, cowrieSource+"/") || strings.Contains(compose, baitPlanPath) {
		t.Error("the compose file of a stock instance mounts QPot files into cowrie")
	}
	// The same containment as any other instance.
	for _, need := range []string{"read_only: true", "no-new-privileges", "cap_drop"} {
		if !strings.Contains(compose, need) {
			t.Errorf("the compose file of a stock instance lacks %q", need)
		}
	}
	if err := CheckSetting("cowrie", cowrieDeceptionSetting, "stock"); err != nil {
		t.Errorf("deception=stock is refused: %v", err)
	}
	if err := CheckSetting("cowrie", cowrieDeceptionSetting, "none"); err == nil {
		t.Error("deception=none is accepted")
	}
}
