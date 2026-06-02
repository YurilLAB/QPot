package instance

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// The exact static identity every stock T-Pot Cowrie advertises. QPot must
// never emit these by default — they are a fingerprint.
const (
	tpotStaticSSHVersion = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
	tpotStaticHostname   = "srv01"
	cowrieDefaultHost    = "svr04"
)

func TestProfileForSeedDeterministic(t *testing.T) {
	a := profileForSeed("qp_instanceA")
	b := profileForSeed("qp_instanceA")
	if a != b {
		t.Error("profileForSeed not deterministic for the same seed")
	}
}

func TestProfileForSeedVariesAcrossInstances(t *testing.T) {
	// Across many distinct seeds we should see more than one profile and more
	// than one hostname selected (i.e. it actually varies, not a constant).
	profSeen := map[string]bool{}
	hostSeen := map[string]bool{}
	for _, s := range []string{
		"qp_a", "qp_b", "qp_c", "qp_d", "qp_e", "qp_f", "qp_g", "qp_h", "qp_i", "qp_j",
	} {
		profSeen[profileForSeed(s).SSHVersion] = true
		hostSeen[hostnameForSeed(s)] = true
	}
	if len(profSeen) < 2 {
		t.Errorf("distro profile does not vary across instances (%d distinct)", len(profSeen))
	}
	if len(hostSeen) < 2 {
		t.Errorf("hostname does not vary across instances (%d distinct)", len(hostSeen))
	}
}

// TestProfilesAreInternallyConsistentAndNonDefault checks every shipped profile
// is realistic (OpenSSH version, x86_64) and that none reproduces the T-Pot
// static fingerprint.
func TestProfilesAreInternallyConsistentAndNonDefault(t *testing.T) {
	for i, p := range distroProfiles {
		if !strings.HasPrefix(p.SSHVersion, "OpenSSH_") {
			t.Errorf("profile %d: SSHVersion %q not an OpenSSH string", i, p.SSHVersion)
		}
		if p.SSHVersion == tpotStaticSSHVersion {
			t.Errorf("profile %d reproduces the static T-Pot SSH version fingerprint", i)
		}
		if p.KernelVersion == "" || p.OperatingSystem == "" || p.HardwarePlatform == "" {
			t.Errorf("profile %d has empty uname fields (would be a tell)", i)
		}
	}
	for _, h := range realisticHostnames {
		if h == tpotStaticHostname || h == cowrieDefaultHost {
			t.Errorf("hostname pool contains a known-default hostname %q", h)
		}
	}
}

// TestCowrieConfigIsPerInstanceAndNonDefault renders the cowrie.cfg for two
// different instances and asserts (a) neither carries the static T-Pot SSH
// version, and (b) the two instances differ.
func TestCowrieConfigIsPerInstanceAndNonDefault(t *testing.T) {
	render := func(qpotID string) string {
		cfg := config.Default("deception-test")
		cfg.QPotID = qpotID
		g := &ComposeGenerator{Config: cfg}
		return g.generateCowrieConfig(cfg.Honeypots["cowrie"])
	}

	a := render("qp_aaaaaaaaaaaaaaaaaaaaaaa1")
	b := render("qp_bbbbbbbbbbbbbbbbbbbbbbb2")

	for _, c := range []string{a, b} {
		if strings.Contains(c, tpotStaticSSHVersion) {
			t.Error("cowrie.cfg advertises the static T-Pot SSH version (fingerprint)")
		}
		if strings.Contains(c, "hostname = server") || strings.Contains(c, "hostname = "+cowrieDefaultHost) {
			t.Error("cowrie.cfg uses a default/static hostname")
		}
		// Identity must be internally consistent: an ssh_version line and a
		// matching kernel line are both present.
		if !strings.Contains(c, "ssh_version = OpenSSH_") || !strings.Contains(c, "kernel_version = ") {
			t.Error("cowrie.cfg missing consistent ssh_version/kernel_version")
		}
	}
	if a == b {
		t.Error("two different instances produced identical cowrie.cfg (no per-instance variation)")
	}
}

// TestCowrieConfigRunsWithoutBreakingShell guards three bugs that each made
// Cowrie crash the interactive shell (or leak the default fingerprint) on every
// login while still passing the port-only healthcheck:
//
//  1. the advertised SSH protocol banner ([ssh] version) must be overridden -
//     [shell] ssh_version alone only changes the in-shell `ssh -V` output, not
//     what a scanner sees, so a missing [ssh] version leaks Cowrie's static
//     default banner (the single most-scanned fingerprint);
//  2. the [ssh] version banner must MATCH the per-instance ssh_version (an
//     internally inconsistent pair is itself a tell);
//  3. [shell] filesystem must point at the path the image actually ships
//     (src/cowrie/data/fs.pickle) - a wrong path makes Cowrie fail to load the
//     fake filesystem and kill the shell channel on login.
func TestCowrieConfigRunsWithoutBreakingShell(t *testing.T) {
	cfg := config.Default("cowrie-shell-test")
	cfg.QPotID = "qp_shelltest000000000001"
	g := &ComposeGenerator{Config: cfg}
	c := g.generateCowrieConfig(cfg.Honeypots["cowrie"])

	// (1) the protocol banner must be present.
	if !strings.Contains(c, "version = SSH-2.0-OpenSSH_") {
		t.Error("cowrie.cfg missing [ssh] version banner override; scanners would see Cowrie's static default")
	}
	// (2) the banner must match the shell's ssh_version (internal consistency).
	shellVer := lineValue(c, "ssh_version = ")
	bannerVer := strings.TrimPrefix(lineValue(c, "version = "), "SSH-2.0-")
	if shellVer == "" || bannerVer == "" || shellVer != bannerVer {
		t.Errorf("[ssh] version (%q) does not match [shell] ssh_version (%q)", bannerVer, shellVer)
	}
	// (3) the filesystem pickle path must be the one the image ships.
	if !strings.Contains(c, "filesystem = src/cowrie/data/fs.pickle") {
		t.Error("cowrie.cfg points [shell] filesystem at a path the image does not ship; the shell dies on login")
	}
}

// lineValue returns the trimmed value following the first occurrence of key
// (which should include the trailing "= ") on its own line.
func lineValue(s, key string) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, key) {
			return strings.TrimSpace(strings.TrimPrefix(ln, key))
		}
	}
	return ""
}

// TestGetTPOTConfigWiresStealthKnobs guards the previously-dropped fields.
func TestGetTPOTConfigWiresStealthKnobs(t *testing.T) {
	cfg := config.Default("tpotcfg-test")
	hp := cfg.Honeypots["cowrie"]
	hp.Stealth.Enabled = true
	hp.Stealth.RandomizeSSHVersion = true
	hp.Stealth.BannerString = "OpenSSH_9.3"
	hp.Stealth.AddArtificialDelay = true
	hp.Stealth.DelayRangeMs = 250
	cfg.Honeypots["cowrie"] = hp

	out := cfg.GetTPOTConfig("cowrie")
	for k, want := range map[string]string{
		"RANDOMIZE_SSH_VERSION": "1",
		"BANNER_STRING":         "OpenSSH_9.3",
		"ARTIFICIAL_DELAY":      "1",
		"DELAY_RANGE_MS":        "250",
	} {
		if out[k] != want {
			t.Errorf("GetTPOTConfig[%q] = %q, want %q (field was being dropped)", k, out[k], want)
		}
	}
}

// TestCowrieUserDBNoDefaultTell guards the research-backed removal of the
// phil/richard Cowrie userdb tell, and that the accept-policy is per-instance.
func TestCowrieUserDBNoDefaultTell(t *testing.T) {
	mk := func(id string) string {
		cfg := config.Default("udb")
		cfg.QPotID = id
		g := &ComposeGenerator{Config: cfg}
		return g.generateCowrieUserDB()
	}
	a := mk("qp_useruseruseruseruser01")
	b := mk("qp_xxxxxxxxxxxxxxxxxxxxx02")

	for _, db := range []string{a, b} {
		for _, tell := range []string{"phil:", "richard:", "fout:", "pi:x:raspberry"} {
			if strings.Contains(db, tell) {
				t.Errorf("userdb contains the default honeypot tell %q", tell)
			}
		}
		// No wildcard: "any password works for every account" is itself a tell.
		if strings.Contains(db, ":x:*") {
			t.Error("userdb uses a wildcard password (any-password-works tell)")
		}
		// Must contain at least one concrete credential line.
		if !strings.Contains(db, ":x:") {
			t.Error("userdb has no credential lines")
		}
	}
	// Two different instances should usually get different personas (10 of
	// them) — assert variation across a spread of seeds.
	seen := map[string]bool{}
	for _, id := range []string{"qp_a1", "qp_b2", "qp_c3", "qp_d4", "qp_e5", "qp_f6"} {
		seen[mk(id)] = true
	}
	if len(seen) < 2 {
		t.Error("credential persona does not vary across instances")
	}
}

// TestCredentialTemplates validates the 10 personas are realistic and free of
// known honeypot tells.
func TestCredentialTemplates(t *testing.T) {
	if len(credentialTemplates) < 10 {
		t.Fatalf("expected >=10 credential personas, got %d", len(credentialTemplates))
	}
	names := map[string]bool{}
	for _, tmpl := range credentialTemplates {
		if names[tmpl.Name] {
			t.Errorf("duplicate persona name %q", tmpl.Name)
		}
		names[tmpl.Name] = true
		if len(tmpl.Users) < 2 || len(tmpl.Users) > 6 {
			t.Errorf("persona %q has %d users; realistic boxes have ~2-6", tmpl.Name, len(tmpl.Users))
		}
		for _, u := range tmpl.Users {
			if u.Username == "" || len(u.Passwords) == 0 {
				t.Errorf("persona %q has an account with no username/passwords", tmpl.Name)
			}
			for _, bait := range []string{"phil", "richard", "hacker", "honeypot", "decoy"} {
				if u.Username == bait {
					t.Errorf("persona %q uses bait username %q", tmpl.Name, bait)
				}
			}
		}
	}
	// Explicit selection by name works; unknown name falls back to auto-select.
	if got := selectCredentialTemplate("iot-camera", "seed").Name; got != "iot-camera" {
		t.Errorf("explicit template selection failed: got %q", got)
	}
	if got := selectCredentialTemplate("does-not-exist", "seed").Name; got == "" {
		t.Error("unknown template name should fall back to a valid persona")
	}
}
