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
