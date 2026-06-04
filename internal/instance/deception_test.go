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
	// (4) SSH host keys must live under the writable etc/ mount, not cowrie's
	// read-only working dir, or key generation crashes the whole SSH service on
	// a read-only root. Persisting them there also keeps the fingerprint stable.
	for _, k := range []string{
		"rsa_private_key = etc/", "ecdsa_private_key = etc/", "ed25519_private_key = etc/",
	} {
		if !strings.Contains(c, k) {
			t.Errorf("cowrie.cfg missing writable host-key path %q; SSH key gen will fail on read-only root", k)
		}
	}
}

// TestCowrieSSHAlgorithmsNormalized verifies QPot overrides Cowrie's
// fingerprintable default SSH algorithm lists with a modern-OpenSSH-like set.
// Stock Cowrie advertises legacy ciphers (blowfish-cbc/cast128-cbc) and a
// MALFORMED "hmac-sha2-56" MAC name that no real server sends - both are strong
// tells and they also pin the well-known, blocklisted stock-Cowrie HASSH. The
// override must (a) be present, (b) restrict ciphers to the modern CTR set,
// (c) use only well-formed SHA-2 MAC names, and (d) never reintroduce a tell.
func TestCowrieSSHAlgorithmsNormalized(t *testing.T) {
	cfg := config.Default("cowrie-algos")
	cfg.QPotID = "qp_algos00000000000000001"
	g := &ComposeGenerator{Config: cfg}
	c := g.generateCowrieConfig(cfg.Honeypots["cowrie"])

	ciphers := lineValue(c, "ciphers = ")
	macs := lineValue(c, "macs = ")
	comp := lineValue(c, "compression = ")
	if ciphers == "" || macs == "" || comp == "" {
		t.Fatalf("cowrie.cfg missing normalized algorithm lists: ciphers=%q macs=%q compression=%q", ciphers, macs, comp)
	}
	// (b) ciphers: only the modern CTR set (no legacy cbc/blowfish/cast128/3des).
	if ciphers != "aes128-ctr,aes192-ctr,aes256-ctr" {
		t.Errorf("ciphers = %q, want the modern CTR-only set", ciphers)
	}
	// (d) the dead-giveaway tells must be gone from the actual config VALUES
	// (comment text may legitimately name them when explaining the override).
	var values strings.Builder
	for _, ln := range strings.Split(c, "\n") {
		if t := strings.TrimSpace(ln); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		values.WriteString(ln)
		values.WriteString("\n")
	}
	for _, tell := range []string{"blowfish-cbc", "cast128-cbc", "hmac-sha2-56", "hmac-md5"} {
		if strings.Contains(values.String(), tell) {
			t.Errorf("cowrie.cfg still advertises the fingerprint tell %q", tell)
		}
	}
	// (c) every MAC must be a well-formed name (sha2-256/512 or sha1), not the
	// malformed "sha2-56".
	for _, m := range strings.Split(macs, ",") {
		switch m {
		case "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1":
		default:
			t.Errorf("unexpected/ malformed MAC %q in %q", m, macs)
		}
	}
	// compression: OpenSSH lists none first; "zlib" (bare) is not an OpenSSH algo.
	if comp != "none,zlib@openssh.com" {
		t.Errorf("compression = %q, want %q", comp, "none,zlib@openssh.com")
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

// TestConpotSensorIDNonIdentifying guards that the Conpot sensor_id is
// per-instance and never embeds a token that flags the box as QPot/T-Pot/a
// honeypot (the stock value was the literal "qpot-conpot").
func TestConpotSensorIDNonIdentifying(t *testing.T) {
	a := conpotSensorIDForSeed("qp_aaaaaaaaaaaaaaaaaaaa1")
	b := conpotSensorIDForSeed("qp_bbbbbbbbbbbbbbbbbbbb2")
	if a == b {
		t.Error("conpot sensor_id is not per-instance")
	}
	if a != conpotSensorIDForSeed("qp_aaaaaaaaaaaaaaaaaaaa1") {
		t.Error("conpot sensor_id is not deterministic for a fixed seed")
	}
	for _, id := range []string{a, b} {
		low := strings.ToLower(id)
		for _, tell := range []string{"qpot", "conpot", "honeypot", "honey"} {
			if strings.Contains(low, tell) {
				t.Errorf("conpot sensor_id %q leaks self-identifying token %q", id, tell)
			}
		}
	}
	// And the generated conpot.cfg must carry it, not the old static value.
	cfg := config.Default("conpot-id-test")
	cfg.QPotID = "qp_conpotseed00000000001"
	g := &ComposeGenerator{Config: cfg}
	c := g.generateConpotConfig(cfg.Honeypots["conpot"])
	if strings.Contains(c, "qpot-conpot") {
		t.Error("conpot.cfg still contains the self-identifying sensor_id 'qpot-conpot'")
	}
	if !strings.Contains(c, conpotSensorIDForSeed("qp_conpotseed00000000001")) {
		t.Error("conpot.cfg does not contain the per-instance sensor_id")
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

// TestHostnamePersonaCoherence guards the "no persona/host mismatch" invariant:
// the auto-derived hostname must belong to the SAME persona Cowrie enforces, so
// the shell prompt/etc agree with the accounts that work. Before this, hostname
// and persona were drawn from independent salts, so a voip-pbx persona could
// present "db-prod" - a contradiction a human attacker would spot.
func TestHostnamePersonaCoherence(t *testing.T) {
	// Every persona that has a hostname pool must draw its derived hostname from
	// THAT pool, for a spread of seeds.
	for _, seed := range []string{"qp_a1", "qp_b2", "qp_c3", "qp_d4", "qp_e5", "qp_f6", "qp_g7", "qp_h8"} {
		persona := selectCredentialTemplate("", seed)
		got := hostnameForPersona(persona, seed)
		pool := personaHostnames[persona.Name]
		if len(pool) == 0 {
			continue // persona intentionally uses the generic fallback
		}
		found := false
		for _, h := range pool {
			if h == got {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("seed %s: persona %q got hostname %q outside its pool %v", seed, persona.Name, got, pool)
		}
	}

	// Every key in personaHostnames must name a real persona. A typo'd key would
	// never match and the persona would silently fall back to the generic pool,
	// quietly reintroducing the mismatch this map exists to prevent.
	for name := range personaHostnames {
		if _, ok := credentialTemplateByName(name); !ok {
			t.Errorf("personaHostnames key %q does not match any credential persona (typo? renamed persona?)", name)
		}
	}

	// Deterministic for a fixed seed.
	p := selectCredentialTemplate("", "qp_stable")
	if hostnameForPersona(p, "qp_stable") != hostnameForPersona(p, "qp_stable") {
		t.Error("hostnameForPersona not deterministic for a fixed seed")
	}

	// Every persona's hostname pool must be sanitize-safe for BOTH the cowrie.cfg
	// path (sanitizeConfigValue) and the ssh-proxy hostname: field (sanitizeHostname),
	// and must not reintroduce a known-default hostname.
	for name, pool := range personaHostnames {
		for _, h := range pool {
			if h == "" {
				t.Errorf("persona %q has an empty hostname", name)
			}
			if sanitizeHostname(h) != h {
				t.Errorf("persona %q hostname %q is not a clean DNS/Linux hostname (sanitizeHostname=%q)", name, h, sanitizeHostname(h))
			}
			if h == tpotStaticHostname || h == cowrieDefaultHost {
				t.Errorf("persona %q reuses a known-default hostname %q", name, h)
			}
		}
	}

	// The whole point: across instances we should see the derived cowrie hostname
	// land inside the active persona's pool, end to end through the renderer.
	for _, id := range []string{"qp_e2e0000000000000000001", "qp_e2e0000000000000000002", "qp_e2e0000000000000000003"} {
		cfg := config.Default("coherence")
		cfg.QPotID = id
		g := &ComposeGenerator{Config: cfg}
		c := g.generateCowrieConfig(cfg.Honeypots["cowrie"])
		host := lineValue(c, "hostname = ")
		persona := selectCredentialTemplate("", id)
		pool := personaHostnames[persona.Name]
		if len(pool) == 0 {
			continue
		}
		inPool := false
		for _, h := range pool {
			if h == host {
				inPool = true
				break
			}
		}
		if !inPool {
			t.Errorf("instance %s: cowrie.cfg hostname %q not in persona %q pool %v", id, host, persona.Name, pool)
		}
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
