package instance

import (
	"fmt"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// Known defaults that are themselves fingerprints: QPot must never emit them.
const (
	tpotStaticHostname = "srv01"
	cowrieDefaultHost  = "svr04"
)

// cowrieCfg returns a default config whose cowrie custom_config is set to kv.
func cowrieCfg(id string, kv map[string]string) *config.Config {
	cfg := config.Default("cowrie-persona")
	cfg.QPotID = id
	hp := cfg.Honeypots["cowrie"]
	hp.CustomConfig = kv
	cfg.Honeypots["cowrie"] = hp
	return cfg
}

func isServerPersona(id string) bool {
	for _, p := range tpotCowriePersonas {
		if p.ID == id {
			return p.Server
		}
	}
	return false
}

// TestCowriePersonaPerInstance: without a pinned persona every instance gets a
// server persona picked from its own seed - stable for one instance (a restart
// must not turn the box into another kind of machine) and varying across
// instances (no shared signature). Embedded-device personas, some of which run
// no SSH server at all, are never picked automatically.
func TestCowriePersonaPerInstance(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		cfg := cowrieCfg(fmt.Sprintf("qp_personaspread%010d", i), nil)
		p := cowriePersona(cfg)
		if !isServerPersona(p) {
			t.Fatalf("instance %d got %q, want a server persona", i, p)
		}
		if again := cowriePersona(cfg); again != p {
			t.Fatalf("persona not stable for one instance: %q then %q", p, again)
		}
		seen[p] = true
	}
	servers := 0
	for _, p := range tpotCowriePersonas {
		if p.Server {
			servers++
		}
	}
	if len(seen) != servers {
		t.Errorf("200 instances drew %d of %d server personas: %v", len(seen), servers, seen)
	}
}

// TestCowriePersonaPinned: a persona the image knows is used as given (devices
// included); anything else falls back to the seed pick, because the image's
// launcher refuses to start on an ID it does not know.
func TestCowriePersonaPinned(t *testing.T) {
	for _, id := range CowriePersonaIDs() {
		if got := cowriePersona(cowrieCfg("qp_pinned00000000000001", map[string]string{"persona": id})); got != id {
			t.Errorf("pinned persona %q ignored, got %q", id, got)
		}
	}
	auto := cowriePersona(cowrieCfg("qp_pinned00000000000001", nil))
	for _, bad := range []string{"web-hosting", "Debian-Bookworm", "debian-bookworm\n", "ubuntu", " "} {
		if got := cowriePersona(cowrieCfg("qp_pinned00000000000001", map[string]string{"persona": bad})); got != auto {
			t.Errorf("unknown persona %q gave %q, want the seed pick %q", bad, got, auto)
		}
	}
	if err := CheckSetting("cowrie", "persona", "web-hosting"); err == nil {
		t.Error("qpot honeypot set accepted a persona the image does not know")
	}
	if err := CheckSetting("cowrie", "persona", "ipcam"); err != nil {
		t.Errorf("valid persona refused: %v", err)
	}
}

// TestCowriePersonaRotation: the image draws a new identity on every start by
// default; QPot keeps it for the longest time the image accepts (365 days)
// unless persona_rotation is a value the image accepts.
func TestCowriePersonaRotation(t *testing.T) {
	cases := map[string]int{
		"": 365, "0": 0, "30": 30, " 7 ": 7, "365": 365, "007": 7,
		"366": 365, "-1": 365, "1e2": 365, "30d": 365, "0x10": 365, "99999999999999999999": 365,
	}
	for in, want := range cases {
		got := cowriePersonaRotation(cowrieCfg("qp_rotation0000000000001", map[string]string{"persona_rotation": in}))
		if got != want {
			t.Errorf("persona_rotation %q -> %d, want %d", in, got, want)
		}
		_, ok := parsePersonaRotation(in)
		if (CheckSetting("cowrie", "persona_rotation", in) == nil) != (ok || in == "") {
			t.Errorf("CheckSetting and compose disagree on persona_rotation %q", in)
		}
	}
}

// TestCowrieRunsImagePersonaLauncher: the cowrie service must run the image's
// own launcher (no command/working_dir override) with the persona in its
// environment, and must not mount any of QPot's former config/fake-fs files
// over the image: on 24.04.2 those overrides left /.dockerenv visible, removed
// /etc/os-release and broke mount/dmesg/lsblk, dpkg, systemctl and python3.
// The only files it mounts are the patch layer's Cowrie sources and the bait
// plan, a file the image does not have that the patch layer reads.
func TestCowrieRunsImagePersonaLauncher(t *testing.T) {
	d := deployProfileFor("cowrie")
	patch := map[string]bool{}
	for _, v := range cowriePatchVolumes() {
		patch[v.ContainerPath] = true
	}
	for _, v := range d.Volumes {
		if v.File && patch[v.ContainerPath] && strings.HasPrefix(v.ContainerPath, cowrieSource+"/") {
			continue
		}
		if v.File && v.ReadOnly && v.ContainerPath == baitPlanPath {
			continue
		}
		if v.File || strings.Contains(v.ContainerPath, "honeyfs") || strings.HasPrefix(v.ContainerPath, "/proc") {
			t.Errorf("cowrie mounts %s over the image", v.ContainerPath)
		}
	}
	cfg := cowrieCfg("qp_launcher0000000000001", map[string]string{"persona": "rhel-9", "persona_rotation": "90"})
	sb, _ := security.NewSandbox(&cfg.Security)
	out, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	svc := composeService(t, out, "cowrie")
	for _, want := range []string{"- COWRIE_PERSONA=rhel-9\n", "- COWRIE_PERSONA_ROTATION=90\n"} {
		if !strings.Contains(svc, want) {
			t.Errorf("cowrie service lacks %q", strings.TrimSpace(want))
		}
	}
	// the patch layer's own sources (core/honeyfs.py among them) aside
	var rest []string
	for _, ln := range strings.Split(svc, "\n") {
		src := false
		for p := range patch {
			src = src || strings.HasSuffix(strings.TrimSpace(ln), ":"+p+":ro")
		}
		if !src {
			rest = append(rest, ln)
		}
	}
	for _, bad := range []string{"command:", "working_dir:", "qpot_patch_fs", "cowrie.cfg", "/proc/meminfo", "honeyfs"} {
		if strings.Contains(strings.Join(rest, "\n"), bad) {
			t.Errorf("cowrie service still renders %q", bad)
		}
	}
	if n := strings.Count(out, "COWRIE_PERSONA="); n != 1 {
		t.Errorf("COWRIE_PERSONA rendered %d times, want only on the cowrie service", n)
	}
}

// TestHostnamePersonaCoherence guards the "no persona/host mismatch" invariant:
// the auto-derived hostname must belong to the SAME persona the HiFi backends
// enforce, so the shell prompt/etc agree with the accounts that work. Before this, hostname
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

	// Deterministic for a fixed seed (two separate calls; kept in vars so the
	// determinism check is not a literal X != X that staticcheck SA4000 flags).
	p := selectCredentialTemplate("", "qp_stable")
	first := hostnameForPersona(p, "qp_stable")
	second := hostnameForPersona(p, "qp_stable")
	if first != second {
		t.Errorf("hostnameForPersona not deterministic for a fixed seed: %q != %q", first, second)
	}

	// Every persona's hostname pool must be safe for the ssh-proxy backends'
	// hostname: field (sanitizeHostname), and must not reintroduce a
	// known-default hostname.
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

// Auto-selected credential personas must fit the HiFi backend's x86_64 server
// hardware; ARM/MIPS appliance personas are only used when chosen explicitly.
func TestAutoPersonaMatchesServerHardware(t *testing.T) {
	for i := 0; i < 2000; i++ {
		seed := fmt.Sprintf("qp_seed_%d", i)
		if p := selectCredentialTemplate("", seed); embeddedHardwarePersonas[p.Name] {
			t.Fatalf("seed %q auto-selected appliance persona %q on x86_64 server hardware", seed, p.Name)
		}
	}
	if p := selectCredentialTemplate("raspberry-pi", "x"); p.Name != "raspberry-pi" {
		t.Errorf("explicit persona not honoured: got %q", p.Name)
	}
	for name := range embeddedHardwarePersonas {
		if _, ok := credentialTemplateByName(name); !ok {
			t.Errorf("embeddedHardwarePersonas lists unknown persona %q", name)
		}
	}
}

// The QPot ID is the web UI credential; the attacker-visible deception seed must
// be a one-way derivation of it, never the ID itself, and nothing rendered for
// a honeypot may carry it.
func TestDeceptionSeedDoesNotExposeQPotID(t *testing.T) {
	cfg := config.Default("seed-test")
	cfg.QPotID = "qp_secretcredential0000001"
	s := deceptionSeed(cfg)
	if strings.Contains(s, "secretcredential") || s == cfg.QPotID {
		t.Fatalf("deception seed %q exposes the QPot ID", s)
	}
	if s != deceptionSeed(cfg) {
		t.Fatal("deception seed is not stable")
	}
	other := config.Default("seed-test")
	other.QPotID = "qp_othercredential00000002"
	if deceptionSeed(other) == s {
		t.Fatal("different QPot IDs share a deception seed")
	}
	for name, out := range map[string]string{
		"conpot":       conpotTemplate(cfg).ID,
		"ssh hostname": sshBackendHostname(cfg),
		"ssh users":    sshBackendUsersCSV(cfg),
		"persona":      cowriePersona(cfg),
	} {
		if strings.Contains(out, cfg.QPotID) || strings.Contains(out, "secretcredential") {
			t.Errorf("%s contains the QPot ID", name)
		}
	}
}
