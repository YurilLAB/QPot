package instance

import (
	"strconv"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// FuzzCowriePersonaSettings drives Cowrie's persona settings (custom_config
// persona / persona_rotation, which `qpot honeypot set` validates but a
// hand-edited config does not) and hostile stealth strings through the compose
// generator. The image's launcher refuses to start on a persona it does not
// know or a rotation outside 0-365 days, so whatever the config holds, the
// rendered cowrie service must carry exactly one known COWRIE_PERSONA and one
// in-range COWRIE_PERSONA_ROTATION, and none of the stealth knobs may reach the
// container environment.
func FuzzCowriePersonaSettings(f *testing.F) {
	f.Add("debian-bookworm", "30", "web01", "Windows Server 2019")
	f.Add("ubuntu-noble\nCOWRIE_PERSONA=evil", "365\n- X=1", "x\nauth_class = none", "")
	f.Add("doesnotexist", "-1", "", "")
	f.Add("", "1000", "", "")
	f.Add("ipcam", " 7 ", "\x00\x07ctrl", "héllo")
	f.Add(strings.Repeat("A", 5000), "0x10", "", "")

	f.Fuzz(func(t *testing.T, persona, rotation, host, fakeOS string) {
		cfg := config.Default("cowrie-persona-fuzz")
		cfg.QPotID = "qp_cowriepersonafuzz0000001"
		hp := cfg.Honeypots["cowrie"]
		hp.Enabled = true
		hp.Stealth.Enabled = true
		hp.Stealth.FakeHostname = host
		hp.Stealth.FakeOS = fakeOS
		hp.Stealth.BannerString = fakeOS
		hp.CustomConfig = map[string]string{"persona": persona, "persona_rotation": rotation}
		cfg.Honeypots["cowrie"] = hp

		sb, err := security.NewSandbox(&cfg.Security)
		if err != nil {
			t.Skip()
		}
		out, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		svc := composeService(t, out, "cowrie")

		var personas, rotations []string
		for _, ln := range strings.Split(svc, "\n") {
			ln = strings.TrimSpace(ln)
			if v, ok := strings.CutPrefix(ln, "- COWRIE_PERSONA="); ok {
				personas = append(personas, v)
			}
			if v, ok := strings.CutPrefix(ln, "- COWRIE_PERSONA_ROTATION="); ok {
				rotations = append(rotations, v)
			}
		}
		if len(personas) != 1 || !containsString(CowriePersonaIDs(), personas[0]) {
			t.Fatalf("COWRIE_PERSONA lines %q: want exactly one known persona (config persona=%q)", personas, persona)
		}
		if len(rotations) != 1 {
			t.Fatalf("COWRIE_PERSONA_ROTATION lines %q: want exactly one", rotations)
		}
		days, err := strconv.Atoi(rotations[0])
		if err != nil || days < 0 || days > cowriePersonaMaxRotation {
			t.Fatalf("COWRIE_PERSONA_ROTATION=%q is outside 0-%d (config %q)", rotations[0], cowriePersonaMaxRotation, rotation)
		}
		// A valid configured persona is used as given; anything else falls back
		// to the seed pick (a server persona).
		if containsString(CowriePersonaIDs(), persona) && personas[0] != persona {
			t.Fatalf("configured persona %q ignored, got %q", persona, personas[0])
		}
		if want, ok := parsePersonaRotation(rotation); ok && want != days {
			t.Fatalf("configured rotation %q ignored, got %d", rotation, days)
		}
		// CheckSetting (what the CLI enforces) must agree with what compose
		// accepts, or `qpot honeypot set` could store a value that is then
		// silently replaced.
		_, rotOK := parsePersonaRotation(rotation)
		if (CheckSetting("cowrie", "persona_rotation", rotation) == nil) != (rotOK || rotation == "") {
			t.Fatalf("CheckSetting and parsePersonaRotation disagree on %q", rotation)
		}
		for _, leak := range []string{"FAKE_HOSTNAME", "FAKE_OS", "FAKE_KERNEL", "BANNER_STRING", "RANDOMIZE_SSH_VERSION", "ARTIFICIAL_DELAY"} {
			if strings.Contains(out, "- "+leak+"=") {
				t.Fatalf("compose leaks %s into a container environment", leak)
			}
		}
	})
}

// composeService returns the text of one service block of a generated compose
// (from its "  name:" line to the next top-level service).
func composeService(t *testing.T, compose, name string) string {
	t.Helper()
	start := strings.Index(compose, "\n  "+name+":\n")
	if start < 0 {
		t.Fatalf("service %q not in compose", name)
	}
	rest := compose[start+1:]
	lines := strings.Split(rest, "\n")
	var b strings.Builder
	for i, ln := range lines {
		if i > 0 && len(ln) > 2 && ln[:2] == "  " && ln[2] != ' ' && ln[2] != '#' && strings.HasSuffix(ln, ":") {
			break
		}
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return b.String()
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
