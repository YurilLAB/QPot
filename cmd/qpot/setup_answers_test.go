package main

import (
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/qpot/qpot/internal/config"
)

func TestParseInstanceAnswer(t *testing.T) {
	for _, ok := range []string{"default", "sensor1", "a", "A-b_c", strings.Repeat("x", 32), "  padded  "} {
		if _, err := parseInstanceAnswer(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-x", "_x", "a b", "../etc", "a/b", `a\b`, strings.Repeat("x", 33), "x;rm", "name!", "é"} {
		if _, err := parseInstanceAnswer(bad); err == nil || err.Code != "QP-INPUT-001" {
			t.Errorf("%q accepted (%v)", bad, err)
		}
	}
}

func TestParseHoneypotsAnswer(t *testing.T) {
	prof, hps, err := parseHoneypotsAnswer(" Standard ")
	if err != nil || prof != "standard" || strings.Join(hps, ",") != strings.Join(setupProfiles["standard"], ",") {
		t.Fatalf("profile: %s %v %v", prof, hps, err)
	}
	prof, hps, err = parseHoneypotsAnswer("dionaea, cowrie cowrie;endlessh")
	if err != nil || prof != "custom" || strings.Join(hps, ",") != "cowrie,dionaea,endlessh" {
		t.Fatalf("list: %s %v %v", prof, hps, err)
	}
	// A list that is exactly a profile is called by its name.
	prof, hps, err = parseHoneypotsAnswer("endlessh, cowrie")
	if err != nil || prof != "minimal" || strings.Join(hps, ",") != "cowrie,endlessh" {
		t.Fatalf("profile as a list: %s %v %v", prof, hps, err)
	}
	if _, _, err := parseHoneypotsAnswer("minimall"); err == nil || err.Code != "QP-INPUT-002" {
		t.Errorf("mistyped profile: %v", err)
	}
	if _, _, err := parseHoneypotsAnswer("cowrie,nosuchpot"); err == nil || err.Code != "QP-INPUT-003" {
		t.Errorf("unknown honeypot: %v", err)
	}
	if _, _, err := parseHoneypotsAnswer(" , ;"); err == nil || err.Code != "QP-INPUT-003" {
		t.Errorf("empty list: %v", err)
	}
	for name, hps := range setupProfiles {
		for _, h := range hps {
			if _, ok := config.Default("x").Honeypots[h]; !ok {
				t.Errorf("profile %s names unknown honeypot %s", name, h)
			}
		}
	}
}

func TestParsePortAnswer(t *testing.T) {
	for in, want := range map[string]int{"8080": 8080, " 1 ": 1, "65535": 65535, "00080": 80} {
		if got, err := parsePortAnswer(in); err != nil || got != want {
			t.Errorf("%q = %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0", "65536", "-1", "+80", "80a", "8 0", "1e3", "999999", "٣٣"} {
		if _, err := parsePortAnswer(bad); err == nil || err.Code != "QP-INPUT-004" {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseBindAnswer(t *testing.T) {
	local := []netip.Addr{netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("fe80::1")}
	cases := []struct {
		in   string
		want string
		exp  bindExposure
	}{
		{"127.0.0.1", "127.0.0.1", bindLocal},
		{"localhost", "127.0.0.1", bindLocal},
		{"::1", "::1", bindLocal},
		{"[::1]", "::1", bindLocal},
		{"127.0.0.5", "127.0.0.5", bindLocal},
		{"0.0.0.0", "0.0.0.0", bindAll},
		{"::", "::", bindAll},
		{"192.168.1.20", "192.168.1.20", bindNetwork},
		{"::ffff:127.0.0.1", "127.0.0.1", bindLocal},
	}
	for _, c := range cases {
		got, exp, err := parseBindAnswer(c.in, local)
		if err != nil || got != c.want || exp != c.exp {
			t.Errorf("%q = %q %v %v", c.in, got, exp, err)
		}
	}
	for _, bad := range []string{"", "example.com", "1.2.3.4", "192.168.1.21", "fe80::1%eth0", "224.0.0.1", "300.1.1.1", "127.0.0.1:8080"} {
		if _, _, err := parseBindAnswer(bad, local); err == nil || err.Code != "QP-INPUT-005" {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseSmallAnswers(t *testing.T) {
	if c, err := parseCountryAnswer("de"); err != nil || c != "DE" {
		t.Errorf("de = %q %v", c, err)
	}
	for _, empty := range []string{"", "none", "SKIP", "auto"} {
		if c, err := parseCountryAnswer(empty); err != nil || c != "" {
			t.Errorf("%q = %q %v", empty, c, err)
		}
	}
	if _, err := parseCountryAnswer("XX"); err == nil || err.Code != "QP-INPUT-006" {
		t.Errorf("XX: %v", err)
	}
	if d, err := parseDatabaseAnswer(" TimescaleDB "); err != nil || d != "timescaledb" {
		t.Errorf("db %q %v", d, err)
	}
	if _, err := parseDatabaseAnswer("mysql"); err == nil || err.Code != "QP-INPUT-007" {
		t.Errorf("mysql: %v", err)
	}
	if _, err := parseOutboundAnswer("maybe"); err == nil || err.Code != "QP-INPUT-012" {
		t.Errorf("outbound: %v", err)
	}
	if _, err := parseDockerSource("ppa"); err == nil || err.Code != "QP-INPUT-012" {
		t.Errorf("source: %v", err)
	}
	for in, want := range map[string]bool{"": true, "y": true, "YES": true, " n ": false, "No": false} {
		if v, ok := parseYesNo(in, true); !ok || v != want {
			t.Errorf("yes/no %q = %v %v", in, v, ok)
		}
	}
	if _, ok := parseYesNo("yep", true); ok {
		t.Error("yep accepted")
	}
}

func TestApplyAnswers(t *testing.T) {
	cfg := config.Default("apply")
	applyAnswers(cfg, setupAnswers{Instance: "apply", Honeypots: []string{"dionaea"}, Bind: "0.0.0.0", Port: 9090,
		Database: "timescaledb", Outbound: "block", Country: "NL"})
	if got := strings.Join(sortedCopy(cfg.GetEnabledHoneypots()), ","); got != "dionaea" {
		t.Errorf("honeypots = %s (the defaults cowrie and endlessh must be off)", got)
	}
	if cfg.WebUI.BindAddr != "0.0.0.0" || cfg.WebUI.Port != 9090 || cfg.Database.Type != "timescaledb" ||
		!cfg.Security.NetworkIsolation.BlockOutbound || cfg.AttackMap.Country != "NL" {
		t.Errorf("cfg = %+v %+v", cfg.WebUI, cfg.Security.NetworkIsolation)
	}
}

func TestSetupStateRoundTripAndDistrust(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("USERPROFILE", home)
	if _, ok := loadSetupState(); ok {
		t.Fatal("no state yet")
	}
	a := defaultAnswers()
	a.Instance, a.Port, a.Profile, a.Honeypots = "saved1", 8099, "custom", []string{"dionaea", "cowrie"}
	if err := saveSetupState(a); err != nil {
		t.Fatal(err)
	}
	got, ok := loadSetupState()
	if !ok || got.Instance != "saved1" || got.Port != 8099 || strings.Join(got.Honeypots, ",") != "cowrie,dionaea" {
		t.Fatalf("loaded %+v %v", got, ok)
	}
	if fi, err := os.Stat(setupStatePath()); err != nil || (fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Fatalf("state file mode: %v %v", fi, err)
	}
	// An edited or damaged file is ignored, not trusted.
	for _, bad := range []string{`{"instance":"../x","bind":"127.0.0.1","port":80,"honeypots":["cowrie"],"database":"clickhouse","outbound":"allow"}`,
		`{"instance":"ok","bind":"8.8.8.8","port":80,"honeypots":["cowrie"],"database":"clickhouse","outbound":"allow"}`,
		`{"instance":"ok","bind":"127.0.0.1","port":0,"honeypots":["cowrie"],"database":"clickhouse","outbound":"allow"}`,
		`{"instance":"ok","bind":"127.0.0.1","port":80,"honeypots":["evil"],"database":"clickhouse","outbound":"allow"}`,
		`not json`} {
		if err := os.WriteFile(setupStatePath(), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if a, ok := loadSetupState(); ok {
			t.Errorf("accepted %s as %+v", bad, a)
		}
	}
	clearSetupState()
	if _, err := os.Stat(setupStatePath()); !os.IsNotExist(err) {
		t.Error("state not cleared")
	}
}

// FuzzSetupAnswers runs every answer parser on the same input: none may
// panic, and whatever one accepts must be valid and stable.
func FuzzSetupAnswers(f *testing.F) {
	for _, s := range []string{"8080", "127.0.0.1", "default", "minimal", "cowrie,dionaea", "DE", "y", "0.0.0.0", "::1",
		"localhost", "../../etc", "\x1b[2J", "65536", "fe80::1%eth0", "standard;hifi", "clickhouse", "block"} {
		f.Add(s)
	}
	local := []netip.Addr{netip.MustParseAddr("10.0.0.5")}
	f.Fuzz(func(t *testing.T, s string) {
		if name, err := parseInstanceAnswer(s); err == nil {
			if !reValidName.MatchString(name) || strings.ContainsAny(name, `/\.`) {
				t.Fatalf("instance %q accepted", name)
			}
		}
		if prof, hps, err := parseHoneypotsAnswer(s); err == nil {
			known := map[string]bool{}
			for _, k := range knownHoneypots() {
				known[k] = true
			}
			if len(hps) == 0 || (prof != "custom" && setupProfiles[prof] == nil) {
				t.Fatalf("%q -> %s %v", s, prof, hps)
			}
			for _, h := range hps {
				if !known[h] {
					t.Fatalf("unknown honeypot %q accepted", h)
				}
			}
		}
		if p, err := parsePortAnswer(s); err == nil {
			if p < 1 || p > 65535 {
				t.Fatalf("port %d accepted", p)
			}
			if again, err := parsePortAnswer(strconv.Itoa(p)); err != nil || again != p {
				t.Fatal("port round trip")
			}
		}
		if b, exp, err := parseBindAnswer(s, local); err == nil {
			a, perr := netip.ParseAddr(b)
			if perr != nil || a.Zone() != "" {
				t.Fatalf("bind %q -> %q", s, b)
			}
			switch exp {
			case bindLocal:
				if !a.IsLoopback() {
					t.Fatalf("%q called local", b)
				}
			case bindAll:
				if !a.IsUnspecified() {
					t.Fatalf("%q called all", b)
				}
			case bindNetwork:
				if a != local[0] {
					t.Fatalf("%q is not a local address", b)
				}
			}
		}
		if c, err := parseCountryAnswer(s); err == nil && c != "" && (len(c) != 2 || strings.ToUpper(c) != c) {
			t.Fatalf("country %q", c)
		}
		if d, err := parseDatabaseAnswer(s); err == nil && d != "clickhouse" && d != "timescaledb" {
			t.Fatalf("database %q", d)
		}
		if o, err := parseOutboundAnswer(s); err == nil && o != "allow" && o != "block" {
			t.Fatalf("outbound %q", o)
		}
		_, _ = parseYesNo(s, true)
		// Errors quote the input; the quote must stay bounded.
		if _, err := parsePortAnswer(s); err != nil && utf8.RuneCountInString(err.Cause()) > 400 {
			t.Fatalf("unbounded message: %d runes", utf8.RuneCountInString(err.Cause()))
		}
	})
}

// Industrial is explicit: a raw conpot selection must keep the existing automatic device semantics.
func TestIndustrialSetupProfile(t *testing.T) {
	profile, hps, err := parseHoneypotsAnswer(" Industrial ")
	if err != nil || profile != "industrial" || strings.Join(hps, ",") != "conpot" {
		t.Fatalf("profile=%q hps=%v err=%v", profile, hps, err)
	}
	cfg := config.Default("industrial-test")
	applyAnswers(cfg, setupAnswers{Profile: profile, Honeypots: hps, Bind: "127.0.0.1", Port: 8080})
	if got := strings.Join(cfg.GetEnabledHoneypots(), ","); got != "conpot" {
		t.Fatalf("industrial enables unrelated services: %s", got)
	}
	hp, _ := cfg.GetHoneypotConfig("conpot")
	if hp.CustomConfig["template"] != "plc_modbus" {
		t.Fatal("industrial did not select the Modbus PLC")
	}
	profile, hps, err = parseHoneypotsAnswer("conpot")
	if err != nil || profile != "custom" {
		t.Fatalf("raw engine list became industrial preset: %s %v", profile, err)
	}
	plain := config.Default("raw-conpot-test")
	applyAnswers(plain, setupAnswers{Profile: profile, Honeypots: hps, Bind: "127.0.0.1", Port: 8080})
	hp, _ = plain.GetHoneypotConfig("conpot")
	if hp.CustomConfig["template"] != "" {
		t.Fatal("raw engine selection unexpectedly pinned a device")
	}
	t.Setenv("HOME", t.TempDir())
	answers := defaultAnswers()
	answers.Profile, answers.Honeypots = "industrial", []string{"conpot"}
	if err := saveSetupState(answers); err != nil {
		t.Fatal(err)
	}
	got, ok := loadSetupState()
	if !ok || got.Profile != "industrial" {
		t.Fatalf("saved industrial profile not preserved: %+v %v", got, ok)
	}
}

func TestRefrigerationSetupProfile(t *testing.T) {
	profile, hps, err := parseHoneypotsAnswer(" Refrigeration ")
	if err != nil || profile != "refrigeration" || strings.Join(hps, ",") != "refrigeration" {
		t.Fatalf("profile=%q hps=%v err=%v", profile, hps, err)
	}
	cfg := config.Default("cold-storage-test")
	applyAnswers(cfg, setupAnswers{Profile: profile, Honeypots: hps, Bind: "127.0.0.1", Port: 8080})
	if got := strings.Join(cfg.GetEnabledHoneypots(), ","); got != "refrigeration" {
		t.Fatalf("refrigeration preset enabled unrelated services: %s", got)
	}
	hp, ok := cfg.GetHoneypotConfig("refrigeration")
	if !ok || hp.CustomConfig["site_profile"] != "" {
		t.Fatal("new refrigeration instance did not preserve the retail default")
	}
	if err := checkSetupFlags(&setupOptions{profileSet: true, profile: "refrigeration"}); err != nil {
		t.Fatalf("documented refrigeration setup flag rejected: %v", err)
	}
}
