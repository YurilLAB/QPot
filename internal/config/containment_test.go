package config

import (
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestParseEnforcesMandatoryContainment: a config file that leaves the
// hardening out (YAML then reads false), or switches it off, loads with it
// on. Before, such a file ran honeypots with Docker's default capabilities
// and a writable root filesystem, without a word.
func TestParseEnforcesMandatoryContainment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inst", "config.yaml")
	for name, body := range map[string]string{
		"security section omitted": "instance_name: inst\n",
		"security section empty":   "instance_name: inst\nsecurity: {}\n",
		"switched off": "instance_name: inst\nsecurity:\n  read_only_filesystem: false\n  drop_capabilities: false\n" +
			"  no_new_privileges: false\n  network_isolation:\n    separate_networks: false\n",
		"switched on": "instance_name: inst\nsecurity:\n  read_only_filesystem: true\n  drop_capabilities: true\n" +
			"  no_new_privileges: true\n  network_isolation:\n    separate_networks: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := Parse([]byte(body), path)
			if err != nil {
				t.Fatal(err)
			}
			s := cfg.Security
			if !s.ReadOnlyFilesystem || !s.DropCapabilities || !s.NoNewPrivileges || !s.NetworkIsolation.SeparateNetworks {
				t.Errorf("mandatory containment is off after loading: %+v", s)
			}
			// Only an explicit false is worth a message: a trimmed file is
			// not a mistake.
			var probe Config
			ignored := probe.enforceMandatoryContainment([]byte(body))
			if want := map[bool]int{true: len(MandatoryControls), false: 0}[name == "switched off"]; len(ignored) != want {
				t.Errorf("%d messages, want %d: %v", len(ignored), want, ignored)
			}
			for i, msg := range ignored {
				if !strings.Contains(msg, "security."+MandatoryControls[i].Key) || !strings.Contains(msg, "mandatory") {
					t.Errorf("message %d does not name its setting: %s", i, msg)
				}
			}
		})
	}
}

func TestSensorIDIsNotTheCredential(t *testing.T) {
	const a, b = "qp_abcdefghijklmnopqrstuvwx", "qp_abcdefghijklmnopqrstuvwy"
	shape := regexp.MustCompile(`^qs_[a-z2-7]{24}$`)
	sa, sb := SensorIDFor(a), SensorIDFor(b)
	if !shape.MatchString(sa) || !shape.MatchString(sb) {
		t.Fatalf("sensor IDs %q %q do not have the documented shape", sa, sb)
	}
	// Same length as the QPot ID: the scrub of old backups overwrites one
	// with the other in place.
	if len(sa) != len(a) {
		t.Fatalf("sensor ID is %d bytes, the QPot ID %d", len(sa), len(a))
	}
	if sa == sb {
		t.Error("two instances share a sensor ID")
	}
	if sa != SensorIDFor(a) {
		t.Error("the sensor ID is not stable")
	}
	if strings.Contains(sa, a[3:]) || qpotIDPattern.MatchString(sa) {
		t.Errorf("sensor ID %q could be used as, or reveals, the QPot ID", sa)
	}
	if SensorIDFor("") != "" {
		t.Error("an instance without a QPot ID got a sensor ID")
	}
	if got := (&Config{QPotID: a}).SensorID(); got != sa {
		t.Errorf("Config.SensorID = %q, want %q", got, sa)
	}
}

// TestWebUIExposureMatrix covers every authentication mode against local and
// remote bind addresses. Only "no login, reachable from other computers" is
// refused.
func TestWebUIExposureMatrix(t *testing.T) {
	auths := []struct {
		name string
		ui   WebUIConfig
		mode string
	}{
		{"qpot id", WebUIConfig{QPotIDAuth: true}, "qpot-id"},
		{"qpot id with basic set too", WebUIConfig{QPotIDAuth: true, Username: "admin", Password: "pw"}, "qpot-id"},
		{"basic", WebUIConfig{Username: "admin", Password: "pw"}, "basic"},
		{"username only", WebUIConfig{Username: "admin"}, "none"},
		{"password only", WebUIConfig{Password: "pw"}, "none"},
		{"nothing", WebUIConfig{}, "none"},
	}
	binds := []struct {
		addr     string
		loopback bool
	}{
		{"127.0.0.1", true}, {"127.8.9.10", true}, {"::1", true}, {"[::1]", true}, {"localhost", true}, {"LOCALHOST", true},
		{" 127.0.0.1 ", true},
		{"", false}, {"0.0.0.0", false}, {"::", false}, {"[::]", false}, {"192.168.1.10", false}, {"10.0.0.5", false},
		{"203.0.113.7", false}, {"2001:db8::1", false}, {"fe80::1", false}, {"example.com", false},
		{"127.0.0.1.example.com", false}, {"localhost.example.com", false}, {"127.0.0.1:8080", false}, {"::ffff:10.0.0.1", false},
	}
	for _, a := range auths {
		for _, b := range binds {
			ui := a.ui
			ui.BindAddr = b.addr
			if got := ui.AuthMode(); got != a.mode {
				t.Errorf("%s: AuthMode = %q, want %q", a.name, got, a.mode)
			}
			if got := ui.LoopbackOnly(); got != b.loopback {
				t.Errorf("bind %q: LoopbackOnly = %v, want %v", b.addr, got, b.loopback)
			}
			err := ui.CheckExposure()
			wantRefused := a.mode == "none" && !b.loopback
			if (err != nil) != wantRefused {
				t.Errorf("%s on %q: CheckExposure = %v, want refused=%v", a.name, b.addr, err, wantRefused)
			}
			if err != nil && !strings.Contains(err.Error(), "bind_addr") {
				t.Errorf("the refusal does not name the setting: %v", err)
			}
		}
	}
	// ::ffff:127.0.0.1 is loopback to the kernel too.
	if !(WebUIConfig{BindAddr: "::ffff:127.0.0.1"}).LoopbackOnly() {
		t.Error("the IPv4-mapped loopback address is not treated as loopback")
	}
}

// TestValidateWarnsAboutLoginlessWebUI: without a login the config says so
// when loaded, on loopback (a warning) and beyond it (a refusal at start).
func TestValidateWarnsAboutLoginlessWebUI(t *testing.T) {
	cfg := Default("warn")
	if w := strings.Join(cfg.Validate(), "\n"); strings.Contains(w, "no login") {
		t.Errorf("the default config warns about its login: %s", w)
	}
	cfg.WebUI.QPotIDAuth = false
	if w := strings.Join(cfg.Validate(), "\n"); !strings.Contains(w, "any local user or process") {
		t.Errorf("no warning for a login-less web UI on loopback: %q", w)
	}
	cfg.WebUI.BindAddr = "0.0.0.0"
	if w := strings.Join(cfg.Validate(), "\n"); !strings.Contains(w, "refuse to start") {
		t.Errorf("no warning for a login-less web UI on 0.0.0.0: %q", w)
	}
}

// FuzzWebUIExposure: for any bind address and any credentials, a web UI with
// no login is refused unless the address parses as loopback, and nothing
// that is not literally a loopback address or "localhost" counts as one.
func FuzzWebUIExposure(f *testing.F) {
	for _, addr := range []string{"127.0.0.1", "::1", "[::1]", "localhost", "", "0.0.0.0", "::", "10.0.0.1", "127.0.0.1.evil.example", "127.1", "0x7f.0.0.1", "localhost.", "[::ffff:127.0.0.1]", "127.0.0.1%eth0", "\x00127.0.0.1"} {
		f.Add(addr, "", "", false)
		f.Add(addr, "admin", "pw", false)
		f.Add(addr, "admin", "", true)
	}
	f.Fuzz(func(t *testing.T, addr, user, pass string, idAuth bool) {
		ui := WebUIConfig{BindAddr: addr, Username: user, Password: pass, QPotIDAuth: idAuth}
		loopback := ui.LoopbackOnly()
		if loopback {
			host := strings.TrimSpace(addr)
			if !strings.EqualFold(host, "localhost") {
				ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
				if ip == nil || !ip.IsLoopback() {
					t.Fatalf("%q is treated as loopback", addr)
				}
			}
		}
		hasLogin := idAuth || (user != "" && pass != "")
		if refused := ui.CheckExposure() != nil; refused != (!hasLogin && !loopback) {
			t.Fatalf("bind %q login=%v loopback=%v: refused=%v", addr, hasLogin, loopback, refused)
		}
	})
}
