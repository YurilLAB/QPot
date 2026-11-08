package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
	"sync"
	"testing"
)

func TestSetHoneypotCustomConfig(t *testing.T) {
	cfg := Default("hp-set")
	custom := map[string]string{"persona": "rhel-9"}
	if !cfg.SetHoneypotCustomConfig("cowrie", custom) {
		t.Fatal("cowrie not set")
	}
	custom["persona"] = "changed later"
	if hp, _ := cfg.GetHoneypotConfig("cowrie"); hp.CustomConfig["persona"] != "rhel-9" {
		t.Fatalf("the caller's map is shared: %v", hp.CustomConfig)
	}
	if cfg.SetHoneypotCustomConfig("nosuch", custom) {
		t.Fatal("an unknown honeypot was set")
	}
	if _, ok := cfg.GetHoneypotConfig("nosuch"); ok {
		t.Fatal("an unknown honeypot was added")
	}
}

func TestReplaceHoneypotsAndClone(t *testing.T) {
	dir := t.TempDir()
	cfg := Default("hp-clone")
	cfg.DataPath = dir
	cfg.ConfigPath = filepath.Join(dir, "config.yaml")
	cfg.QPotID = "qp_cloneclonecloneclonecl"
	cfg.SetHoneypotCustomConfig("cowrie", map[string]string{"bait": "off"})

	cp, err := cfg.Clone()
	if err != nil {
		t.Fatal(err)
	}
	if cp == cfg || cp.QPotID != cfg.QPotID || cp.DataPath != dir {
		t.Fatalf("clone: %+v", cp)
	}
	cp.SetHoneypotCustomConfig("cowrie", map[string]string{"bait": "on"})
	cp.EnableHoneypot("conpot")
	if hp, _ := cfg.GetHoneypotConfig("cowrie"); hp.CustomConfig["bait"] != "off" {
		t.Fatal("a change to the clone reached the original")
	}

	cfg.ReplaceHoneypots(cp.SnapshotHoneypots())
	if hp, _ := cfg.GetHoneypotConfig("conpot"); !hp.Enabled {
		t.Fatal("ReplaceHoneypots did not take the other config's honeypots")
	}
	cp.SetHoneypotCustomConfig("cowrie", map[string]string{"bait": "maybe"})
	if hp, _ := cfg.GetHoneypotConfig("cowrie"); hp.CustomConfig["bait"] != "on" {
		t.Fatalf("ReplaceHoneypots shares maps with the other config: %v", hp.CustomConfig)
	}
}

// The setters hold the honeypot lock (run with -race).
func TestHoneypotSettersConcurrent(t *testing.T) {
	cfg := Default("hp-race")
	other := Default("hp-race2")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); cfg.SetHoneypotCustomConfig("cowrie", map[string]string{"bait": "off"}) }()
		go func() { defer wg.Done(); cfg.ReplaceHoneypots(other.SnapshotHoneypots()) }()
		go func() { defer wg.Done(); _, _ = cfg.Clone() }()
	}
	wg.Wait()
}

// Reading a legacy file preserves its choice without resolving a record.
// The next authorized save records it, and later catalog changes cannot remap it.
func TestConpotProfileMigrationAndCatalogGrowth(t *testing.T) {
	cfg := Default("industrial-migrate")
	cfg.QPotID = "qp_industriallegacy"
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	legacy, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.ConfigPath, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	want := ConpotAutomaticProfileID(cfg)

	migrated, err := Parse(legacy, cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := os.ReadFile(cfg.ConfigPath)
	if string(stored) != string(legacy) {
		t.Fatal("Parse wrote the legacy config")
	}
	hp, _ := migrated.GetHoneypotConfig("conpot")
	if hp.DeviceProfile != (ResolvedDeviceProfile{}) || ConpotAutomaticProfileID(migrated) != want {
		t.Fatalf("Parse must preserve choice %s without freezing a record: %+v", want, hp.DeviceProfile)
	}
	if err := Save(migrated); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), "device_profile:") {
		t.Fatal("resolved profile was not persisted")
	}

	original := conpotDeviceProfiles
	t.Cleanup(func() { conpotDeviceProfiles = original })
	conpotDeviceProfiles = slices.Clone(original)
	slices.Reverse(conpotDeviceProfiles)
	conpotDeviceProfiles = append(conpotDeviceProfiles, ConpotDeviceProfile{ID: "future-controller"})
	for _, contents := range [][]byte{legacy, persisted} {
		loaded, err := Parse(contents, cfg.ConfigPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := ConpotAutomaticProfileID(loaded); got != want {
			t.Fatalf("catalog expansion/reordering changed device: got %s, want %s", got, want)
		}
	}
}

func TestConpotSavedProfileValidation(t *testing.T) {
	for _, tc := range []struct{ name, profile, pin string }{
		{"unknown-id", "{id: nonexistent, version: 1}", ""},
		{"future-version", "{id: plc_modbus, version: 2}", ""},
		{"missing-version", "{id: plc_modbus}", ""},
		{"missing-id", "{version: 1}", ""},
		{"unknown-pin", "{id: plc_modbus, version: 1}", "default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents := "honeypots:\n  conpot:\n    device_profile: " + tc.profile + "\n    custom_config:\n      template: '" + tc.pin + "'\n"
			if _, err := Parse([]byte(contents), filepath.Join(t.TempDir(), "config.yaml")); err == nil {
				t.Fatal("invalid device choice was silently replaced")
			}
		})
	}
}

func TestConpotProfilesIndependentCopies(t *testing.T) {
	profiles := ConpotProfiles()
	seen := map[string]bool{}
	for _, p := range profiles {
		if p.ID == "" || seen[p.ID] || p.Label == "" || p.Category == "" || p.Model == "" || p.Description == "" || p.Limitations == "" || len(p.Protocols) == 0 || len(p.TCP)+len(p.UDP) == 0 {
			t.Fatalf("incomplete or duplicate device profile: %+v", p)
		}
		seen[p.ID] = true
	}
	wantProtocol, wantPort := profiles[0].Protocols[0], profiles[0].TCP[0]
	profiles[0].Protocols[0] = "mutated"
	profiles[0].TCP[0] = 1
	profiles[0].ID = "mutated"
	fresh := ConpotProfiles()
	if fresh[0].ID != "IEC104" || fresh[0].Protocols[0] != wantProtocol || fresh[0].TCP[0] != wantPort {
		t.Fatal("caller can mutate the shared device catalog")
	}
}

func TestConpotLegacySelectionVectors(t *testing.T) {
	// Recorded from the pre-profile instance selection algorithm. These are a
	// compatibility contract, not choices recalculated from the live catalog.
	for _, tc := range []struct{ identity, want string }{
		{"qp_industriallegacy", "kamstrup_382"},
		{"qp_a", "hart_gateway"},
		{"qp_conpotpin0000000001", "building_automation"},
		{"", "plc_modbus"},
	} {
		cfg := Default("legacy-without-qpot-id")
		cfg.QPotID = tc.identity
		if got := ConpotAutomaticProfileID(cfg); got != tc.want {
			t.Errorf("identity %q chose %s, want legacy choice %s", tc.identity, got, tc.want)
		}
	}
}

func TestConpotMigrationWaitsForLegacyIdentity(t *testing.T) {
	contents := []byte("instance_name: legacy-without-qpot-id\nhoneypots:\n  conpot: {}\n")
	cfg, err := Parse(contents, filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	hp, _ := cfg.GetHoneypotConfig("conpot")
	if hp.DeviceProfile.ID != "" {
		t.Fatal("Parse froze an automatic choice before qpot.id was loaded")
	}
	cfg.QPotID = "qp_a" // What the runtime loads from the legacy qpot.id.
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	hp, _ = cfg.GetHoneypotConfig("conpot")
	if hp.DeviceProfile.ID != "hart_gateway" {
		t.Fatalf("migration ignored the loaded identity: %+v", hp.DeviceProfile)
	}
}

func TestLoadConpotProfileUsesLegacyIdentityFile(t *testing.T) {
	for _, tc := range []struct{ name, yamlID, profile string }{
		{"missing-yaml-id", "", ""},
		{"stale-yaml-id", "qp_zzzzzzzzzzzzzzzzzzzzzzzz", ""},
		{"saved-profile-after-rotation", "qp_zzzzzzzzzzzzzzzzzzzzzzzz", "    device_profile: {id: plc_modbus, version: 1}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			name := "ind-" + tc.name
			dir := filepath.Join(home, ".qpot", "instances", name)
			if err := os.MkdirAll(dir, 0750); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.yaml")
			contents := []byte("instance_name: " + name + "\nqpot_id: " + tc.yamlID + "\nhoneypots:\n  conpot:\n" + tc.profile + "    enabled: true\n")
			if err := os.WriteFile(path, contents, 0600); err != nil {
				t.Fatal(err)
			}
			const id = "qp_abcdefghijklmnopqrstuvwx"
			if err := os.WriteFile(filepath.Join(dir, "qpot.id"), []byte("  "+id+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { configMu.Lock(); delete(configs, name); configMu.Unlock() })
			cfg, err := Load(name)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.QPotID != id {
				t.Fatal("canonical identity did not override the stale YAML credential")
			}
			withID := Default(name)
			withID.QPotID = id
			want := ConpotAutomaticProfileID(withID)
			if tc.profile != "" {
				want = "plc_modbus"
			}
			if got := ConpotAutomaticProfileID(cfg); got != want {
				t.Fatalf("got device %s, want %s", got, want)
			}
			stored, _ := os.ReadFile(path)
			if string(stored) != string(contents) {
				t.Fatal("Load wrote a legacy config")
			}
			if err := Save(cfg); err != nil {
				t.Fatal(err)
			}
			stored, _ = os.ReadFile(path)
			reloaded, err := Parse(stored, path)
			if err != nil {
				t.Fatal(err)
			}
			if got := ConpotAutomaticProfileID(reloaded); got != want {
				t.Fatalf("saving migrated device changed %s to %s", want, got)
			}
		})
	}
}

// The API parses the current file and then supplies the server's canonical
// credential. Parsing must not freeze a choice based on a stale YAML ID.
func TestConpotMigrationAfterRuntimeIdentityOverride(t *testing.T) {
	cfg, err := Parse([]byte("qpot_id: qp_stale\nhoneypots:\n  conpot: {}\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	hp, _ := cfg.GetHoneypotConfig("conpot")
	if hp.DeviceProfile != (ResolvedDeviceProfile{}) {
		t.Fatal("Parse froze the stale YAML identity")
	}
	cfg.QPotID = "qp_a"
	if got := ConpotAutomaticProfileID(cfg); got != "hart_gateway" {
		t.Fatalf("runtime identity did not control legacy read: %s", got)
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	hp, _ = cfg.GetHoneypotConfig("conpot")
	if hp.DeviceProfile.ID != "hart_gateway" {
		t.Fatalf("Save froze stale choice: %+v", hp.DeviceProfile)
	}
	cfg.QPotID = "qp_conpotpin0000000001"
	if got := ConpotAutomaticProfileID(cfg); got != "hart_gateway" {
		t.Fatalf("credential rotation changed saved choice: %s", got)
	}
}
