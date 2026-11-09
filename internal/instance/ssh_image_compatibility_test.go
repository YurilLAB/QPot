package instance

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
)

func TestSSHRuntimeImageCompatibility(t *testing.T) {
	cfg := config.Default("compatibility")
	revision := strings.Repeat("a1", 20)
	for _, source := range []string{"", "published", "local"} {
		cfg.SetHoneypotCustomConfig(sshProxyHoneypot, map[string]string{"image_source": source})
		for _, value := range []string{"", "latest", "abcdef", strings.Repeat("a", 39), strings.Repeat("a", 41), strings.Repeat("g", 40), strings.Repeat("A", 40), revision} {
			err := validateSSHRuntimeImages(cfg, value)
			allowed := source == "local" || value == revision
			if (err == nil) != allowed {
				t.Fatalf("source=%q revision=%q accepted=%v want%v", source, value, err == nil, allowed)
			}
			if err != nil && hostsetup.AsError(err).Code != "QP-INST-013" {
				t.Fatalf("uncoded incompatibility: %v", err)
			}
		}
	}
}

func TestSSHLayoutImageCompatibility(t *testing.T) {
	revision := strings.Repeat("a1", 20)
	layout, err := parseSSHLayout(organizationComposeFixture(t, "compat", 2, true), "compat")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSSHLayoutImages(layout, ""); err != nil {
		t.Fatalf("matching local images refused: %v", err)
	}
	release := layout
	release.Images = maps.Clone(layout.Images)
	for name := range release.Images {
		if name == sshProxyHoneypot {
			release.Images[name] = sshPublishedImage(sshProxyHoneypot, revision)
		} else if !strings.HasSuffix(name, "-db") {
			release.Images[name] = sshPublishedImage("ssh-backend", revision)
		}
	}
	if err := validateSSHLayoutImages(release, revision); err != nil {
		t.Fatalf("matching full-release images refused: %v", err)
	}
	for _, test := range []struct{ name, service, image, revision string }{
		{"legacy broker", sshProxyHoneypot, GetHoneypotImage(sshProxyHoneypot), ""},
		{"missing broker", sshProxyHoneypot, "", ""},
		{"mixed application", "ssh-backend-1", sshPublishedImage("ssh-backend", revision), revision},
		{"legacy backup", "ssh-backend-1-backup", GetHoneypotImage("ssh-backend"), revision},
		{"missing application", "ssh-backend-2", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := layout
			copy.Images = maps.Clone(layout.Images)
			copy.Images[test.service] = test.image
			if err := validateSSHLayoutImages(copy, test.revision); err == nil || hostsetup.AsError(err).Code != "QP-INST-013" {
				t.Fatalf("incompatible actual document accepted: %v", err)
			}
		})
	}
	if err := validateSSHLayoutImages(release, strings.Repeat("b", 40)); err == nil {
		t.Fatal("another release's image contract accepted")
	}
	if _, exists := layout.Images["ssh-backend-16"]; exists {
		t.Fatal("foreign instance participated in image authority")
	}
}

func TestHiFiImageCompatibilityRefusesBeforeRuntimeMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("synthetic Docker executable requires Unix shell")
	}
	if validHiFiImageRevision(HiFiImageRevision) {
		t.Skip("unlinked-binary refusal fixture; pure table also tests valid releases")
	}
	for _, action := range []string{"instance", "honeypot", "recreate", "restart"} {
		t.Run(action, func(t *testing.T) {
			cfg := unreservedSSHStoreConfig(t)
			cfg.SetHoneypotCustomConfig(sshProxyHoneypot, map[string]string{"image_source": "published"})
			if err := config.Save(cfg); err != nil {
				t.Fatal(err)
			}
			old := organizationComposeFixture(t, cfg.InstanceName, 2, false)
			storageWrite(t, cfg.GetDockerComposePath(), old, 0o600)
			saved, err := os.ReadFile(cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			record := organizationFakeDocker(t)
			manager, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			// Sandbox detection may issue its existing read-only runtime-info
			// probe during construction. Measure only the guarded operation.
			if err := os.Remove(record); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			switch action {
			case "instance":
				err = manager.Start(t.Context(), true)
			case "honeypot":
				err = manager.StartHoneypot(t.Context(), sshProxyHoneypot)
			case "recreate":
				err = manager.RecreateHoneypot(t.Context(), sshProxyHoneypot)
			case "restart":
				err = manager.RestartHoneypot(t.Context(), sshProxyHoneypot)
			}
			if err == nil || hostsetup.AsError(err).Code != "QP-INST-013" {
				t.Fatalf("legacy published runtime reached %s: %v", action, err)
			}
			if _, err := os.Lstat(record); !os.IsNotExist(err) {
				t.Fatal("incompatible startup reached Docker, including status probes")
			}
			for _, name := range []string{sshStorePointer, ".ssh-cells.lock", "collector", "vector.yaml"} {
				if _, err := os.Lstat(filepath.Join(cfg.DataPath, name)); !os.IsNotExist(err) {
					t.Fatalf("incompatible startup mutated %s", name)
				}
			}
			if data, _ := os.ReadFile(cfg.ConfigPath); string(data) != string(saved) {
				t.Fatal("incompatible startup changed saved config")
			}
			if data, _ := os.ReadFile(cfg.GetDockerComposePath()); string(data) != string(old) {
				t.Fatal("incompatible startup changed actual Compose")
			}
		})
	}
}

func legacySSHComposeFixture(t *testing.T, cfg *config.Config) []byte {
	t.Helper()
	current := string(organizationComposeFixture(t, cfg.InstanceName, 2, true))
	current = strings.ReplaceAll(current, "qpot-local/ssh-proxy:development", GetHoneypotImage(sshProxyHoneypot))
	return []byte(strings.ReplaceAll(current, "qpot-local/ssh-backend:development", GetHoneypotImage("ssh-backend")))
}

func TestHiFiRestartChecksActualImagesEvenWhenSavedConfigSelectsLocal(t *testing.T) {
	cfg := organizationTestConfig(t)
	old := legacySSHComposeFixture(t, cfg)
	storageWrite(t, cfg.GetDockerComposePath(), old, 0o600)
	record := organizationFakeDocker(t)
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(record); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := manager.RestartHoneypot(t.Context(), sshProxyHoneypot); err == nil || hostsetup.AsError(err).Code != "QP-INST-013" {
		t.Fatalf("saved local config hid actual legacy document: %v", err)
	}
	if _, err := os.Lstat(record); !os.IsNotExist(err) {
		t.Fatal("incompatible actual restart reached Docker")
	}
	if data, _ := os.ReadFile(cfg.GetDockerComposePath()); string(data) != string(old) {
		t.Fatal("refused restart replaced Compose")
	}
}

func TestHiFiRecyclerDoesNotStartOrAdvanceIncompatibleActualImages(t *testing.T) {
	cfg := organizationTestConfig(t)
	storageWrite(t, cfg.GetDockerComposePath(), legacySSHComposeFixture(t, cfg), 0o600)
	record := organizationFakeDocker(t)
	current := requireSSHLogDir(t, cfg, "ssh-backend-1")
	storageWrite(t, filepath.Join(current, "prior.json"), []byte("prior evidence\n"), 0o600)
	recycler := requireBackendRecycler(t, cfg)
	generation := uint64(0)
	err := recycler.resetCell(t.Context(), "ssh-backend-1", &generation)
	if err == nil || hostsetup.AsError(err).Code != "QP-INST-013" {
		t.Fatalf("legacy recycler contract accepted: %v", err)
	}
	if recycler.generation("ssh-backend-1") != 0 {
		t.Fatal("incompatible reset became reusable")
	}
	commands, _ := os.ReadFile(record)
	if !strings.Contains(string(commands), "\nstop\n") || strings.Contains(string(commands), "\nup\n") {
		t.Fatalf("legacy cell was not held stopped: %s", commands)
	}
	archived, err := filepath.Glob(filepath.Join(filepath.Dir(current), "archive-g0-*", "logs", "prior.json"))
	if err != nil || len(archived) != 1 {
		t.Fatal("legacy refusal lost prior evidence")
	}
	if data, _ := os.ReadFile(archived[0]); string(data) != "prior evidence\n" {
		t.Fatal("legacy refusal changed prior evidence")
	}
}

func TestHiFiCompatibilityFailurePreservesSavedSettingsContract(t *testing.T) {
	if validHiFiImageRevision(HiFiImageRevision) {
		t.Skip("unlinked development-binary failure scenario")
	}
	cfg := organizationTestConfig(t)
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	old := organizationComposeFixture(t, cfg.InstanceName, 2, true)
	storageWrite(t, cfg.GetDockerComposePath(), old, 0o600)
	record := organizationFakeDocker(t)
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ApplySettings(t.Context(), cfg, sshProxyHoneypot, ParseSettingArgs([]string{"image_source=published"}), manager)
	if !errors.Is(err, ErrRecreateFailed) || hostsetup.AsError(err).Code != "QP-INST-013" || result == nil || !result.Saved || !result.InstanceRunning || result.Recreated {
		t.Fatalf("failed apply misrepresented saved/live state: %+v %v", result, err)
	}
	if config.SSHImageSource(cfg) != config.SSHImageSourcePublished {
		t.Fatal("saved setting was silently rolled back")
	}
	if data, _ := os.ReadFile(cfg.GetDockerComposePath()); string(data) != string(old) {
		t.Fatal("incompatible saved setting changed working Compose")
	}
	commands, _ := os.ReadFile(record)
	for _, verb := range []string{"up", "stop", "rm", "pull", "run", "restart"} {
		if strings.Contains(string(commands), "\n"+verb+"\n") {
			t.Fatalf("incompatible apply reached Docker %s", verb)
		}
	}
}
