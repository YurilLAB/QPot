package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
)

// This stand-in exercises the actual CLI and Manager restart path without
// accessing Docker or starting an attacker-facing service.
func dockerRestartFixture(t *testing.T, mode, service, honeypot string) (*config.Config, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the isolated CLI Docker stand-in is a shell script")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfg := config.Default("docker-restart")
	cfg.Security.SandboxMode = mode
	for name, hp := range cfg.Honeypots {
		hp.Enabled = name == "cowrie"
		cfg.Honeypots[name] = hp
	}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	dockerRestartCompose(t, cfg, service, honeypot, "runsc")
	metadata, err := json.Marshal(dockerRestartContainer{ID: strings.Repeat("a", 64), Instance: cfg.InstanceName, Service: service, Honeypot: honeypot})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("QPOT_DOCKER_RESTART_METADATA", string(metadata))
	t.Setenv("QPOT_DOCKER_RESTART_REGISTRY", `{"runc":{}}`)
	t.Setenv("QPOT_DOCKER_RESTART_RUNTIME", "runc")
	t.Setenv("QPOT_DOCKER_RESTART_SERVICE", service)
	t.Setenv("QPOT_DOCKER_RESTART_HONEYPOT", honeypot)
	t.Setenv("QPOT_DOCKER_RESTART_FAIL", "")
	bin := t.TempDir()
	calls := filepath.Join(bin, "calls.log")
	t.Setenv("QPOT_DOCKER_RESTART_CALLS", calls)
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$QPOT_DOCKER_RESTART_CALLS"
case "$1" in
 inspect)
  if [ "$2" = --type ]; then
   printf '%s\n' "$QPOT_DOCKER_RESTART_METADATA"
  else
   printf '{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instance":"docker-restart","service":"%s","honeypot":"%s","runtime":"%s","running":true}\n' "$QPOT_DOCKER_RESTART_SERVICE" "$QPOT_DOCKER_RESTART_HONEYPOT" "$QPOT_DOCKER_RESTART_RUNTIME"
  fi ;;
 info) printf '%s\n' "$QPOT_DOCKER_RESTART_REGISTRY" ;;
 ps) printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
 restart|compose)
  if [ "$QPOT_DOCKER_RESTART_FAIL" = 1 ]; then exit 17; fi ;;
 *) exit 18 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil { // #nosec G306 -- isolated executable test fixture
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return cfg, calls
}

func dockerRestartCompose(t *testing.T, cfg *config.Config, service, honeypot, runtimeName string) {
	t.Helper()
	data := fmt.Sprintf("services:\n  %s:\n    runtime: %s\n    labels:\n      qpot.instance: %s\n      qpot.honeypot: %q\n", service, runtimeName, cfg.InstanceName, honeypot)
	if err := os.WriteFile(cfg.GetDockerComposePath(), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runDockerRestartTest(t *testing.T, calls, wantCode string) error {
	t.Helper()
	cmd := newDockerRestartCommand()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"selected-container"})
	err := cmd.ExecuteContext(t.Context())
	if wantCode == "" {
		if err != nil {
			t.Fatal(err)
		}
		return nil
	}
	var coded *hostsetup.Error
	if !errors.As(err, &coded) || coded.Code != wantCode {
		t.Fatalf("restart error = %v, want %s", err, wantCode)
	}
	data, readErr := os.ReadFile(calls)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "restart ") || strings.Contains(line, " restart ") {
			t.Fatalf("refused restart still reached Docker: %s", data)
		}
	}
	return err
}

// Before this fix, all three cases directly invoked docker restart, bypassing
// the mandatory isolation policy and both deployment/runtime checks.
func TestDockerRestartEnforcesMandatoryIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, registry, stored, actual, code string
	}{
		{"runtime unavailable", `{"runc":{}}`, "runsc", "runc", "QP-DOCKER-011"},
		{"existing container uses Docker", `{"runc":{},"runsc":{}}`, "runsc", "runc", "QP-DOCKER-012"},
		{"stored deployment uses Docker", `{"runc":{},"runsc":{}}`, "runc", "runsc", "QP-DOCKER-012"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, calls := dockerRestartFixture(t, "gvisor", "cowrie", "cowrie")
			dockerRestartCompose(t, cfg, "cowrie", "cowrie", tc.stored)
			t.Setenv("QPOT_DOCKER_RESTART_REGISTRY", tc.registry)
			t.Setenv("QPOT_DOCKER_RESTART_RUNTIME", tc.actual)
			runDockerRestartTest(t, calls, tc.code)
		})
	}
}

func TestDockerRestartUsesFreshSavedPolicy(t *testing.T) {
	cfg, calls := dockerRestartFixture(t, "none", "cowrie", "cowrie")
	// Save populated Load's cache with none. Change only the saved document so
	// reusing that cache would silently authorize the old, weaker policy.
	data, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(data), "sandbox_mode: none", "sandbox_mode: gvisor", 1)
	if updated == string(data) {
		t.Fatal("fixture did not update the saved sandbox policy")
	}
	if err := os.WriteFile(cfg.ConfigPath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	runDockerRestartTest(t, calls, "QP-DOCKER-011")
}

func TestDockerRestartRejectsExecutingCompanionFallback(t *testing.T) {
	for _, tc := range []struct{ service, honeypot string }{{"tanner_phpox", "tanner"}, {"ssh-backend-1", "ssh-backend"}, {"ssh-backend-1-db", "ssh-backend"}} {
		t.Run(tc.service, func(t *testing.T) {
			cfg, calls := dockerRestartFixture(t, "gvisor", tc.service, tc.honeypot)
			cfg.Security.SandboxFallback = "docker"
			cfg.SetHoneypotCustomConfig("ssh-proxy", map[string]string{"backends": "2", "image_source": "local"})
			// Only Cowrie is enabled; an executing companion remains from an
			// older deployment. The selected target must prevent fallback.
			if err := config.Save(cfg); err != nil {
				t.Fatal(err)
			}
			runDockerRestartTest(t, calls, "QP-DOCKER-011")
		})
	}
}

func TestDockerRestartRetainsAllowedPaths(t *testing.T) {
	for _, tc := range []struct {
		name, mode, service, honeypot, registry, actual string
		fallback                                        bool
	}{
		{"explicit Docker honeypot", "none", "cowrie", "cowrie", `{"runc":{}}`, "runc", false},
		{"verified stronger runtime", "gvisor", "cowrie", "cowrie", `{"runc":{},"runsc":{}}`, "runsc", false},
		{"approved emulator fallback", "gvisor", "cowrie", "cowrie", `{"runc":{}}`, "runc", true},
		{"database recovery", "gvisor", "database", "", `{"runc":{}}`, "runc", false},
		{"collector recovery with invalid guest policy", "firejail", "collector", "", `{"runc":{}}`, "runc", false},
		{"egress guard recovery", "gvisor", "netguard", "", `{"runc":{}}`, "runc", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, calls := dockerRestartFixture(t, tc.mode, tc.service, tc.honeypot)
			if tc.fallback {
				cfg.Security.SandboxFallback = "docker"
				if err := config.Save(cfg); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("QPOT_DOCKER_RESTART_REGISTRY", tc.registry)
			t.Setenv("QPOT_DOCKER_RESTART_RUNTIME", tc.actual)
			runDockerRestartTest(t, calls, "")
			data, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			want := "compose -f " + cfg.GetDockerComposePath() + " restart cowrie\n"
			if tc.honeypot == "" {
				want = "restart " + strings.Repeat("a", 64) + "\n"
				if strings.Contains(string(data), "info ") {
					t.Fatal("control-service recovery depended on a guest runtime")
				}
			}
			if !strings.Contains(string(data), want) || strings.Contains(string(data), "restart selected-container") {
				t.Fatalf("restart did not use its validated boundary: %s", data)
			}
		})
	}
}

func TestDockerRestartRejectsUnresolvedOwnership(t *testing.T) {
	for _, scenario := range []string{"missing config", "invalid config", "foreign instance", "missing deployment", "unknown service", "missing honeypot label", "contradictory honeypot label", "truncated ID", "malformed JSON", "trailing JSON", "oversized metadata"} {
		t.Run(scenario, func(t *testing.T) {
			cfg, calls := dockerRestartFixture(t, "none", "cowrie", "cowrie")
			var metadata dockerRestartContainer
			if err := json.Unmarshal([]byte(os.Getenv("QPOT_DOCKER_RESTART_METADATA")), &metadata); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing config":
				if err := os.Remove(cfg.ConfigPath); err != nil {
					t.Fatal(err)
				}
			case "invalid config":
				if err := os.WriteFile(cfg.ConfigPath, []byte("database: [broken"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "foreign instance":
				metadata.Instance = "../foreign"
			case "missing deployment":
				if err := os.Remove(cfg.GetDockerComposePath()); err != nil {
					t.Fatal(err)
				}
			case "unknown service":
				metadata.Service = "unknown-service"
			case "missing honeypot label":
				metadata.Honeypot = ""
			case "contradictory honeypot label":
				metadata.Honeypot = "tanner"
			case "truncated ID":
				metadata.ID = "aaaaaaaaaaaa"
			}
			encoded, err := json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "malformed JSON":
				encoded = []byte("not JSON")
			case "trailing JSON":
				encoded = append(encoded, ']')
			case "oversized metadata":
				encoded = append(encoded, []byte(strings.Repeat(" ", 16<<10))...)
			}
			t.Setenv("QPOT_DOCKER_RESTART_METADATA", string(encoded))
			runDockerRestartTest(t, calls, "QP-DOCKER-012")
		})
	}
}
