package instance

import (
	"context"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// newGuardTestManager builds a Manager whose config has a couple of known
// honeypots, without touching Docker.
func newGuardTestManager(t *testing.T) *Manager {
	t.Helper()
	cfg := config.Default("guard-test")
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// TestHoneypotGuardsRejectUnknown verifies the docker-compose argv guards
// reject unknown / injection-style names BEFORE invoking docker. These must
// return an error immediately (no exec), so they're safe to run without Docker.
func TestHoneypotGuardsRejectUnknown(t *testing.T) {
	m := newGuardTestManager(t)
	ctx := context.Background()

	bad := []string{"", "--help", "-v", "nonexistent", "cowrie; rm -rf /", "../etc"}
	for _, name := range bad {
		if err := m.StartHoneypot(ctx, name); err == nil {
			t.Errorf("StartHoneypot(%q) should be rejected", name)
		}
		if err := m.StopHoneypot(ctx, name); err == nil {
			t.Errorf("StopHoneypot(%q) should be rejected", name)
		}
		if _, err := m.GetLogs(ctx, name, false, 10); err == nil {
			t.Errorf("GetLogs(%q) should be rejected", name)
		}
	}

	// A configured honeypot name passes the guard (it will then try docker and
	// likely fail in this environment — that's fine, we only assert the guard
	// itself does not reject it with an "unknown honeypot" error).
	if _, ok := m.config.Honeypots["cowrie"]; !ok {
		t.Skip("default config has no cowrie honeypot")
	}
	if _, err := m.GetLogs(ctx, "cowrie", false, 1); err != nil && strings.Contains(err.Error(), "unknown honeypot") {
		t.Errorf("GetLogs(cowrie) wrongly rejected as unknown: %v", err)
	}
}
