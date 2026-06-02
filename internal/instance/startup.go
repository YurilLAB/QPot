package instance

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// startup.go adds per-honeypot startup reporting: after `qpot up` brings the
// stack up, we watch each enabled honeypot until it settles into a terminal
// state and emit a clear log of which ones came up and which did not - with the
// reason (exit code + the tail of the container's own log) for any that failed.
// Without this a failed honeypot was invisible: `waitForHealthy` only ever
// returned a generic "timeout waiting for services".

// honeypotStartup is the startup outcome of a single honeypot service.
type honeypotStartup struct {
	Name   string
	State  string // running, exited, restarting, created, dead, ...
	Health string // healthy, unhealthy, starting, "" (no healthcheck)
	Phase  startupPhase
	Reason string // populated for Failed: exit code + log tail explaining why
}

type startupPhase int

const (
	phasePending startupPhase = iota // not yet settled (created/starting/restarting)
	phaseUp                          // running and healthy (or no healthcheck)
	phaseFailed                      // exited, dead, or unhealthy
)

// classifyStartup maps a compose ps row to a startup phase.
func classifyStartup(e composePSEntry) startupPhase {
	state := strings.ToLower(strings.TrimSpace(e.State))
	health := strings.ToLower(strings.TrimSpace(e.Health))
	switch {
	case state == "running" && health == "unhealthy":
		return phaseFailed
	case state == "running" && (health == "" || health == "healthy"):
		return phaseUp
	case state == "running" && health == "starting":
		return phasePending
	case state == "exited" || state == "dead":
		return phaseFailed
	case state == "restarting":
		// A container stuck restarting is failing its command repeatedly; treat a
		// non-zero exit as a failure but give it a moment via Pending first.
		return phasePending
	default: // created, paused, "", ...
		return phasePending
	}
}

// collectStartup returns the current startup state of every enabled honeypot.
func (m *Manager) collectStartup(ctx context.Context) []honeypotStartup {
	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "ps", "-a", "--format", "json")
	cmd.Dir = m.config.DataPath
	out, err := cmd.Output()
	entries := map[string]composePSEntry{}
	if err == nil {
		entries = parseComposePS(out)
	}

	var result []honeypotStartup
	for name, hp := range m.config.Honeypots {
		if !hp.Enabled {
			continue
		}
		e, present := entries[name]
		hs := honeypotStartup{Name: name, State: e.State, Health: e.Health}
		if !present {
			// No container row yet. During the startup window this just means
			// compose has not created it yet, so treat it as pending and keep
			// polling; only if it is still absent at the final timeout do we
			// report it as failed-to-start (a network/image error aborting
			// creation).
			hs.Phase = phasePending
			hs.State = "absent"
		} else {
			hs.Phase = classifyStartup(e)
		}
		result = append(result, hs)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// honeypotLogTail returns the last n non-empty log lines of a honeypot service,
// used to explain WHY a container failed to start.
func (m *Manager) honeypotLogTail(ctx context.Context, service string, n int) string {
	if !m.isConfiguredHoneypot(service) { // guard the compose arg
		return ""
	}
	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile,
		"logs", "--no-log-prefix", "--tail", fmt.Sprintf("%d", n), service)
	cmd.Dir = m.config.DataPath
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	var lines []string
	for _, ln := range strings.Split(string(out), "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			lines = append(lines, t)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// verifyStartup watches the enabled honeypots until they all settle (each either
// up or failed) or until timeout, then logs a per-honeypot report. It returns
// the names that came up and the ones that failed (with reasons attached). It
// deliberately does NOT abort the instance: the collector, database, web UI and
// the healthy honeypots keep running; the operator just gets a clear account of
// what did not start and why.
func (m *Manager) verifyStartup(ctx context.Context, timeout time.Duration) (up []string, failed []honeypotStartup) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	slog.Info("Verifying honeypot startup", "instance", m.config.InstanceName, "timeout", timeout.String())
	var states []honeypotStartup
	for {
		states = m.collectStartup(ctx)
		pending := 0
		for _, s := range states {
			if s.Phase == phasePending {
				pending++
			}
		}
		if pending == 0 || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, nil
		case <-ticker.C:
		}
	}

	for i := range states {
		s := &states[i]
		switch s.Phase {
		case phaseUp:
			up = append(up, s.Name)
		default: // failed, or still pending at timeout (treated as failed-to-start)
			if s.Phase == phasePending {
				s.Reason = fmt.Sprintf("did not become healthy within %s (state=%s health=%s)",
					timeout, nonEmpty(s.State, "unknown"), nonEmpty(s.Health, "none"))
			} else {
				reason := m.honeypotLogTail(ctx, s.Name, 12)
				s.Reason = fmt.Sprintf("state=%s", nonEmpty(s.State, "unknown"))
				if reason != "" {
					s.Reason += ": " + reason
				}
			}
			failed = append(failed, *s)
		}
	}

	// Emit the report.
	total := len(states)
	if len(failed) == 0 {
		slog.Info("All honeypots started", "instance", m.config.InstanceName,
			"started", len(up), "total", total)
	} else {
		slog.Warn("Some honeypots failed to start", "instance", m.config.InstanceName,
			"started", len(up), "failed", len(failed), "total", total,
			"failed_honeypots", failedNames(failed))
		for _, f := range failed {
			slog.Error("Honeypot did not start", "honeypot", f.Name, "reason", f.Reason)
		}
	}
	return up, failed
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func failedNames(failed []honeypotStartup) string {
	names := make([]string, len(failed))
	for i, f := range failed {
		names[i] = f.Name
	}
	return strings.Join(names, ",")
}
