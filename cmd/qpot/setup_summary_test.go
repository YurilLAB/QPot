package main

import (
	"bytes"
	"strings"
	"testing"
)

func sampleSummary() setupSummary {
	return setupSummary{
		Instance: "sensor1", Started: true, Healthy: true, Bind: "127.0.0.1", Port: 8081,
		ShowID: true, QPotID: "qp_" + strings.Repeat("ab", 12), SSHTarget: "alice@192.0.2.10",
		Honeypots: []honeypotPorts{{Name: "cowrie", Risk: "low", Ports: []portPair{{22, 12022}, {23, 12023}}},
			{Name: "endlessh", Risk: "low", Ports: []portPair{{2222, 13001}}}},
		Config: "/home/alice/.qpot/instances/sensor1/config.yaml", DataPath: "/home/alice/.qpot/instances/sensor1",
		ServeLog: "/home/alice/.qpot/instances/sensor1/logs/qpot-serve.log", SetupLog: "/home/alice/.qpot/logs/setup.log",
		Sandbox: "standard Docker containers",
	}
}

func TestRenderSummary(t *testing.T) {
	var b bytes.Buffer
	s := sampleSummary()
	renderSummary(&b, s)
	out := b.String()
	for _, want := range []string{
		"QPot is running: instance \"sensor1\"",
		"Open:        http://127.0.0.1:8081/",
		"Log in with your QPot ID: " + s.QPotID,
		"Show it again any time with: qpot id -i sensor1",
		"ssh -N -L 8081:127.0.0.1:8081 alice@192.0.2.10",
		"cowrie          [low risk] 12022 (as 22), 12023 (as 23)",
		"endlessh        [low risk] 13001 (as 2222)",
		"Settings:    /home/alice/.qpot/instances/sensor1/config.yaml",
		"Web UI log:  /home/alice/.qpot/instances/sensor1/logs/qpot-serve.log",
		"qpot status -i sensor1", "qpot logs -i sensor1", "qpot doctor -i sensor1", "qpot down -i sensor1",
		"qpot config -i sensor1", "qpot doctor --explain <code>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}

	// Not on the owner's terminal (output redirected to a file or a log):
	// the ID is never printed, only how to show it.
	s.ShowID = false
	b.Reset()
	renderSummary(&b, s)
	if strings.Contains(b.String(), s.QPotID) || !strings.Contains(b.String(), "Show it with: qpot id -i sensor1") {
		t.Errorf("ID leaked or hint missing:\n%s", b.String())
	}

	// The default instance needs no -i; a network bind gets a warning and no tunnel.
	s.Instance, s.Bind = "default", "0.0.0.0"
	b.Reset()
	renderSummary(&b, s)
	if strings.Contains(b.String(), " -i ") || strings.Contains(b.String(), "ssh -N -L") ||
		!strings.Contains(b.String(), "reachable from the network over plain HTTP") {
		t.Errorf("default/0.0.0.0 summary:\n%s", b.String())
	}

	s.Started = false
	b.Reset()
	renderSummary(&b, s)
	if !strings.Contains(b.String(), "(not started yet)") || !strings.Contains(b.String(), "qpot up -d") {
		t.Errorf("not-started summary:\n%s", b.String())
	}
}

// shape replaces every text field with a harmless placeholder that keeps
// the summary's layout (empty stays empty; the bind address keeps its kind).
func shape(s setupSummary) setupSummary {
	ph := func(x string) string {
		if x == "" {
			return ""
		}
		return "v"
	}
	switch {
	case s.Bind == "0.0.0.0" || s.Bind == "::" || s.Bind == "":
	case s.loopback():
		s.Bind = "127.0.0.1"
	default:
		s.Bind = "192.0.2.1"
	}
	s.Instance, s.Config, s.DataPath, s.ServeLog, s.SetupLog = ph(s.Instance), ph(s.Config), ph(s.DataPath), ph(s.ServeLog), ph(s.SetupLog)
	s.SSHTarget, s.Sandbox, s.QPotID = ph(s.SSHTarget), ph(s.Sandbox), ph(s.QPotID)
	hps := make([]honeypotPorts, len(s.Honeypots))
	for i, h := range s.Honeypots {
		hps[i] = honeypotPorts{Name: ph(h.Name), Risk: ph(h.Risk), Ports: h.Ports}
	}
	s.Honeypots = hps
	return s
}

// FuzzRenderSummary puts hostile text into every field that can come from
// the system or a config file: nothing may reach the terminal as a control
// sequence (OSC 52 clipboard writes, cursor moves, bidi overrides), and no
// value can add or remove lines.
func FuzzRenderSummary(f *testing.F) {
	f.Add("sensor1", "cowrie", "/home/a/.qpot", "alice@host", "127.0.0.1", "low")
	f.Add("\x1b]52;c;aGk=\x07", "\x1b[2J\x1b[H", "/tmp/\xe2\x80\xaeevil", "\xc2\x9b31m", "::1", "\r\x00")
	f.Add("x", "\xff\xfe", "\n\n", "\t", "0.0.0.0", "\xe2\x81\xa6")
	f.Fuzz(func(t *testing.T, inst, hp, path, target, bind, risk string) {
		s := sampleSummary()
		s.Instance, s.Config, s.DataPath, s.ServeLog, s.SetupLog, s.SSHTarget, s.Bind, s.Sandbox = inst, path, path, path, path, target, bind, risk
		s.QPotID = "qp_" + hp
		s.Honeypots = append(s.Honeypots, honeypotPorts{Name: hp, Risk: risk, Ports: []portPair{{1, 2}}})
		var b, ref bytes.Buffer
		renderSummary(&b, s)
		for _, r := range b.String() {
			if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
				(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
				t.Fatalf("unsafe rune %U in summary", r)
			}
		}
		renderSummary(&ref, shape(s))
		if got, want := strings.Count(b.String(), "\n"), strings.Count(ref.String(), "\n"); got != want {
			t.Fatalf("hostile text changed the line count: %d, want %d", got, want)
		}
	})
}
