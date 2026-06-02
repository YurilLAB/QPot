package instance

import "testing"

func TestClassifyStartup(t *testing.T) {
	cases := []struct {
		state, health string
		want          startupPhase
	}{
		{"running", "healthy", phaseUp},
		{"running", "", phaseUp}, // no healthcheck configured
		{"running", "starting", phasePending},
		{"running", "unhealthy", phaseFailed},
		{"exited", "", phaseFailed},
		{"dead", "", phaseFailed},
		{"created", "", phasePending},
		{"restarting", "", phasePending},
		{"Running", "Healthy", phaseUp}, // case-insensitive
	}
	for _, c := range cases {
		got := classifyStartup(composePSEntry{State: c.state, Health: c.health})
		if got != c.want {
			t.Errorf("classifyStartup(state=%q health=%q) = %d, want %d", c.state, c.health, got, c.want)
		}
	}
}

// TestParseComposePSExitCode confirms the exit code is parsed (used in failure
// reasons) and that case-insensitive JSON keys from docker compose v2 are read.
func TestParseComposePSExitCode(t *testing.T) {
	out := []byte(`{"Service":"cowrie","State":"exited","Health":"","ExitCode":1}
{"Service":"heralding","State":"running","Health":"healthy","ExitCode":0}`)
	got := parseComposePS(out)
	if e, ok := got["cowrie"]; !ok || e.State != "exited" || e.ExitCode != 1 {
		t.Errorf("cowrie entry = %+v, want exited/exit1", got["cowrie"])
	}
	if classifyStartup(got["cowrie"]) != phaseFailed {
		t.Error("exited cowrie should classify as failed")
	}
	if classifyStartup(got["heralding"]) != phaseUp {
		t.Error("healthy heralding should classify as up")
	}
}

func TestFailedNames(t *testing.T) {
	f := []honeypotStartup{{Name: "cowrie"}, {Name: "medpot"}}
	if got := failedNames(f); got != "cowrie,medpot" {
		t.Errorf("failedNames = %q", got)
	}
}
