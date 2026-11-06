package main

import (
	"slices"
	"strings"
	"testing"
)

// TestPopupKeepsQPotIDOutOfArgv: the start-up popup passed the QPot ID (the
// web UI/API credential) as a command-line argument of notify-send, zenity,
// kdialog, osascript or PowerShell, where every local user can read it with
// ps while the dialog is open.
func TestPopupKeepsQPotIDOutOfArgv(t *testing.T) {
	const id = "qp_mex2bshuyobxhwltkvllbwdp"
	only := func(bin string) func(string) bool { return func(b string) bool { return b == bin } }
	cases := []struct {
		goos string
		has  func(string) bool
	}{
		{"windows", only("pwsh")},
		{"windows", only("")},
		{"darwin", only("")},
		{"linux", only("notify-send")},
		{"linux", only("zenity")},
		{"linux", only("kdialog")},
	}
	for _, c := range cases {
		cmds := popupCommands(c.goos, id, "prod", 8080, c.has)
		if len(cmds) == 0 {
			t.Errorf("%s: no popup", c.goos)
		}
		for _, p := range cmds {
			for _, a := range append([]string{p.name}, p.args...) {
				if strings.Contains(a, id) {
					t.Errorf("%s/%s: QPot ID in argv: %q", c.goos, p.name, a)
				}
			}
			// Where the helper can read it from the environment, the
			// popup still shows the ID.
			if c.goos != "linux" && !slices.Contains(p.env, popupIDEnv+"="+id) {
				t.Errorf("%s/%s: ID not passed in the environment", c.goos, p.name)
			}
			if c.goos == "linux" && !strings.Contains(strings.Join(p.args, " "), "qpot id -i prod") {
				t.Errorf("%s/%s: popup does not say how to show the ID", c.goos, p.name)
			}
		}
	}
	if cmds := popupCommands("linux", id, "prod", 8080, only("")); len(cmds) != 0 {
		t.Errorf("headless linux: %d popups", len(cmds))
	}
}
