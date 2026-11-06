package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

func TestLocalBaseURLHandlesIPv6(t *testing.T) {
	for bind, want := range map[string]string{
		"":          "http://127.0.0.1:8080",
		"0.0.0.0":   "http://127.0.0.1:8080",
		"::":        "http://127.0.0.1:8080",
		"::1":       "http://[::1]:8080",
		"[::1]":     "http://[::1]:8080",
		"10.0.0.5":  "http://10.0.0.5:8080",
		"localhost": "http://localhost:8080",
	} {
		cfg := config.Default("u")
		cfg.WebUI.BindAddr, cfg.WebUI.Port = bind, 8080
		got := localBaseURL(cfg)
		if got != want {
			t.Errorf("bind %q: %q, want %q", bind, got, want)
		}
		if _, err := url.Parse(got + "/api/overview"); err != nil {
			t.Errorf("bind %q: %q does not parse: %v", bind, got, err)
		}
	}
}

func TestCheckInstanceFlag(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	if err := config.Save(config.Default("exists")); err != nil {
		t.Fatal(err)
	}
	root := &cobra.Command{Use: "qpot"}
	mk := func(path ...string) *cobra.Command {
		parent := root
		var c *cobra.Command
		for _, p := range path {
			c = &cobra.Command{Use: p}
			parent.AddCommand(c)
			parent = c
		}
		c.Flags().StringP("instance", "i", "default", "")
		return c
	}
	cases := []struct {
		cmd     *cobra.Command
		name    string
		wantErr bool
	}{
		{mk("status"), "exists", false},
		{mk("status2"), "missing", true},           // must exist
		{mk("honeypot", "enable"), "my pot", true}, // invalid name
		{mk("x1"), "a\nb", true},
		{mk("x2"), "../etc", true},
		{mk("setup"), "brand-new", false},          // creates it
		{mk("honeypot2", "list"), "missing", true}, // only the real `honeypot list` is exempt
	}
	for _, tc := range cases {
		if err := tc.cmd.Flags().Set("instance", tc.name); err != nil {
			t.Fatal(err)
		}
		err := checkInstanceFlag(tc.cmd, nil)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s -i %q: err=%v, wantErr=%v", tc.cmd.CommandPath(), tc.name, err, tc.wantErr)
		}
	}
	// No config is created for a rejected or missing name.
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".qpot", "instances", "missing")); !os.IsNotExist(err) {
		t.Error("a config directory was created for a missing instance")
	}
}

func TestLastLogLineSkipsNoise(t *testing.T) {
	p := filepath.Join(t.TempDir(), "serve.log")
	if err := os.WriteFile(p, []byte("first\nweb UI address 127.0.0.1:8080 is already in use\nWarning: gvisor sandbox not available\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := lastLogLine(p); got != "web UI address 127.0.0.1:8080 is already in use" {
		t.Errorf("lastLogLine = %q", got)
	}
}

// TestHoneypotSetHelpListsConpotTemplates keeps the help text's device list in
// step with the templates QPot can run.
func TestHoneypotSetHelpListsConpotTemplates(t *testing.T) {
	var set *cobra.Command
	for _, c := range newHoneypotCommand().Commands() {
		if c.Name() == "set" {
			set = c
		}
	}
	if set == nil {
		t.Fatal("no honeypot set command")
	}
	help := strings.Join(strings.Fields(set.Long), " ")
	for _, id := range instance.ConpotTemplateIDs() {
		if !strings.Contains(help, id) {
			t.Errorf("honeypot set help does not list conpot template %q", id)
		}
	}
}
