package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
)

// TestExplainCodedErrorPrintsWhyAndFix: `qpot up` on Docker Desktop printed
// only "QP-DOCKER-011: <title>" and the reason and fix stayed hidden.
func TestExplainCodedErrorPrintsWhyAndFix(t *testing.T) {
	coded := hostsetup.E("QP-DOCKER-011").WithWhy("no \"runsc\" runtime \x1b]52;c;x\a").WithFix("set security.sandbox_mode: none")
	var out bytes.Buffer
	explainCodedError(&out, fmt.Errorf("failed to start instance: %w", coded))
	got := out.String()
	for _, want := range []string{"  Why:  no \"runsc\" runtime", "  Fix:  set security.sandbox_mode: none\n", "  More: qpot doctor --explain QP-DOCKER-011\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q lacks %q", got, want)
		}
	}
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x07) {
		t.Errorf("control bytes reached the terminal: %q", got)
	}
	// A message that already carries the fix, an uncoded error and no error
	// print nothing more.
	for _, err := range []error{fmt.Errorf("%w: %s Fix: %s", coded, coded.Cause(), coded.Remedy()), errors.New("plain"), nil} {
		out.Reset()
		explainCodedError(&out, err)
		if out.Len() != 0 {
			t.Errorf("%v: printed %q", err, out.String())
		}
	}
}

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

// Explore the industrial catalog before creating an instance, without Docker or writes.
func TestIndustrialProfilesCatalogCLI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := &cobra.Command{Use: "qpot", PersistentPreRunE: checkInstanceFlag, SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(newHoneypotCommand())
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetArgs([]string{"honeypot", "profiles", "conpot", "-i", "not-created"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Industrial control systems", "plc_modbus", "Modbus", "502/tcp", "IEC104", "Host ports", "Limits:"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("catalog omits %q: %s", want, output.String())
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".qpot")); !os.IsNotExist(err) {
		t.Fatalf("read-only catalog created instance files: %v", err)
	}
	root.SetArgs([]string{"honeypot", "profiles", "cowrie"})
	if err := root.Execute(); err == nil {
		t.Fatal("unsupported profiles accepted")
	}
}

func TestIndustrialProfilesCatalogWithBrokenConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".qpot", "instances", "broken-industrial")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("honeypots:\n  conpot:\n    custom_config:\n      template: unsupported-device\n")
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	root := &cobra.Command{Use: "qpot", PersistentPreRunE: checkInstanceFlag}
	root.AddCommand(newHoneypotCommand())
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetArgs([]string{"honeypot", "profiles", "-i", "broken-industrial"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Effective device unavailable", "unsupported-device", "plc_modbus", "Catalog only"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("recovery catalog omits %q", want)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("catalog changed broken configuration")
	}
}

func TestIndustrialHoneypotCommandErrorsAreCoded(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	cfg := config.Default("coded-industrial")
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		code string
	}{
		{[]string{"set", "refrigeration", "site_profile=invalid"}, "QP-INPUT-012"},
		{[]string{"set", "conpot", "template=invalid"}, "QP-INPUT-012"},
		{[]string{"set", "cowrie", "bait_target=invalid"}, "QP-INPUT-012"},
		{[]string{"enable", "unknown-native"}, "QP-INPUT-003"},
		{[]string{"disable", "unknown-native"}, "QP-INPUT-003"},
	} {
		root := &cobra.Command{Use: "qpot", SilenceErrors: true, SilenceUsage: true}
		root.AddCommand(newHoneypotCommand())
		root.SetArgs(append(append([]string{"honeypot"}, tc.args...), "-i", "coded-industrial"))
		err := root.Execute()
		var coded *hostsetup.Error
		if !errors.As(err, &coded) || coded.Code != tc.code || !strings.Contains(err.Error(), "Fix:") {
			t.Errorf("%v: %v, want %s with guidance", tc.args, err, tc.code)
		}
		if commandExitStatus(err) != 1 {
			t.Errorf("%v changed existing CLI exit status", tc.args)
		}
	}
	after, err := os.ReadFile(cfg.ConfigPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid newtemplate/scenario command changed configuration")
	}
}

func TestHoneypotCommandErrorRetainsCauseAndSavedState(t *testing.T) {
	cause := errors.New("local image builder unavailable")
	for _, tc := range []struct {
		name  string
		err   error
		saved bool
		code  string
	}{
		{"refrigeration", cause, true, "QP-INST-008"},
		{"conpot", &instance.SettingsError{Kind: instance.ErrRecreateFailed, Msg: "settings saved, but container failed", Err: cause}, true, "QP-INST-008"},
		{"refrigeration", &instance.SettingsError{Kind: instance.ErrSaveFailed, Msg: "failed to save config", Err: cause}, false, "QP-INST-002"},
	} {
		err := honeypotCommandError(tc.name, tc.err, tc.saved)
		var coded *hostsetup.Error
		if !errors.As(err, &coded) || coded.Code != tc.code || !errors.Is(err, cause) {
			t.Fatalf("%+v: %v", tc, err)
		}
		if tc.saved && !strings.Contains(err.Error(), "configuration was saved") {
			t.Errorf("saved failure lost saved status: %v", err)
		}
		if tc.name == "refrigeration" && tc.saved && (!strings.Contains(err.Error(), "QPot service output") || !strings.Contains(err.Error(), "saved scenario may not be live")) {
			t.Errorf("local build failure has misleading log advice: %v", err)
		}
	}
	if honeypotCommandError("conpot", nil, false) != nil {
		t.Fatal("nil became error")
	}
	if got := honeypotCommandError("conpot", cause, false); got != cause {
		t.Fatal("unexpected failure was mislabeled")
	}
}
