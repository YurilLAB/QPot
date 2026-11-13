package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/access"
	"github.com/qpot/qpot/internal/config"
)

func executeAccess(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "qpot", SilenceUsage: true, SilenceErrors: true, PersistentPreRunE: checkInstanceFlag}
	root.AddCommand(newAccessCommand())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"access"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestAccessCommand(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	path := config.Default("lab").ConfigPath
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("instance_name: lab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	const owner = "qp_abcdefghijklmnopqrstuvwx"
	real := accessContext
	t.Cleanup(func() { accessContext = real })
	accessContext = func(string) (string, string, error) { return dir, owner, nil }

	if out, err := executeAccess(t, "list", "-i", "lab"); err != nil || !strings.Contains(out, "No members") {
		t.Fatalf("empty list: %v\n%s", err, out)
	}
	out, err := executeAccess(t, "add", "alice", "--role", "analyst", "-i", "lab")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	key := regexp.MustCompile(`Key: (qp_[a-z2-7]{24})\n`).FindStringSubmatch(out)
	if key == nil || !strings.Contains(out, "Added alice as analyst on instance lab") || !strings.Contains(out, "shown once") || strings.Contains(out, owner) {
		t.Fatalf("add output:\n%s", out)
	}
	l, err := access.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := l.Lookup(key[1]); !ok || m.Name != "alice" || m.Role != access.Analyst {
		t.Fatalf("the printed key finds %+v", m)
	}
	if out, err = executeAccess(t, "add", "bob", "-i", "lab"); err != nil || !strings.Contains(out, "Added bob as viewer") {
		t.Fatalf("default role: %v\n%s", err, out)
	}
	out, err = executeAccess(t, "list", "-i", "lab")
	if err != nil || !regexp.MustCompile(`alice +analyst +20\d\d-`).MatchString(out) || !regexp.MustCompile(`bob +viewer `).MatchString(out) || strings.Contains(out, key[1]) || strings.Contains(out, "sha256") {
		t.Fatalf("list: %v\n%s", err, out)
	}

	// The log, as the control plane writes it.
	a := access.NewAudit(dir)
	at := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	_ = a.Record(access.Entry{Time: at, Who: "alice", Role: access.Analyst, Method: "PUT", Path: "/api/alerts", Status: 200})
	_ = a.Record(access.Entry{Time: at.Add(time.Minute), Who: "bob", Role: access.Viewer, Method: "POST", Path: "/api/honeypots\x1b[2J", Status: 403, Denied: true})
	out, err = executeAccess(t, "log", "-i", "lab")
	if err != nil || !regexp.MustCompile(`2026-11-14 09:01:00 +bob +viewer +POST +403 +/api/honeypots\\x1b\[2J refused: the role may not do this`).MatchString(out) ||
		!regexp.MustCompile(`2026-11-14 09:00:00 +alice +analyst +PUT +200 +/api/alerts\n`).MatchString(out) || strings.ContainsRune(out, 0x1b) {
		t.Fatalf("log: %v\n%s", err, out)
	}
	if out, err = executeAccess(t, "log", "-i", "lab", "--json", "--limit", "1"); err != nil || !strings.Contains(out, `"who": "bob"`) || strings.Contains(out, "alice") {
		t.Fatalf("log --json: %v\n%s", err, out)
	}

	if out, err = executeAccess(t, "remove", "alice", "-i", "lab"); err != nil || !strings.Contains(out, "Removed alice") {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	if l, _ = access.Load(dir); len(l.Members) != 1 {
		t.Fatal("alice is still a member")
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"add", "bob", "-i", "lab"}, "exists already"},
		{[]string{"add", "Carol", "-i", "lab"}, "lower-case"},
		{[]string{"add", "carol", "--role", "owner", "-i", "lab"}, "viewer, analyst or admin"},
		{[]string{"remove", "alice", "-i", "lab"}, "no member of that name"},
		{[]string{"log", "-i", "lab", "--limit", "0"}, "--limit must be"},
		{[]string{"list", "-i", "missing"}, `instance "missing" does not exist`},
		{[]string{"add", "-i", "lab"}, "accepts 1 arg"},
	} {
		if out, err := executeAccess(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v\n%s", tc.args, err, out)
		}
	}
}
