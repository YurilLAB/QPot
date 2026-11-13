package access

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const owner = "qp_abcdefghijklmnopqrstuvwx"

// A member gets a key once, in the form of a QPot ID; the file holds its
// hash, never the key; the key finds the member, and nothing else does.
func TestMemberKeys(t *testing.T) {
	dir := t.TempDir()
	if l, err := Load(dir); err != nil || len(l.Members) != 0 {
		t.Fatalf("no file: %v", err)
	}
	alice, err := Add(dir, "alice", Viewer, owner)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := Add(dir, "bob.ops", Admin, owner)
	if err != nil {
		t.Fatal(err)
	}
	if !reKey.MatchString(alice) || len(alice) != KeyLength || alice == bob || alice == owner {
		t.Fatalf("keys %q %q", alice, bob)
	}
	data, err := os.ReadFile(Path(dir))
	if err != nil || strings.Contains(string(data), alice) || strings.Contains(string(data), bob) || !strings.Contains(string(data), hashKey(alice)) {
		t.Fatalf("the members file holds a key, or not its hash: %v", err)
	}
	if info, err := os.Stat(Path(dir)); err != nil || (os.PathSeparator == '/' && info.Mode().Perm() != 0o600) {
		t.Fatalf("members file mode: %v", err)
	}
	l, err := Load(dir)
	if err != nil || len(l.Members) != 2 {
		t.Fatal(err)
	}
	if m, ok := l.Lookup(alice); !ok || m.Name != "alice" || m.Role != Viewer || m.Created.IsZero() {
		t.Fatalf("alice: %+v %v", m, ok)
	}
	if m, ok := l.Lookup(bob); !ok || m.Role != Admin {
		t.Fatalf("bob: %+v", m)
	}
	for _, key := range []string{"", owner, alice[:26], alice + "a", strings.ToUpper(alice), hashKey(alice), "qp_" + strings.Repeat("a", 24), alice[:26] + "1"} {
		if m, ok := l.Lookup(key); ok {
			t.Fatalf("%q found %+v", key, m)
		}
	}
	if _, ok := (*List)(nil).Lookup(alice); ok {
		t.Fatal("no list found a member")
	}

	for name, want := range map[string]error{"alice": ErrExists, "": ErrName, "Alice": ErrName, "a b": ErrName, "../x": ErrName, strings.Repeat("a", 33): ErrName} {
		if _, err := Add(dir, name, Viewer, owner); !errors.Is(err, want) {
			t.Errorf("add %q: %v", name, err)
		}
	}
	for _, role := range []Role{"", Owner, "root", "VIEWER"} {
		if _, err := Add(dir, "carol", role, owner); !errors.Is(err, ErrRole) {
			t.Errorf("role %q: %v", role, err)
		}
	}

	// Removed: the key no longer finds anyone.
	if err := Remove(dir, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := Remove(dir, "alice"); !errors.Is(err, ErrNoSuch) {
		t.Fatalf("removed twice: %v", err)
	}
	l, _ = Load(dir)
	if _, ok := l.Lookup(alice); ok || len(l.Members) != 1 {
		t.Fatal("a removed member's key still works")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d files left", len(entries))
	}
	for i := len(l.Members); i < MaxMembers; i++ {
		if _, err := Add(dir, fmt.Sprintf("m%d", i), Analyst, owner); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Add(dir, "onemore", Viewer, owner); !errors.Is(err, ErrFull) {
		t.Fatalf("over the limit: %v", err)
	}
}

// A members file that is damaged or was edited into something else lets no
// one in and is not written over.
func TestDamagedMembersFile(t *testing.T) {
	good := `{"version":1,"members":[{"name":"a","role":"viewer","key_sha256":"` + strings.Repeat("0", 64) + `","created":"2026-11-14T00:00:00Z"}]}`
	for name, content := range map[string]string{
		"not JSON":         "{",
		"another version":  strings.Replace(good, `"version":1`, `"version":2`, 1),
		"an owner member":  strings.Replace(good, "viewer", "owner", 1),
		"a short hash":     strings.Replace(good, strings.Repeat("0", 64), "00", 1),
		"a bad name":       strings.Replace(good, `"name":"a"`, `"name":"A B"`, 1),
		"an unknown field": strings.Replace(good, `"created"`, `"key":"qp_x","created"`, 1),
		"the same name":    strings.Replace(good, `}]}`, `},{"name":"a","role":"admin","key_sha256":"`+strings.Repeat("1", 64)+`","created":"2026-11-14T00:00:00Z"}]}`, 1),
	} {
		dir := t.TempDir()
		if err := os.WriteFile(Path(dir), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Errorf("%s was read as a members file", name)
		}
		if _, err := Add(dir, "new", Viewer, owner); err == nil {
			t.Errorf("%s: a member was added", name)
		}
		if data, _ := os.ReadFile(Path(dir)); string(data) != content {
			t.Errorf("%s: the file was written over", name)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(Path(dir), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := Load(dir); err != nil || len(l.Members) != 1 {
		t.Fatalf("a good file: %v", err)
	}
}

// What each role may ask of the web API.
func TestRolesAllowed(t *testing.T) {
	type req struct{ method, path string }
	read := []req{{http.MethodGet, "/api/events"}, {http.MethodGet, "/api/canaries"}, {http.MethodHead, "/api/status"}, {http.MethodGet, "/api/investigate/export"}}
	analyst := []req{{http.MethodPost, "/api/canaries"}, {http.MethodDelete, "/api/canaries"}, {http.MethodPut, "/api/alerts"}}
	admin := []req{{http.MethodPost, "/api/honeypots"}, {http.MethodPut, "/api/honeypots/settings"}, {http.MethodPost, "/api/honeypots/restart"},
		{http.MethodPut, "/api/cleanup"}, {http.MethodPost, "/api/cleanup/run"}, {http.MethodPost, "/api/canaries/trips"}, {http.MethodPatch, "/api/alerts/x"}, {"BREW", "/api/canaries/"}}
	for role, want := range map[Role][3]bool{Viewer: {true, false, false}, Analyst: {true, true, false}, Admin: {true, true, true}, Owner: {true, true, true}, "": {false, false, false}, "root": {false, false, false}} {
		for i, group := range [][]req{read, analyst, admin} {
			for _, r := range group {
				if got := Allowed(role, r.method, r.path); got != want[i] {
					t.Errorf("%q %s %s: allowed %v", role, r.method, r.path, got)
				}
			}
		}
	}
	if !ValidRole(Viewer) || ValidRole(Owner) || ValidRole("") || len(Roles) != 3 {
		t.Fatal("roles")
	}
}

// The audit log keeps who did what, newest first, within a bounded size.
func TestAuditLog(t *testing.T) {
	dir := t.TempDir()
	if got, err := ReadAudit(dir, 10); err != nil || len(got) != 0 {
		t.Fatalf("no log: %v", err)
	}
	a := NewAudit(dir)
	base := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if err := a.Record(Entry{Time: base.Add(time.Duration(i) * time.Minute), Who: "alice", Role: Analyst, Method: "PUT", Path: "/api/alerts", Status: 200, Remote: "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Record(Entry{Time: base.Add(time.Hour), Who: "bob", Role: Viewer, Method: "POST", Path: "/api/honeypots?" + strings.Repeat("x", 5000), Status: 403, Denied: true}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadAudit(dir, 3)
	if err != nil || len(got) != 3 || got[0].Who != "bob" || !got[0].Denied || len(got[0].Path) != 256 || got[1].Time != base.Add(4*time.Minute) {
		t.Fatalf("read: %v %+v", err, got)
	}
	// Past its size the log is set aside and started again; both are read.
	a.max = 2000
	for i := 0; i < 40; i++ {
		if err := a.Record(Entry{Time: base.Add(2*time.Hour + time.Duration(i)*time.Second), Who: "alice", Role: Admin, Method: "POST", Path: "/api/cleanup/run", Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"audit.log", "audit.log.1"} {
		if info, err := os.Stat(dir + "/" + name); err != nil || info.Size() > 2000 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	got, err = ReadAudit(dir, 0)
	if err != nil || len(got) < 10 || got[0].Time != base.Add(2*time.Hour+39*time.Second) {
		t.Fatalf("after rotation: %v, %d entries", err, len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].Time.After(got[i-1].Time) {
			t.Fatal("not newest first")
		}
	}
	if err := (*Audit)(nil).Record(Entry{}); err != nil {
		t.Fatal(err)
	}
}

func FuzzLoadMembers(f *testing.F) {
	f.Add([]byte(`{"version":1,"members":[{"name":"a","role":"viewer","key_sha256":"` + strings.Repeat("0", 64) + `","created":"2026-11-14T00:00:00Z"}]}`))
	f.Add([]byte(`{"version":1,"members":null}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(Path(dir), data, 0o600); err != nil {
			t.Fatal(err)
		}
		l, err := Load(dir)
		if err != nil {
			return
		}
		// Whatever was read holds only members a key can find, and no owner.
		for _, m := range l.Members {
			if !reName.MatchString(m.Name) || !ValidRole(m.Role) || len(m.KeyHash) != 64 {
				t.Fatalf("read a member that is none: %+v", m)
			}
		}
		if _, ok := l.Lookup(owner); ok && !strings.Contains(string(data), hashKey(owner)) {
			t.Fatal("a key found a member whose hash is not in the file")
		}
	})
}

func FuzzAllowed(f *testing.F) {
	for _, s := range [][3]string{{"viewer", "GET", "/api/events"}, {"analyst", "POST", "/api/canaries"}, {"viewer", "POST", "/api/canaries"}, {"", "GET", "/"}, {"owner", "X", "y"}} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, role, method, path string) {
		got := Allowed(Role(role), method, path)
		switch Role(role) {
		case Owner, Admin:
			if !got {
				t.Fatalf("%s refused %s %s", role, method, path)
			}
		case Viewer:
			if got != (method == "GET" || method == "HEAD") {
				t.Fatalf("viewer %s %s: %v", method, path, got)
			}
		case Analyst:
			if got && method != "GET" && method != "HEAD" && path != "/api/canaries" && path != "/api/alerts" {
				t.Fatalf("analyst allowed %s %s", method, path)
			}
		default:
			if got {
				t.Fatalf("role %q allowed %s %s", role, method, path)
			}
		}
	})
}
