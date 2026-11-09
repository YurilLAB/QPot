package sshbackend

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testManifest() Manifest {
	return Manifest{Version: 1, Role: "app", Organization: "North service", Directories: []Directory{{Path: "/srv/app", Mode: 0o750, Owner: "operator"}}, Files: []File{{Path: "/srv/app/.env", Content: "DATABASE_HOST=db\n", Mode: 0o640, Owner: "operator"}}}
}

func TestManifestPreflightAndAtomicSeed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership and permissions")
	}
	root := t.TempDir()
	m := testManifest()
	lookup := func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil }
	if err := Seed(root, m, lookup); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "srv/app/.env")
	data, err := os.ReadFile(file)
	if err != nil || string(data) != m.Files[0].Content {
		t.Fatalf("seeded file: %q %v", data, err)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("real mode: %v %v", info, err)
	}
	m.Files[0].Content = "DATABASE_HOST=changed\n"
	if err := Seed(root, m, lookup); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(file)
	if string(data) != m.Files[0].Content {
		t.Fatal("replacement did not take effect")
	}
	before, _ := os.ReadFile(file)
	bad := m
	bad.Files = append(append([]File(nil), m.Files...), File{Path: "/etc/passwd", Content: "bad", Mode: 0o644, Owner: "operator"})
	if err := Seed(root, bad, lookup); err == nil {
		t.Fatal("reserved account database accepted")
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid manifest partially changed files")
	}
	if err := Seed(root, m, func(string) (int, int, error) { return 0, 0, errors.New("unknown") }); err == nil {
		t.Fatal("unknown owner accepted")
	}
	after, _ = os.ReadFile(file)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid owner partially changed files")
	}
}

func TestManifestRefusesSymlinkEscapeAndMalformedInputs(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "srv"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "srv/app")); err != nil {
		t.Skip(err)
	}
	if err := Seed(root, testManifest(), func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil }); err == nil {
		t.Fatal("symlink parent accepted")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("wrote outside scene root")
	}
	base, _ := json.Marshal(testManifest())
	if _, err := DecodeManifest(base); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, append(append([]byte(nil), base...), []byte(" {}")...), []byte(`{"version":1,"role":"app","organization":"x","unknown":1}`), bytes.Repeat([]byte(" "), MaxManifestBytes+1)} {
		if _, err := DecodeManifest(data); err == nil {
			t.Fatalf("invalid input accepted: %.80s", data)
		}
	}
	for _, name := range []string{"/srv/app/../../etc/passwd", "/srv//app/file", "/etc/ssh/keys/key", "/proc/1/environ", "/etc/ssh/sshd_config", "/usr/local/libexec/session-audit", "relative/file"} {
		m := testManifest()
		m.Files[0].Path = name
		if err := m.Validate(); err == nil {
			t.Errorf("unsafe path accepted %q", name)
		}
	}
}

func TestAccountsAndEnvironmentAreBounded(t *testing.T) {
	accounts, err := ParseAccounts("root:root123,bkp:operator123")
	if err != nil || len(accounts) != 2 || accounts[1].Name != "bkp" {
		t.Fatalf("parse: %v %v", accounts, err)
	}
	for _, value := range []string{"root:", "../root:a", "-root:a", "root:a,root:b", "root:a\nb", "root:a:b", strings.Repeat("a", 17<<10)} {
		if _, err := ParseAccounts(value); err == nil {
			t.Errorf("malformed account accepted %q", value[:min(len(value), 80)])
		}
	}
	got := FilterEnvironment([]string{"PATH=/usr/bin", "LANG=C.UTF-8", "BACKEND_USERS=secret", "BACKEND_SCENE=secret", "BACKEND_HOST_KEYS=secret", "HTTPS_PROXY=outside", "http_proxy=outside", "DOCKER_HOST=outside"})
	if strings.Join(got, "\n") != "PATH=/usr/bin\nLANG=C.UTF-8" {
		t.Fatalf("bootstrap secret/proxy leaked: %v", got)
	}
}

func TestPrivateHostKeyBootstrapRefusesNonordinaryParents(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Unix directory permissions")
	}
	for _, invalid := range []string{"file", "symlink", "ancestor symlink"} {
		t.Run(invalid, func(t *testing.T) {
			parent, outside := t.TempDir(), t.TempDir()
			if err := os.Chmod(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(parent, "bootstrap")
			var err error
			switch invalid {
			case "file":
				err = os.WriteFile(name, []byte("preserved"), 0o600)
			case "symlink":
				err = os.Symlink(outside, name)
			default:
				err = os.Symlink(outside, name)
				name = filepath.Join(name, "child")
			}
			if err != nil {
				t.Fatal(err)
			}
			root, err := hostKeyDirectory(name)
			if root != nil {
				root.Close()
			}
			if err == nil {
				t.Fatal("nonordinary bootstrap parent accepted")
			}
			info, err := os.Stat(outside)
			if err != nil || info.Mode().Perm() != 0o755 {
				t.Fatal("bootstrap followed or chmodded the outside directory")
			}
		})
	}
}

func TestServeRefusesAccidentalHostBootstrap(t *testing.T) {
	t.Setenv("SESSION_CONTAINER", "")
	if err := Serve(); err == nil {
		t.Fatal("unconfigured host bootstrap was accepted")
	}
}

func TestExistingSystemGroupIsReusedForNewAccount(t *testing.T) {
	args, err := newAccountArgs("operator", func(string) (*user.Group, error) { return &user.Group{Name: "operator", Gid: "37"}, nil })
	if err != nil || strings.Join(args, " ") != "-m -s /bin/bash -g operator -- operator" {
		t.Fatalf("existing group: %v %v", args, err)
	}
	args, err = newAccountArgs("bkp", func(string) (*user.Group, error) { return nil, user.UnknownGroupError("bkp") })
	if err != nil || strings.Join(args, " ") != "-m -s /bin/bash -- bkp" {
		t.Fatalf("new private group: %v %v", args, err)
	}
	if _, err := newAccountArgs("bkp", func(string) (*user.Group, error) { return nil, errors.New("unreadable group database") }); err == nil {
		t.Fatal("group lookup error silently treated as nonexistent")
	}
}

func syntheticHostKeys() map[string]string {
	keys := map[string]string{}
	for _, kind := range hostKeyKinds {
		keys[kind] = "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-" + kind + "\n-----END OPENSSH PRIVATE KEY-----\n"
	}
	return keys
}

func hostKeysValue(keys map[string]string) string {
	var parts []string
	for _, kind := range hostKeyKinds {
		if v, ok := keys[kind]; ok {
			parts = append(parts, kind+":"+base64.StdEncoding.EncodeToString([]byte(v)))
		}
	}
	return strings.Join(parts, ",")
}

func TestParseHostKeys(t *testing.T) {
	keys := syntheticHostKeys()
	got, err := ParseHostKeys(hostKeysValue(keys))
	if err != nil || len(got) != 3 || string(got["ed25519"]) != keys["ed25519"] {
		t.Fatalf("parse: %v %v", got, err)
	}
	if got, err := ParseHostKeys(""); err != nil || got != nil {
		t.Fatalf("no value means no keys: %v %v", got, err)
	}
	missing := syntheticHostKeys()
	delete(missing, "rsa")
	notKey := syntheticHostKeys()
	notKey["ecdsa"] = "just text"
	for name, value := range map[string]string{
		"missing kind":   hostKeysValue(missing),
		"not a key":      hostKeysValue(notKey),
		"unknown kind":   hostKeysValue(keys) + ",dsa:" + base64.StdEncoding.EncodeToString([]byte(keys["rsa"])),
		"duplicate kind": hostKeysValue(keys) + ",rsa:" + base64.StdEncoding.EncodeToString([]byte(keys["rsa"])),
		"bad base64":     "rsa:@@@,ecdsa:@@@,ed25519:@@@",
		"oversized":      strings.Repeat("a", 300<<10),
	} {
		if _, err := ParseHostKeys(value); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestHostKeysAreInstalledLikeDebian(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the native SSH daemon is Linux-only")
	}
	keys := map[string][]byte{}
	for kind, v := range syntheticHostKeys() {
		keys[kind] = []byte(v)
	}
	public := func(private string) ([]byte, error) {
		return []byte("public " + filepath.Base(private) + "\n"), nil
	}
	destination := filepath.Join(t.TempDir(), "ssh")
	if err := os.Mkdir(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := writeHostKeys(destination, keys, public); err != nil {
			t.Fatal(err)
		}
	}
	for kind, want := range keys {
		name := filepath.Join(destination, "ssh_host_"+kind+"_key")
		data, err := os.ReadFile(name)
		info, statErr := os.Stat(name)
		if err != nil || statErr != nil || !bytes.Equal(data, want) || info.Mode().Perm() != 0o600 || fileUID(info) != os.Geteuid() {
			t.Fatalf("%s: %v %v %v", kind, err, statErr, info)
		}
		data, err = os.ReadFile(name + ".pub")
		info, statErr = os.Stat(name + ".pub")
		if err != nil || statErr != nil || string(data) != "public ssh_host_"+kind+"_key\n" || info.Mode().Perm() != 0o644 {
			t.Fatalf("%s public half: %q %v %v %v", kind, data, err, statErr, info)
		}
	}
	directory, err := os.Stat(destination)
	if err != nil || directory.Mode().Perm() != 0o755 {
		t.Fatalf("the key directory's mode changed: %v %v", directory, err)
	}
	if entries, err := os.ReadDir(destination); err != nil || len(entries) != 6 {
		t.Fatalf("staging files left behind: %d %v", len(entries), err)
	}
	// A failed derivation stops before a key without its public half is used.
	if err := writeHostKeys(destination, keys, func(string) ([]byte, error) { return nil, errors.New("no tool") }); err == nil {
		t.Fatal("a missing public half was accepted")
	}
	// A directory others may write, or a symlink, is refused and left alone.
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := writeHostKeys(shared, keys, public); err == nil {
		t.Fatal("a directory others may write was accepted")
	}
	outside, parent := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(parent, "ssh")); err != nil {
		t.Fatal(err)
	}
	if err := writeHostKeys(filepath.Join(parent, "ssh"), keys, public); err == nil {
		t.Fatal("destination symlink was accepted")
	}
	for _, dir := range []string{shared, outside} {
		if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
			t.Fatalf("host keys were written into %s", dir)
		}
	}
}
