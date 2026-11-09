package sshbackend

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func FuzzParseAccounts(f *testing.F) {
	for _, value := range []string{"", "root:pass", "user:a:b", "same:a,same:b", "user:unicode-π", "bad\nuser:pass", "user:a\x00b", strings.Repeat("a", 32) + ":x"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		accounts, err := ParseAccounts(value)
		if err != nil {
			return
		}
		if len(accounts) < 1 || len(accounts) > 32 {
			t.Fatalf("unbounded accepted account count: %d", len(accounts))
		}
		names := map[string]bool{}
		var serialized []string
		for _, account := range accounts {
			if account.Name == "" || len(account.Name) > 32 || strings.ContainsAny(account.Name, ":,\r\n\x00/") || names[account.Name] {
				t.Fatalf("invalid accepted account: %#v", account)
			}
			if account.Password == "" || len(account.Password) > 128 || strings.ContainsAny(account.Password, ":,\r\n\x00") {
				t.Fatalf("invalid accepted password")
			}
			names[account.Name] = true
			serialized = append(serialized, account.Name+":"+account.Password)
		}
		again, err := ParseAccounts(strings.Join(serialized, ","))
		if err != nil || !reflect.DeepEqual(accounts, again) {
			t.Fatalf("accepted account configuration changed on roundtrip: %v", err)
		}
	})
}

func FuzzBootstrapEnvironment(f *testing.F) {
	for _, value := range []string{"BACKEND_USERS=secret\nPATH=/bin", "backend_scene=secret\nLANG=C", "http_proxy=http://local\nUSER=test", "SHELL=/bin/bash\nLC_ALL=C", ""} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 32768 {
			return
		}
		original := strings.Split(value, "\n")
		filtered := FilterEnvironment(original)
		pos := 0
		for _, entry := range filtered {
			name, _, _ := strings.Cut(entry, "=")
			switch strings.ToUpper(name) {
			case "BACKEND_SCENE", "BACKEND_USERS", "BACKEND_HOST_KEYS", "SESSION_CONTAINER", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS", "DOCKER_TLS_VERIFY":
				t.Fatalf("bootstrap field survived filter: %s", name)
			}
			for pos < len(original) && original[pos] != entry {
				pos++
			}
			if pos == len(original) {
				t.Fatal("filter changed an unrelated environment entry")
			}
			pos++
		}
		if !reflect.DeepEqual(filtered, FilterEnvironment(filtered)) {
			t.Fatal("environment filter is not idempotent")
		}
		if !bytes.Equal([]byte(strings.Join(original, "\n")), []byte(value)) {
			t.Fatal("filter mutated its input")
		}
	})
}
