package instance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/sshbackend"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func TestEnsureSSHHostKeys(t *testing.T) {
	dir := t.TempDir()
	if err := ensureSSHHostKeys(dir); err != nil {
		t.Fatal(err)
	}
	fps := map[string]string{}
	for _, kt := range []string{"ed25519", "rsa", "ecdsa"} {
		p := filepath.Join(dir, "ssh_host_"+kt+"_key")
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		// Windows has no POSIX modes (Go reports a writable file as 0666): the
		// profile folder's ACL keeps the key private there, and the backend
		// reads a 0600 copy of its own, as Docker Desktop shows every file
		// shared from Windows as 0777 (docker/ssh-backend).
		if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, want 0600 (sshd rejects readable private host keys)", kt, st.Mode().Perm())
		}
		data, _ := os.ReadFile(p)
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			t.Fatalf("%s: not a valid OpenSSH private key: %v", kt, err)
		}
		pub, _ := os.ReadFile(p + ".pub")
		if !strings.HasPrefix(string(pub), signer.PublicKey().Type()+" ") {
			t.Errorf("%s: .pub does not match the private key", kt)
		}
		fps[kt] = ssh.FingerprintSHA256(signer.PublicKey())
	}
	// The env_file hands exactly these keys to a backend, privately.
	envFile := filepath.Join(dir, hostKeysEnvFile)
	env, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	name, value, ok := strings.Cut(strings.TrimSuffix(string(env), "\n"), "=")
	parsed, perr := sshbackend.ParseHostKeys(value)
	if !ok || name != sshbackend.HostKeysVariable || perr != nil || len(parsed) != 3 || strings.Count(string(env), "\n") != 1 {
		t.Fatalf("env_file: %v %v", ok, perr)
	}
	for kt, key := range parsed {
		data, _ := os.ReadFile(filepath.Join(dir, "ssh_host_"+kt+"_key"))
		if string(data) != string(key) {
			t.Fatalf("env_file %s key differs from the key file", kt)
		}
	}
	if st, err := os.Stat(envFile); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("env_file is not private: %v %v", st, err)
	}
	before, _ := os.Stat(envFile)
	// A second run keeps the existing keys (stable fingerprint) and file.
	if err := ensureSSHHostKeys(dir); err != nil {
		t.Fatal(err)
	}
	if after, err := os.Stat(envFile); err != nil || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("an unchanged env_file was rewritten: %v", err)
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".host-keys-*")); len(matches) != 0 {
		t.Fatalf("staging files left behind: %v", matches)
	}
	for kt, fp := range fps {
		data, _ := os.ReadFile(filepath.Join(dir, "ssh_host_"+kt+"_key"))
		s, _ := ssh.ParsePrivateKey(data)
		if ssh.FingerprintSHA256(s.PublicKey()) != fp {
			t.Errorf("%s: host key changed on re-run", kt)
		}
	}
}

// The backends get the shared host keys through Compose's env_file, and
// nothing from the host is mounted into them.
func TestComposeHandsHostKeysWithoutMounts(t *testing.T) {
	cfg := config.Default("hostkey-env")
	cfg.QPotID = "qp_hostkeyro000000000000001"
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.Enabled = true
	cfg.Honeypots[sshProxyHoneypot] = hp
	var doc struct {
		Services map[string]struct {
			Volumes []string `yaml:"volumes"`
			EnvFile []string `yaml:"env_file"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(renderComposeCfg(t, cfg)), &doc); err != nil {
		t.Fatal(err)
	}
	keys, err := sshStoreSharedKeys(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range sshBackendServiceNames(cfg) {
		svc := doc.Services[backend]
		if len(svc.Volumes) != 0 || len(svc.EnvFile) != 1 || svc.EnvFile[0] != filepath.Join(keys, hostKeysEnvFile) {
			t.Fatalf("%s: volumes %v, env_file %v; want no mounts and %s", backend, svc.Volumes, svc.EnvFile, filepath.Join(keys, hostKeysEnvFile))
		}
	}
}
