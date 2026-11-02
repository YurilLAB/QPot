package instance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"golang.org/x/crypto/ssh"
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
		if st.Mode().Perm() != 0o600 {
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
	// A second run keeps the existing keys (stable fingerprint).
	if err := ensureSSHHostKeys(dir); err != nil {
		t.Fatal(err)
	}
	for kt, fp := range fps {
		data, _ := os.ReadFile(filepath.Join(dir, "ssh_host_"+kt+"_key"))
		s, _ := ssh.ParsePrivateKey(data)
		if ssh.FingerprintSHA256(s.PublicKey()) != fp {
			t.Errorf("%s: host key changed on re-run", kt)
		}
	}
}

// The backends get the shared host keys read-only.
func TestComposeHostKeysReadOnly(t *testing.T) {
	cfg := config.Default("hostkey-ro")
	cfg.QPotID = "qp_hostkeyro000000000000001"
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.Enabled = true
	cfg.Honeypots[sshProxyHoneypot] = hp
	blk := serviceBlock(renderComposeCfg(t, cfg), "ssh-backend-1")
	if !strings.Contains(blk, "/shared-hostkeys:/etc/ssh/keys:ro\n") {
		t.Fatalf("shared host keys not mounted read-only:\n%s", blk)
	}
}
