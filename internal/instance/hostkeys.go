package instance

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/qpot/qpot/internal/sshbackend"
	"golang.org/x/crypto/ssh"
)

// hostKeysEnvFile is the Compose env_file beside the keys. It hands them to
// each backend at start, so no host folder is mounted into a guest (a mount
// shows its host path in the guest's mount table).
const hostKeysEnvFile = "host-keys.env"

// ensureSSHHostKeys makes sure dir holds the HiFi backend pool's SSH host keys
// (ed25519, rsa, ecdsa, OpenSSH format) and the env_file that carries them.
// They are generated here, on the trusted host, and every backend start gets
// a fresh copy: root on one backend can read its copy, as on any server, but
// never change the key the others present. Existing keys are kept, so the
// pool's fingerprint never changes.
func ensureSSHHostKeys(dir string) error {
	gens := map[string]func() (crypto.Signer, error){
		"ed25519": func() (crypto.Signer, error) { _, k, err := ed25519.GenerateKey(rand.Reader); return k, err },
		"rsa":     func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 3072) },
		"ecdsa":   func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
	}
	for kt, gen := range gens {
		priv := filepath.Join(dir, "ssh_host_"+kt+"_key")
		if _, err := os.Stat(priv); err == nil {
			continue
		}
		key, err := gen()
		if err != nil {
			return fmt.Errorf("generate %s host key: %w", kt, err)
		}
		block, err := ssh.MarshalPrivateKey(key, "")
		if err != nil {
			return fmt.Errorf("encode %s host key: %w", kt, err)
		}
		pub, err := ssh.NewPublicKey(key.Public())
		if err != nil {
			return fmt.Errorf("encode %s public key: %w", kt, err)
		}
		if err := os.WriteFile(priv, pem.EncodeToMemory(block), 0o600); err != nil {
			return err
		}
		// #nosec G306 -- a public key is meant to be world-readable.
		if err := os.WriteFile(priv+".pub", ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
			return err
		}
	}
	return writeHostKeysEnv(dir)
}

// writeHostKeysEnv writes the env_file from the keys in dir, privately and
// atomically; an unchanged file is left alone.
func writeHostKeysEnv(dir string) error {
	var parts []string
	for _, kind := range []string{"rsa", "ecdsa", "ed25519"} {
		data, err := os.ReadFile(filepath.Join(dir, "ssh_host_"+kind+"_key"))
		if err != nil {
			return fmt.Errorf("read %s host key: %w", kind, err)
		}
		parts = append(parts, kind+":"+base64.StdEncoding.EncodeToString(data))
	}
	content := []byte(sshbackend.HostKeysVariable + "=" + strings.Join(parts, ",") + "\n")
	name := filepath.Join(dir, hostKeysEnvFile)
	if existing, err := os.ReadFile(name); err == nil && bytes.Equal(existing, content) {
		return nil
	}
	tmp, err := os.CreateTemp(dir, ".host-keys-*.env")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(content)
	if werr == nil {
		werr = tmp.Chmod(0o600)
	}
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), name)
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write the backend host key environment: %w", werr)
	}
	return nil
}

// sshHostKeysEnvFile is the env_file path for a host key directory.
func sshHostKeysEnvFile(keyDir string) string {
	return filepath.Join(keyDir, hostKeysEnvFile)
}
