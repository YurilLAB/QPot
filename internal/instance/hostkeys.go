package instance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// ensureSSHHostKeys makes sure dir holds the HiFi backend pool's SSH host keys
// (ed25519, rsa, ecdsa, OpenSSH format). They are generated here, on the
// trusted host, so the shared key directory can be mounted READ-ONLY into the
// backends: with root on one backend an attacker could otherwise replace or
// steal the key every backend presents. Existing keys are kept, so the pool's
// fingerprint never changes.
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
	return nil
}
