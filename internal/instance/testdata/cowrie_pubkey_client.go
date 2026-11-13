// Command cowrie_pubkey_client reports how the local SSH service answers
// public-key authentication: a key offered with a signature another key
// made, and a key offered by the client that holds it. It runs only inside
// the test container's network-none namespace.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// borrowedKey offers one key and signs with another: what a client does
// that knows a public key and does not hold its private half.
type borrowedKey struct {
	offered ssh.PublicKey
	held    ssh.Signer
	signed  int
}

func (b *borrowedKey) PublicKey() ssh.PublicKey { return b.offered }

func (b *borrowedKey) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	b.signed++
	return b.held.Sign(random, data)
}

func newSigner() ssh.Signer {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	signer, err := ssh.NewSignerFromKey(private)
	must(err)
	return signer
}

// attempt logs in as root with one signer and says what came of it.
func attempt(signer ssh.Signer) (client *ssh.Client, failure string) {
	config := &ssh.ClientConfig{
		User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, Timeout: 5 * time.Second,
		HostKeyCallback: func(_ string, remote net.Addr, _ ssh.PublicKey) error {
			host, _, err := net.SplitHostPort(remote.String())
			if err != nil || !net.ParseIP(host).IsLoopback() {
				return fmt.Errorf("test SSH endpoint must be loopback")
			}
			return nil
		},
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", "127.0.0.1:22")
	must(err)
	must(conn.SetDeadline(time.Now().Add(30 * time.Second)))
	c, channels, requests, err := ssh.NewClientConn(conn, "127.0.0.1:22", config)
	if err != nil {
		_ = conn.Close()
		return nil, err.Error()
	}
	return ssh.NewClient(c, channels, requests), ""
}

func main() {
	result := map[string]string{}

	// The key is offered first without a signature (the query). A server
	// answers "acceptable" or refuses; only then does the client sign.
	borrowed := &borrowedKey{offered: newSigner().PublicKey(), held: newSigner()}
	client, failure := attempt(borrowed)
	switch {
	case client != nil:
		_ = client.Close()
		result["wrong_signature"] = "logged in"
	case strings.Contains(failure, "unexpected message type 52"):
		result["wrong_signature"] = "logged in on the query, before any signature"
	case strings.Contains(failure, "unable to authenticate") && borrowed.signed > 0:
		result["wrong_signature"] = "key acceptable, signature refused"
	case strings.Contains(failure, "unable to authenticate"):
		result["wrong_signature"] = "key refused"
	default:
		result["wrong_signature"] = "error: " + failure
	}

	client, failure = attempt(newSigner())
	switch {
	case client != nil:
		session, err := client.NewSession()
		must(err)
		out, err := session.CombinedOutput("whoami")
		must(err)
		_ = session.Close()
		_ = client.Close()
		result["right_signature"] = "logged in as " + strings.TrimSpace(string(out))
	case strings.Contains(failure, "unexpected message type 52"):
		result["right_signature"] = "logged in on the query, before any signature"
	default:
		result["right_signature"] = "error: " + failure
	}

	must(json.NewEncoder(os.Stdout).Encode(result))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
