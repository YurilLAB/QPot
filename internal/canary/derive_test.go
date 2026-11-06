package canary

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// TestDeriverStableAndSeparate: the same seed always derives the same values,
// another seed or another label different ones, and a sub-deriver's values do
// not depend on what else is derived.
func TestDeriverStableAndSeparate(t *testing.T) {
	a, b := NewDeriver("seed-a"), NewDeriver("seed-a")
	if a.Secret("x", 18) != b.Secret("x", 18) || a.HumanPassword("p") != b.HumanPassword("p") {
		t.Fatal("same seed, different values")
	}
	id1, s1 := a.AWSKeyPair("aws")
	id2, s2 := NewDeriver("seed-b").AWSKeyPair("aws")
	if id1 == id2 || s1 == s2 {
		t.Fatal("different seeds, same AWS key")
	}
	if a.Secret("x", 18) == a.Secret("y", 18) {
		t.Fatal("different labels, same value")
	}
	if a.Sub("one").GitLabToken("t") == a.Sub("two").GitLabToken("t") {
		t.Fatal("different subs, same token")
	}
	if a.Sub("one").GitLabToken("t") != NewDeriver("seed-a").Sub("one").GitLabToken("t") {
		t.Fatal("sub not stable")
	}
	st1, st2 := a.Stream("rows"), a.Stream("rows")
	for i := 0; i < 50; i++ {
		if st1.Intn(1000) != st2.Intn(1000) {
			t.Fatal("stream not stable")
		}
	}
}

// TestAWSKeyIDsDecodeToAnAccount: an access key id, derived or minted, reads
// back (as key scanners read it, without asking AWS) as a 12 digit account,
// with a fifth character of the keys AWS issues now; a key that decodes to a
// 13 digit number or starts like a pre-2019 key gives the canary away.
func TestAWSKeyIDsDecodeToAnAccount(t *testing.T) {
	accounts := map[uint64]bool{}
	check := func(what, id string) {
		t.Helper()
		if len(id) != 20 || !strings.HasPrefix(id, "AKIA") || strings.Trim(id[4:], awsKeyCharset) != "" {
			t.Fatalf("%s: access key id %q", what, id)
		}
		if !strings.ContainsRune("QRSTUVWXYZ234567", rune(id[4])) {
			t.Errorf("%s: %q has the fifth character of an old key", what, id)
		}
		acct, ok := AWSAccountOfKey(id)
		if !ok || acct >= 1_000_000_000_000 {
			t.Errorf("%s: %q decodes to account %d, not 12 digits", what, id, acct)
		}
		accounts[acct] = true
	}
	for i := 0; i < 400; i++ {
		id, _ := NewDeriver(fmt.Sprintf("seed-%d", i)).AWSKeyPair("aws")
		check("derived", id)
		check("minted", mintAWSKeyID())
	}
	if len(accounts) < 790 {
		t.Errorf("only %d accounts in 800 keys", len(accounts))
	}
	// the decoding itself, on the example key of AWS's documentation (scanners
	// read it as account 581039954779) and on ids that are none
	if acct, ok := AWSAccountOfKey("AKIAIOSFODNN7EXAMPLE"); !ok || acct != 581039954779 {
		t.Errorf("example key: %d %v", acct, ok)
	}
	for _, bad := range []string{"", "AKIA", "AKIAIOSFODNN7EXAMPL1", "akiaiosfodnn7example", "AROAIOSFODNN7EXAMPLE"} {
		if _, ok := AWSAccountOfKey(bad); ok {
			t.Errorf("%q decoded", bad)
		}
	}
}

// TestDeriverShapes: every derived credential has the shape of the real one
// and is long enough to be watched (MinWatchLen).
func TestDeriverShapes(t *testing.T) {
	for i := 0; i < 200; i++ {
		d := NewDeriver(strings.Repeat("s", i))
		id, secret := d.AWSKeyPair("aws")
		if len(id) != 20 || !strings.HasPrefix(id, "AKIA") || strings.Trim(id[4:], awsKeyCharset) != "" {
			t.Fatalf("access key id %q", id)
		}
		if len(secret) != 40 || strings.Trim(secret, charsBase64) != "" {
			t.Fatalf("secret %q", secret)
		}
		pw := d.Secret("db", 18)
		if len(pw) != 24 || strings.ContainsAny(pw, `'"\ $`) {
			t.Fatalf("secret password %q", pw)
		}
		if raw, err := base64.StdEncoding.DecodeString(pw); err != nil || len(raw) != 18 {
			t.Fatalf("secret password %q is not openssl rand -base64 18", pw)
		}
		human := d.HumanPassword("user")
		if len(human) < MinWatchLen || strings.ContainsAny(human, `'"\ $`) {
			t.Fatalf("human password %q", human)
		}
		gl := d.GitLabToken("git")
		if len(gl) != 26 || !strings.HasPrefix(gl, "glpat-") || strings.Trim(gl[6:], charsAlnum+"_-") != "" {
			t.Fatalf("gitlab token %q", gl)
		}
		tok := d.BeaconToken("ping")
		if len(tok) != 32 || strings.Trim(tok, "abcdefghijklmnopqrstuvwxyz234567") != "" {
			t.Fatalf("beacon token %q", tok)
		}
		if id := d.ID("x"); len(id) != 29 || !strings.HasPrefix(id, "cnry_") {
			t.Fatalf("id %q", id)
		}
		if n := d.Intn("n", 7); n < 0 || n >= 7 {
			t.Fatalf("Intn out of range: %d", n)
		}
		if f := d.Float("f"); f < 0 || f >= 1 {
			t.Fatalf("Float out of range: %v", f)
		}
	}
}

// TestPrivateKeyFileParses: the private key file is one OpenSSH reads, of the
// key it was made from, and the same key always gives the same file.
func TestPrivateKeyFileParses(t *testing.T) {
	d := NewDeriver("key-seed")
	key := d.Ed25519Key("root")
	file := MarshalEd25519PrivateKey(key, "backup@example", 0x01020304)
	if string(file) != string(MarshalEd25519PrivateKey(d.Ed25519Key("root"), "backup@example", 0x01020304)) {
		t.Fatal("private key file not stable")
	}
	parsed, err := ssh.ParseRawPrivateKey(file)
	if err != nil {
		t.Fatalf("ssh cannot read the private key file: %v\n%s", err, file)
	}
	got, ok := parsed.(*ed25519.PrivateKey)
	if !ok || !got.Equal(key) {
		t.Fatalf("parsed key %T differs", parsed)
	}
	lines := strings.Split(strings.TrimSpace(string(file)), "\n")
	for _, l := range lines[1 : len(lines)-1] {
		if len(l) > 70 {
			t.Fatalf("line longer than ssh-keygen writes: %q", l)
		}
	}
	// negative control: a file whose check words disagree is refused
	broken := strings.Split(strings.TrimSpace(string(MarshalEd25519PrivateKey(key, "x", 1))), "\n")
	b, _ := base64.StdEncoding.DecodeString(strings.Join(broken[1:len(broken)-1], ""))
	i := strings.Index(string(b), "\x00\x00\x00\x01\x00\x00\x00\x01") // the two check words
	if i < 0 {
		t.Fatal("check words not found")
	}
	binary.BigEndian.PutUint32(b[i+4:], 2)
	bad := pemArmor("BEGIN") + base64.StdEncoding.EncodeToString(b) + "\n" + pemArmor("END")
	if _, err := ssh.ParseRawPrivateKey([]byte(bad)); err == nil {
		t.Fatal("a file with mismatched check words parsed")
	}
}

// TestPublicKeyFormats: the authorized_keys line parses, and the fingerprints
// are the ones OpenSSH and Cowrie compute.
func TestPublicKeyFormats(t *testing.T) {
	d := NewDeriver("pub-seed")
	pub := d.Ed25519Key("k").Public().(ed25519.PublicKey)
	blob := Ed25519PublicBlob(pub)
	line := AuthorizedKey(blob, "root@box")
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || comment != "root@box" {
		t.Fatalf("authorized key %q: %v %q", line, err, comment)
	}
	if MD5Fingerprint(blob) != ssh.FingerprintLegacyMD5(pk) {
		t.Fatalf("MD5 fingerprint %s, ssh says %s", MD5Fingerprint(blob), ssh.FingerprintLegacyMD5(pk))
	}
	if SHA256Fingerprint(blob) != ssh.FingerprintSHA256(pk) {
		t.Fatalf("SHA256 fingerprint %s, ssh says %s", SHA256Fingerprint(blob), ssh.FingerprintSHA256(pk))
	}
	if AuthorizedKey(blob, "") != strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pk)), "\n") {
		t.Fatal("authorized key without comment differs from ssh's")
	}
	ec := d.ECDSAP256PublicBlob("host")
	epk, err := ssh.ParsePublicKey(ec)
	if err != nil || epk.Type() != ssh.KeyAlgoECDSA256 {
		t.Fatalf("ecdsa blob: %v", err)
	}
}

// TestHashedKnownHost: a hashed known_hosts line is one OpenSSH's known_hosts
// matching accepts for the host it hashes, and only for it.
func TestHashedKnownHost(t *testing.T) {
	d := NewDeriver("kh")
	pk, err := ssh.ParsePublicKey(Ed25519PublicBlob(d.Ed25519Key("host").Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	line := HashKnownHost(d.Bytes("salt", 20), "10.20.30.40") + " " + AuthorizedKey(pk.Marshal(), "") + "\n"
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	check, err := knownhosts.New(path)
	if err != nil {
		t.Fatalf("knownhosts cannot read %q: %v", line, err)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("10.20.30.40"), Port: 22}
	if err := check("10.20.30.40:22", addr, pk); err != nil {
		t.Fatalf("hashed entry does not match its host: %v", err)
	}
	other := &net.TCPAddr{IP: net.ParseIP("10.20.30.41"), Port: 22}
	if err := check("10.20.30.41:22", other, pk); err == nil {
		t.Fatal("hashed entry matched another host")
	}
}
