package canary

// derive.go: the values of the canaries QPot plants in its own honeypots.
//
// They are derived, not minted: every value comes from an HMAC-SHA256 stream
// keyed with a per-instance seed, so a regenerated compose (and a restarted
// server) plants and watches exactly the same values, while two instances
// never share one. The seed is the instance's deception seed, itself a one-way
// hash of the instance ID; nothing an attacker sees can lead back to the ID.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // OpenSSH's legacy fingerprint format, not a security use
	"crypto/sha1" //nolint:gosec // HashKnownHosts is HMAC-SHA1 in OpenSSH
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// Deriver derives stable pseudo-random values from a seed. The zero value is
// not usable; build one with NewDeriver.
type Deriver struct {
	key [32]byte
}

// NewDeriver returns the Deriver of seed. Different seeds give unrelated
// streams; the same seed always gives the same values.
func NewDeriver(seed string) Deriver {
	return Deriver{key: sha256.Sum256([]byte("qpot-canary-derive-v1\x00" + seed))}
}

// Sub returns a Deriver for a part of the derivation (one honeypot, one file),
// so adding values to one part never moves the values of another.
func (d Deriver) Sub(label string) Deriver {
	return Deriver{key: [32]byte(d.block("sub\x00"+label, 0))}
}

// block is HMAC-SHA256(key, label || 0x00 || counter).
func (d Deriver) block(label string, counter uint32) []byte {
	m := hmac.New(sha256.New, d.key[:])
	m.Write([]byte(label))
	var c [5]byte
	binary.BigEndian.PutUint32(c[1:], counter)
	m.Write(c[:])
	return m.Sum(nil)
}

// Bytes returns n bytes of the stream named label.
func (d Deriver) Bytes(label string, n int) []byte {
	out := make([]byte, 0, n+32)
	for i := uint32(0); len(out) < n; i++ {
		out = append(out, d.block(label, i)...)
	}
	return out[:n]
}

// reader hands out the bytes of one stream in order.
type reader struct {
	d     Deriver
	label string
	n     uint32
	buf   []byte
}

func (r *reader) byte() byte {
	if len(r.buf) == 0 {
		r.buf = r.d.block(r.label, r.n)
		r.n++
	}
	b := r.buf[0]
	r.buf = r.buf[1:]
	return b
}

// uint32 returns a uniform value of the stream.
func (r *reader) uint32() uint32 {
	return uint32(r.byte())<<24 | uint32(r.byte())<<16 | uint32(r.byte())<<8 | uint32(r.byte())
}

// intn returns a uniform value in [0, n) by rejection, without modulo bias.
func (r *reader) intn(n int) int {
	if n <= 1 {
		return 0
	}
	limit := ^uint32(0) - ^uint32(0)%uint32(n)
	for {
		v := r.uint32()
		if v < limit {
			return int(v % uint32(n))
		}
	}
}

// Intn returns a value in [0, n) of the stream named label; 0 when n <= 1.
func (d Deriver) Intn(label string, n int) int {
	r := &reader{d: d, label: label}
	return r.intn(n)
}

// Stream is a sequence of derived values: each call takes the next ones. It
// serves long runs of choices (the rows of a table) from one label.
type Stream struct{ r reader }

// Stream returns the stream named label.
func (d Deriver) Stream(label string) *Stream {
	return &Stream{r: reader{d: d, label: label}}
}

// Intn returns the next value in [0, n); 0 when n <= 1.
func (s *Stream) Intn(n int) int { return s.r.intn(n) }

// Chars returns the next n characters of charset.
func (s *Stream) Chars(n int, charset string) string {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		b.WriteByte(charset[s.r.intn(len(charset))])
	}
	return b.String()
}

// Float returns a value in [0, 1) of the stream named label.
func (d Deriver) Float(label string) float64 {
	b := d.Bytes(label, 8)
	return float64(binary.BigEndian.Uint64(b)>>11) / (1 << 53)
}

// Pick returns one element of pool, chosen by the stream named label.
func Pick[T any](d Deriver, label string, pool []T) T {
	return pool[d.Intn(label, len(pool))]
}

// Chars returns n characters of charset drawn uniformly by the stream named
// label.
func (d Deriver) Chars(label string, n int, charset string) string {
	r := &reader{d: d, label: label}
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		b.WriteByte(charset[r.intn(len(charset))])
	}
	return b.String()
}

const (
	charsUpper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsLower  = "abcdefghijklmnopqrstuvwxyz"
	charsDigits = "0123456789"
	charsAlnum  = charsUpper + charsLower + charsDigits
	charsBase64 = charsAlnum + "+/"
)

// AWSKeyPair derives an access key id (see awsKeyID) and a 40 character
// secret, the shapes of a long-term IAM user key.
func (d Deriver) AWSKeyPair(label string) (id, secret string) {
	r := &reader{d: d, label: label + "/id"}
	return awsKeyID(r.byte), d.Chars(label+"/secret", 40, charsBase64)
}

// Secret derives a machine-generated password: what `openssl rand -base64 n`
// prints (4*ceil(n/3) characters, no padding for n divisible by 3). It never
// holds a quote, a backslash or a space, so it can sit in shell and SQL
// quotes as is.
func (d Deriver) Secret(label string, n int) string {
	return base64.StdEncoding.EncodeToString(d.Bytes(label, n))
}

// AlnumSecret derives an n character password of letters and digits (pwgen -s).
func (d Deriver) AlnumSecret(label string, n int) string {
	return d.Chars(label, n, charsAlnum)
}

// passwordWords are the words of human passwords: two of them, digits and one
// symbol are long enough that no brute-force list holds the result, so a login
// with it can only come from someone who read it.
var passwordWords = []string{
	"Amber", "Anchor", "Aspen", "Badger", "Basil", "Beacon", "Birch", "Bison", "Blaze", "Breeze",
	"Bronze", "Cactus", "Canyon", "Cedar", "Cobalt", "Comet", "Copper", "Coral", "Cricket", "Crimson",
	"Dakota", "Delta", "Ember", "Falcon", "Fennel", "Fjord", "Gable", "Garnet", "Glacier", "Granite",
	"Harbor", "Hazel", "Heron", "Indigo", "Jasper", "Juniper", "Kestrel", "Lagoon", "Lantern", "Laurel",
	"Lynx", "Maple", "Marble", "Meadow", "Merlin", "Mosaic", "Nectar", "Nimbus", "Nova", "Oasis",
	"Onyx", "Orchid", "Osprey", "Otter", "Pebble", "Pepper", "Pine", "Pixel", "Prairie", "Quartz",
	"Raven", "Ridge", "River", "Rocket", "Saffron", "Sable", "Sequoia", "Sierra", "Silver", "Sparrow",
	"Spruce", "Summit", "Tango", "Thistle", "Thunder", "Timber", "Topaz", "Tundra", "Velvet", "Walnut",
	"Willow", "Winter", "Zephyr", "Zinnia",
}

// HumanPassword derives a password as a person makes one up: two words, two to
// four digits and a symbol.
func (d Deriver) HumanPassword(label string) string {
	r := &reader{d: d, label: label}
	a := passwordWords[r.intn(len(passwordWords))]
	b := passwordWords[r.intn(len(passwordWords))]
	for b == a {
		b = passwordWords[r.intn(len(passwordWords))]
	}
	// two to four digits, more where short words would leave it below 13
	// characters (MinWatchLen and one to spare)
	digits := max(2+r.intn(3), 13-len(a)-len(b)-1)
	var num strings.Builder
	for i := 0; i < digits; i++ {
		num.WriteByte(charsDigits[r.intn(10)])
	}
	sym := string("!#%*+-.@_"[r.intn(9)])
	switch r.intn(3) {
	case 0:
		return a + b + num.String() + sym
	case 1:
		return a + sym + b + num.String()
	default:
		return strings.ToLower(a) + "." + b + num.String() + sym
	}
}

// GitLabToken derives a GitLab personal access token: glpat- and 20 of
// [A-Za-z0-9_-], the format GitLab issued before its 2025 routable tokens.
func (d Deriver) GitLabToken(label string) string {
	return "glpat-" + d.Chars(label, 20, charsAlnum+"_-")
}

// BeaconToken derives a beacon token of the shape mintToken gives.
func (d Deriver) BeaconToken(label string) string {
	return strings.ToLower(b32.EncodeToString(d.Bytes(label, 20)))
}

// ID derives a canary ID (cnry_ and 24 hex digits).
func (d Deriver) ID(label string) string {
	return "cnry_" + hex.EncodeToString(d.Bytes("id\x00"+label, 12))
}

// Ed25519Key derives an Ed25519 key pair.
func (d Deriver) Ed25519Key(label string) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(d.Bytes(label, ed25519.SeedSize))
}

// sshString appends an SSH wire-format string (uint32 length, bytes).
func sshString(b []byte, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// Ed25519PublicBlob is the SSH wire encoding of an Ed25519 public key.
func Ed25519PublicBlob(pub ed25519.PublicKey) []byte {
	return sshString(sshString(nil, []byte("ssh-ed25519")), pub)
}

// AuthorizedKey is the authorized_keys / .pub line of a public key blob:
// "<type> <base64 blob>" and the comment, when there is one.
func AuthorizedKey(blob []byte, comment string) string {
	typ := string(blob[4 : 4+binary.BigEndian.Uint32(blob)])
	line := typ + " " + base64.StdEncoding.EncodeToString(blob)
	if comment != "" {
		line += " " + comment
	}
	return line
}

// MD5Fingerprint is the colon-separated MD5 fingerprint of a public key blob,
// the form Cowrie logs for a public key login.
func MD5Fingerprint(blob []byte) string {
	sum := md5.Sum(blob) //nolint:gosec // see the import
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = hex.EncodeToString([]byte{b})
	}
	return strings.Join(parts, ":")
}

// SHA256Fingerprint is the SHA256: fingerprint OpenSSH prints for a key blob.
func SHA256Fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// MarshalEd25519PrivateKey encodes key in OpenSSH's private key format, the
// file ssh-keygen writes without a passphrase. OpenSSH fills the two check
// words with random bytes; here they come from check, so the same key always
// gives the same file.
func MarshalEd25519PrivateKey(key ed25519.PrivateKey, comment string, check uint32) []byte {
	pub := key.Public().(ed25519.PublicKey)
	blob := Ed25519PublicBlob(pub)
	var priv []byte
	priv = binary.BigEndian.AppendUint32(priv, check)
	priv = binary.BigEndian.AppendUint32(priv, check)
	priv = sshString(priv, []byte("ssh-ed25519"))
	priv = sshString(priv, pub)
	priv = sshString(priv, key) // 64 bytes: the seed, then the public key
	priv = sshString(priv, []byte(comment))
	for i := byte(1); len(priv)%8 != 0; i++ {
		priv = append(priv, i)
	}
	var b []byte
	b = append(b, "openssh-key-v1\x00"...)
	b = sshString(b, []byte("none"))
	b = sshString(b, []byte("none"))
	b = sshString(b, nil)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = sshString(b, blob)
	b = sshString(b, priv)
	enc := base64.StdEncoding.EncodeToString(b)
	var out strings.Builder
	out.WriteString(pemArmor("BEGIN"))
	for len(enc) > 70 {
		out.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	out.WriteString(enc + "\n" + pemArmor("END"))
	return []byte(out.String())
}

// pemArmor is an armor line of an OpenSSH key file. It is put together here
// so the source holds no key block a secret scanner would flag.
func pemArmor(edge string) string {
	return "-----" + edge + " OPENSSH PRIVATE KEY-----\n"
}

// ECDSAP256PublicBlob derives a NIST P-256 public key and returns its SSH wire
// encoding (ecdsa-sha2-nistp256), the second host key type known_hosts lists.
func (d Deriver) ECDSAP256PublicBlob(label string) []byte {
	for i := 0; ; i++ {
		// A scalar of zero or one above the group order is refused; the next
		// one of the stream is taken, as a key generator would draw again.
		key, err := ecdh.P256().NewPrivateKey(d.Bytes(label+"\x00"+string(rune('a'+i)), 32))
		if err != nil {
			continue
		}
		b := sshString(nil, []byte("ecdsa-sha2-nistp256"))
		b = sshString(b, []byte("nistp256"))
		return sshString(b, key.PublicKey().Bytes())
	}
}

// HashKnownHost is the hashed host field ssh writes with HashKnownHosts yes:
// |1|base64(salt)|base64(HMAC-SHA1(salt, host)), salt 20 bytes.
func HashKnownHost(salt []byte, host string) string {
	m := hmac.New(sha1.New, salt)
	m.Write([]byte(host))
	return "|1|" + base64.StdEncoding.EncodeToString(salt) + "|" + base64.StdEncoding.EncodeToString(m.Sum(nil))
}
