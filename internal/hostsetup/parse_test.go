package hostsetup

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

const ubuntuOSRelease = `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=noble
`

func TestParseOSRelease(t *testing.T) {
	o := ParseOSRelease([]byte(ubuntuOSRelease))
	if o.ID() != "ubuntu" || o["VERSION_CODENAME"] != "noble" || o.Pretty() != "Ubuntu 24.04.1 LTS" || o.MajorVersion() != "24" {
		t.Fatalf("parsed %v", o)
	}
	if !o.IsLike("debian") || o.IsLike("fedora") {
		t.Fatal("ID_LIKE not honoured")
	}
	tricky := ParseOSRelease([]byte("# comment\n\nID='rocky'\nNAME=\"Rocky \\\"Linux\\\"\"\nBAD LINE\nX=$(rm -rf /)\nY=\"a\x01b\"\nlower=1\nVERSION_ID=\"9.4\"\n"))
	if tricky.ID() != "rocky" || tricky["NAME"] != `Rocky "Linux"` || tricky.MajorVersion() != "9" {
		t.Fatalf("tricky = %v", tricky)
	}
	for _, k := range []string{"X", "Y", "lower", "BAD LINE"} {
		if _, ok := tricky[k]; ok {
			t.Errorf("%s should have been skipped", k)
		}
	}
}

func FuzzParseOSRelease(f *testing.F) {
	f.Add([]byte(ubuntuOSRelease))
	f.Add([]byte("ID=\"fedora\"\nVERSION_ID=43\n"))
	f.Add([]byte("ID='a\nb'\n"))
	f.Add([]byte("A=\"\\\"\"\nB=\"\\\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		o := ParseOSRelease(data)
		for k, v := range o {
			if !validOSReleaseKey(k) {
				t.Fatalf("bad key %q", k)
			}
			for _, r := range v {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("control character in %s=%q", k, v)
				}
			}
		}
		_ = o.Pretty()
		_ = o.Like()
		_ = o.MajorVersion()
		_, _ = DistroFor(o)
	})
}

func TestParseVersion(t *testing.T) {
	cases := map[string]Version{
		"27.3.1":                                 {27, 3, 1},
		"v2.29.7":                                {2, 29, 7},
		"2.29.7-desktop.1":                       {2, 29, 7},
		"20.10.24+dfsg1":                         {20, 10, 24},
		"Docker version 27.3.1, build ce12230":   {27, 3, 1},
		"Docker Compose version v2.31.0":         {2, 31, 0},
		"28.0.0-rc.1":                            {28, 0, 0},
		"26":                                     {26, 0, 0},
		"docker-compose version 1.29.2, build x": {1, 29, 2},
	}
	for in, want := range cases {
		if got, err := ParseVersion(in); err != nil || got != want {
			t.Errorf("ParseVersion(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "version unknown", "vx.1", "1234567.1.1"} {
		if _, err := ParseVersion(in); err == nil {
			t.Errorf("ParseVersion(%q) accepted", in)
		}
	}
	if !(Version{20, 9, 9}).Less(MinEngine) || (Version{20, 10, 0}).Less(MinEngine) || !(Version{1, 29, 2}).Less(MinCompose) {
		t.Error("Less is wrong")
	}
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"27.3.1", "v2.29.7", "Docker version 27.3.1, build ce12230", "1.2.3.4.5", "v", "+", "9999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseVersion(s)
		if err != nil {
			return
		}
		if v.Major < 0 || v.Minor < 0 || v.Patch < 0 || v.Major > 999999 {
			t.Fatalf("ParseVersion(%q) = %v", s, v)
		}
		again, err := ParseVersion(v.String())
		if err != nil || again != v {
			t.Fatalf("round trip %v -> %v, %v", v, again, err)
		}
	})
}

// testKeyBody returns a v4 public key packet body with random key material.
func testKeyBody(t testing.TB, version byte) []byte {
	b := []byte{version, 0x58, 0xa3, 0x1f, 0xe8, 22}
	m := make([]byte, 40)
	if _, err := rand.Read(m); err != nil {
		t.Fatal(err)
	}
	return append(b, m...)
}

// newPacket frames body as an OpenPGP packet (new format).
func newPacket(tag byte, body []byte) []byte {
	p := []byte{0xc0 | tag}
	switch n := len(body); {
	case n < 192:
		p = append(p, byte(n))
	case n < 8384:
		n -= 192
		p = append(p, byte(n>>8)+192, byte(n))
	default:
		p = append(p, 255, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(p, body...)
}

// oldPacket frames body in the old format with a two-octet length.
func oldPacket(tag byte, body []byte) []byte {
	return append([]byte{0x80 | tag<<2 | 1, byte(len(body) >> 8), byte(len(body))}, body...)
}

func armor(raw []byte, withCRC bool) []byte {
	var b bytes.Buffer
	b.WriteString("-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: test\n\n")
	enc := base64.StdEncoding.EncodeToString(raw)
	for len(enc) > 64 {
		b.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	b.WriteString(enc + "\n")
	if withCRC {
		c := crc24(raw)
		b.WriteString("=" + base64.StdEncoding.EncodeToString([]byte{byte(c >> 16), byte(c >> 8), byte(c)}) + "\n")
	}
	b.WriteString("-----END PGP PUBLIC KEY BLOCK-----\n")
	return b.Bytes()
}

// fingerprintOf computes a v4 fingerprint independently of KeyFingerprint.
func fingerprintOf(body []byte) string {
	h := sha1.New()
	h.Write(append([]byte{0x99, byte(len(body) >> 8), byte(len(body))}, body...))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

func TestKeyFingerprint(t *testing.T) {
	body := testKeyBody(t, 4)
	want := fingerprintOf(body)
	uid := newPacket(13, []byte("Docker Release (CE deb) <docker@docker.com>"))
	sig := newPacket(2, bytes.Repeat([]byte{0x04}, 300))
	sub := newPacket(14, testKeyBody(t, 4))
	good := append(append(append(newPacket(6, body), uid...), sig...), sub...)
	for name, data := range map[string][]byte{
		"crc":        armor(good, true),
		"no crc":     armor(good, false),
		"old format": armor(append(oldPacket(6, body), uid...), true),
		"crlf":       bytes.ReplaceAll(armor(good, true), []byte("\n"), []byte("\r\n")),
	} {
		got, err := KeyFingerprint(data)
		if err != nil || got != want {
			t.Errorf("%s: KeyFingerprint = %q, %v; want %s", name, got, err, want)
		}
	}

	badCRC := armor(good, true)
	i := bytes.Index(badCRC, []byte("\n="))
	badCRC[i+2] ^= 1
	second := append(append([]byte{}, good...), newPacket(6, testKeyBody(t, 4))...)
	for name, data := range map[string][]byte{
		"bad crc":         badCRC,
		"two primaries":   armor(second, true),
		"no primary":      armor(append(uid, sub...), true),
		"v3 key":          armor(newPacket(6, testKeyBody(t, 3)), true),
		"secret packet":   armor(append(append([]byte{}, good...), newPacket(5, []byte{4, 1})...), true),
		"truncated":       armor(good[:len(good)-10], true),
		"partial length":  armor(append([]byte{0xc6, 0xe1}, body...), true),
		"second block":    append(armor(good, true), armor(newPacket(6, testKeyBody(t, 4)), true)...),
		"not armored":     good,
		"empty":           nil,
		"garbage base64":  []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!!\n-----END PGP PUBLIC KEY BLOCK-----\n"),
		"too big":         bytes.Repeat([]byte("A"), maxKeySize+1),
		"indeterminate":   armor(append([]byte{0x80 | 6<<2 | 3}, body...), true),
		"length overflow": armor([]byte{0xc6, 0xff, 0xff, 0xff, 0xff, 0xff, 4}, true),
	} {
		if got, err := KeyFingerprint(data); err == nil {
			t.Errorf("%s: accepted with fingerprint %s", name, got)
		}
	}
	if FormatFingerprint(DockerDebKeyFingerprint) != "9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88" ||
		FormatFingerprint(compactFingerprint(DockerRPMKeyFingerprint)) != DockerRPMKeyFingerprint {
		t.Error("FormatFingerprint")
	}
	// The published fingerprints are v4 (SHA-1): 40 hex digits.
	for _, fpr := range []string{DockerDebKeyFingerprint, DockerRPMKeyFingerprint} {
		c := compactFingerprint(fpr)
		if len(c) != 40 || strings.Trim(c, "0123456789ABCDEF") != "" {
			t.Errorf("fingerprint %q is not 40 hex digits", fpr)
		}
	}
}

// The armor must start the file and its BEGIN and END lines must be whole
// lines: bytes outside the checked block could be read by apt, gpg or rpm as
// another key that the fingerprint check never saw.
func TestKeyArmorIsAnchored(t *testing.T) {
	body := testKeyBody(t, 4)
	want := fingerprintOf(body)
	uid := newPacket(13, []byte("Docker Release (CE deb) <docker@docker.com>"))
	good := append(newPacket(6, body), uid...)
	other := append(newPacket(6, testKeyBody(t, 4)), newPacket(13, []byte("someone else"))...)
	endGlued := bytes.Replace(armor(good, true), []byte("\n-----END"), []byte("-----END"), 1)
	beginGlued := bytes.Replace(armor(good, true), []byte("-----\nComment"), []byte("-----Comment"), 1)
	for name, data := range map[string][]byte{
		"text before the armor":            append([]byte("junk\n"), armor(good, true)...),
		"binary key before the armor":      append(append(append([]byte{}, other...), '\n'), armor(good, true)...),
		"BEGIN not at the start of a line": append([]byte("x "), armor(good, true)...),
		"END not at the start of a line":   endGlued,
		"text after BEGIN on its line":     beginGlued,
		"text after the armor":             append(armor(good, true), []byte("junk")...),
		"binary key after the armor":       append(armor(good, true), other...),
		"two blocks":                       append(armor(good, true), armor(other, true)...),
		"two keys in one block":            armor(append(append([]byte{}, good...), other...), true),
		"subkey before the primary key":    armor(append(newPacket(14, testKeyBody(t, 4)), good...), true),
		"user ID before the primary key":   armor(append(append([]byte{}, uid...), newPacket(6, body)...), true),
		"trailing bytes in the block":      armor(append(append([]byte{}, good...), 0x00), true),
	} {
		if got, err := KeyFingerprint(data); err == nil {
			t.Errorf("%s: accepted with fingerprint %s", name, got)
		}
	}
	// Leading blank lines are fine.
	if got, err := KeyFingerprint(append([]byte("\n  \n"), armor(good, true)...)); err != nil || got != want {
		t.Errorf("leading whitespace: %s %v", got, err)
	}
}

// CanonicalKey re-armors exactly the checked packets in one fixed layout.
func TestCanonicalKey(t *testing.T) {
	body := testKeyBody(t, 4)
	good := append(append(newPacket(6, body), newPacket(13, []byte("Docker Release"))...),
		newPacket(2, bytes.Repeat([]byte{0x04}, 150))...)
	sent := bytes.ReplaceAll(armor(good, false), []byte("\n"), []byte("\r\n")) // CRLF, a header, no checksum
	fpr, canonical, err := CanonicalKey(append([]byte("\n\n"), sent...))
	if err != nil || fpr != fingerprintOf(body) {
		t.Fatalf("CanonicalKey: %s %v", fpr, err)
	}
	if !bytes.HasPrefix(canonical, []byte(armorBegin+"\n\n")) || !bytes.HasSuffix(canonical, []byte("\n"+armorEnd+"\n")) ||
		bytes.Contains(canonical, []byte("\r")) || bytes.Contains(canonical, []byte("Comment")) || !bytes.Contains(canonical, []byte("\n=")) {
		t.Fatalf("not canonical:\n%s", canonical)
	}
	for _, l := range strings.Split(string(canonical), "\n") {
		if len(l) > 64 {
			t.Fatalf("line longer than 64 characters: %q", l)
		}
	}
	raw, err := dearmor(canonical)
	if err != nil || !bytes.Equal(raw, good) {
		t.Fatal("the canonical form holds other packets than the checked ones")
	}
	// It is a fixed point.
	if _, again, err := CanonicalKey(canonical); err != nil || !bytes.Equal(again, canonical) {
		t.Fatalf("canonical form changes when checked again: %v", err)
	}
}

func FuzzKeyFingerprint(f *testing.F) {
	body := testKeyBody(f, 4)
	good := append(newPacket(6, body), newPacket(13, []byte("x"))...)
	other := append(newPacket(6, testKeyBody(f, 4)), newPacket(13, []byte("y"))...)
	f.Add(armor(good, true))
	f.Add(armor(oldPacket(6, body), false))
	f.Add([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----"))
	f.Add(append([]byte("junk\n"), armor(good, true)...))                                // text before the armor
	f.Add(append(append(append([]byte{}, other...), '\n'), armor(good, true)...))        // binary key before it
	f.Add(armor(append(append([]byte{}, good...), other...), true))                      // two keys in one block
	f.Add(append(armor(good, true), armor(other, true)...))                              // two blocks
	f.Add(append(armor(good, true), other...))                                           // data after the armor
	f.Add(bytes.Replace(armor(good, true), []byte("\n="), []byte("\n=A"), 1))            // checksum mismatch
	f.Add(bytes.Replace(armor(good, true), []byte("\n-----END"), []byte("-----END"), 1)) // END inside a line
	f.Add(armor(append(newPacket(14, testKeyBody(f, 4)), good...), true))                // subkey first
	f.Add(bytes.ReplaceAll(armor(good, true), []byte("\n"), []byte("\r\n")))             // CRLF
	f.Fuzz(func(t *testing.T, data []byte) {
		got, canonical, err := CanonicalKey(data)
		if err != nil {
			if fpr, ferr := KeyFingerprint(data); ferr == nil {
				t.Fatalf("KeyFingerprint accepted what CanonicalKey refused (%s)", fpr)
			}
			return
		}
		if len(got) != 40 || strings.ToUpper(got) != got {
			t.Fatalf("fingerprint %q", got)
		}
		if _, err := hex.DecodeString(got); err != nil {
			t.Fatalf("fingerprint %q is not hex", got)
		}
		// Only blank lines may come before the armor. The BEGIN line itself
		// may end in blanks: RFC 4880 6.2 lets armor lines carry trailing
		// whitespace, which readers ignore.
		norm := strings.TrimLeft(strings.ReplaceAll(string(data), "\r\n", "\n"), " \t\n")
		if first, _, ok := strings.Cut(norm, "\n"); !ok || strings.TrimRight(first, " \t") != armorBegin {
			t.Fatalf("accepted with bytes before the BEGIN line: %q", data)
		}
		// What gets installed is clean armor whatever the input's blanks.
		if !bytes.HasPrefix(canonical, []byte(armorBegin+"\n\n")) || !bytes.HasSuffix(canonical, []byte("\n"+armorEnd+"\n")) {
			t.Fatalf("canonical form is not clean armor: %q", canonical)
		}
		// The installed form holds the same packets and checks the same.
		raw, err := dearmor(data)
		if err != nil {
			t.Fatal(err)
		}
		craw, err := dearmor(canonical)
		if err != nil || !bytes.Equal(raw, craw) {
			t.Fatalf("canonical form holds other packets: %v", err)
		}
		if again, _, err := CanonicalKey(canonical); err != nil || again != got {
			t.Fatalf("canonical form checks as %s %v, want %s", again, err, got)
		}
		// Exactly one primary key, first.
		primaries := 0
		for rest, first := raw, true; len(rest) > 0; first = false {
			tag, _, next, err := nextPacket(rest)
			if err != nil {
				t.Fatal(err)
			}
			if tag == 6 {
				primaries++
			} else if first {
				t.Fatalf("first packet is tag %d", tag)
			}
			rest = next
		}
		if primaries != 1 {
			t.Fatalf("%d primary keys accepted", primaries)
		}
	})
}

func TestParseAptPolicy(t *testing.T) {
	out := `docker-compose-v2:
  Installed: (none)
  Candidate: 2.24.6+ds1-0ubuntu1~22.04.1
  Version table:
docker-compose-plugin:
  Installed: (none)
  Candidate: (none)
docker-compose:
  Installed: (none)
  Candidate: 1.29.2-1
`
	p := ParseAptPolicy(out)
	if p["docker-compose-v2"] != "2.24.6+ds1-0ubuntu1~22.04.1" || p["docker-compose-plugin"] != "" || p["docker-compose"] != "1.29.2-1" {
		t.Fatalf("policy = %v", p)
	}
	if PickComposePackage(p) != "docker-compose-v2" {
		t.Fatal("should pick docker-compose-v2")
	}
	if got := PickComposePackage(map[string]string{"docker-compose": "1.29.2-1"}); got != "" {
		t.Fatalf("v1 picked: %q", got)
	}
	if got := PickComposePackage(map[string]string{"docker-compose": "1:2.26.1-4"}); got != "docker-compose" {
		t.Fatalf("Debian 13's v2 docker-compose not picked: %q", got)
	}
}

func FuzzParseAptPolicy(f *testing.F) {
	f.Add("docker-compose-v2:\n  Candidate: 2.24.6\n")
	f.Add("x:\n  Candidate: (none)\n:\n  Candidate: 1\n")
	f.Fuzz(func(t *testing.T, s string) {
		p := ParseAptPolicy(s)
		pick := PickComposePackage(p)
		if pick != "" && p[pick] == "" {
			t.Fatalf("picked %q without a candidate", pick)
		}
		for k := range p {
			if k == "" || strings.ContainsAny(k, " \t\n") {
				t.Fatalf("bad package name %q", k)
			}
		}
	})
}
