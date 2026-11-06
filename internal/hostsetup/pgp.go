package hostsetup

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- OpenPGP v4 fingerprints are defined as SHA-1; this only identifies the key.
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// Docker's release signing keys, as published on
// https://docs.docker.com/engine/install/ (checked 2026-11-07: the key
// files under download.docker.com/linux/{ubuntu,debian,raspbian} carry the
// first, those under {fedora,centos,rhel} the second). Written in groups of
// four as Docker publishes them; compactFingerprint removes the spaces.
const (
	DockerDebKeyFingerprint = "9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88"
	DockerRPMKeyFingerprint = "060A 61C5 1B55 8A7F 742B 77AA C52F EB6B 621E 9F35"
)

// compactFingerprint returns a fingerprint as KeyFingerprint does: upper-case
// hex without spaces.
func compactFingerprint(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, " ", ""))
}

// maxKeySize bounds a downloaded key file (Docker's are under 4 KiB).
const maxKeySize = 64 << 10

var errKey = errors.New("not a single OpenPGP public key")

// The armor lines of a public key block (RFC 4880 6.2).
const (
	armorBegin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	armorEnd   = "-----END PGP PUBLIC KEY BLOCK-----"
)

// KeyFingerprint returns the upper-case hex v4 fingerprint of the one
// primary public key in an ASCII-armored OpenPGP public key block. It
// rejects anything else: bytes around the armor, no armor, a bad checksum,
// a second primary key (which apt or rpm would also trust), packets before
// the primary key or that do not belong in a public key file, or a key
// version other than 4.
func KeyFingerprint(armored []byte) (string, error) {
	fpr, _, err := CanonicalKey(armored)
	return fpr, err
}

// CanonicalKey checks a key block as KeyFingerprint does and also returns it
// re-armored from exactly the packets it checked (no armor headers, LF line
// ends, a checksum). Setup installs this, never the downloaded bytes, so apt,
// gpg and rpm only ever see the key whose fingerprint was checked.
func CanonicalKey(armored []byte) (string, []byte, error) {
	if len(armored) > maxKeySize {
		return "", nil, errKey
	}
	raw, err := dearmor(armored)
	if err != nil {
		return "", nil, err
	}
	var fpr string
	primaries := 0
	for rest := raw; len(rest) > 0; {
		tag, body, next, err := nextPacket(rest)
		if err != nil {
			return "", nil, err
		}
		// The primary key comes first: a subkey, user ID or signature in
		// front of it belongs to no key that was checked.
		if len(rest) == len(raw) && tag != 6 {
			return "", nil, errKey
		}
		rest = next
		switch tag {
		case 6: // public key
			primaries++
			if len(body) < 1 || body[0] != 4 || len(body) > 0xffff {
				return "", nil, errKey
			}
			h := sha1.New() // #nosec G401 -- v4 fingerprint definition (RFC 4880 12.2)
			h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
			h.Write(body)
			fpr = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
		case 2, 12, 13, 14, 17: // signature, trust, user ID, public subkey, user attribute
		default:
			return "", nil, errKey
		}
	}
	if primaries != 1 {
		return "", nil, errKey
	}
	return fpr, armorKey(raw), nil
}

// armorKey writes packets as a public key block in one fixed layout.
func armorKey(raw []byte) []byte {
	var b strings.Builder
	b.WriteString(armorBegin + "\n\n")
	enc := base64.StdEncoding.EncodeToString(raw)
	for len(enc) > 64 {
		b.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	b.WriteString(enc + "\n")
	c := crc24(raw)
	b.WriteString("=" + base64.StdEncoding.EncodeToString([]byte{byte(c >> 16), byte(c >> 8), byte(c)}) + "\n")
	b.WriteString(armorEnd + "\n")
	return []byte(b.String())
}

// dearmor decodes an ASCII-armored public key block and checks its CRC-24
// when one is present. The block must be the whole file: only blank lines
// may come before its BEGIN line and after its END line, and both must be
// whole lines. A tool reading the file could otherwise take bytes outside
// the checked block (another key, in text or binary) for the key.
func dearmor(data []byte) ([]byte, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimLeft(text, " \t\n")
	first, rest, ok := strings.Cut(text, "\n")
	if !ok || strings.TrimRight(first, " \t") != armorBegin {
		return nil, errKey
	}
	body, after, ok := strings.Cut(rest, "\n"+armorEnd)
	if !ok {
		return nil, errKey
	}
	// Nothing but whitespace may follow: a second block would be a second key.
	if strings.TrimSpace(after) != "" {
		return nil, errKey
	}
	lines := strings.Split(body, "\n")
	// Armor headers ("Comment: ...") run up to the first blank line.
	k := 0
	for k < len(lines) && strings.TrimSpace(lines[k]) == "" {
		k++
	}
	if k < len(lines) && strings.Contains(lines[k], ": ") {
		for k < len(lines) && strings.TrimSpace(lines[k]) != "" {
			k++
		}
	}
	var b64 strings.Builder
	var crc string
	for _, l := range lines[k:] {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case strings.HasPrefix(l, "="):
			if crc != "" {
				return nil, errKey
			}
			crc = l[1:]
		default:
			if crc != "" { // data after the checksum line
				return nil, errKey
			}
			b64.WriteString(l)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil || len(raw) == 0 {
		return nil, errKey
	}
	if crc != "" {
		want, err := base64.StdEncoding.DecodeString(crc)
		if err != nil || len(want) != 3 {
			return nil, errKey
		}
		got := crc24(raw)
		if !bytes.Equal(want, []byte{byte(got >> 16), byte(got >> 8), byte(got)}) {
			return nil, errKey
		}
	}
	return raw, nil
}

func crc24(data []byte) uint32 {
	crc := uint32(0xB704CE)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864CFB
			}
		}
	}
	return crc & 0xFFFFFF
}

// nextPacket splits one OpenPGP packet off data (RFC 4880 4.2). Indeterminate
// and partial lengths are refused: key files never use them.
func nextPacket(data []byte) (tag int, body, rest []byte, err error) {
	if len(data) < 2 || data[0]&0x80 == 0 {
		return 0, nil, nil, errKey
	}
	var n, hdr int
	if data[0]&0x40 != 0 { // new format
		tag = int(data[0] & 0x3f)
		o1 := int(data[1])
		switch {
		case o1 < 192:
			n, hdr = o1, 2
		case o1 < 224:
			if len(data) < 3 {
				return 0, nil, nil, errKey
			}
			n, hdr = (o1-192)<<8+int(data[2])+192, 3
		case o1 == 255:
			if len(data) < 6 {
				return 0, nil, nil, errKey
			}
			n, hdr = int(binary.BigEndian.Uint32(data[2:6])), 6
		default:
			return 0, nil, nil, errKey
		}
	} else { // old format
		tag = int(data[0]>>2) & 0x0f
		switch data[0] & 3 {
		case 0:
			n, hdr = int(data[1]), 2
		case 1:
			if len(data) < 3 {
				return 0, nil, nil, errKey
			}
			n, hdr = int(binary.BigEndian.Uint16(data[1:3])), 3
		case 2:
			if len(data) < 5 {
				return 0, nil, nil, errKey
			}
			n, hdr = int(binary.BigEndian.Uint32(data[1:5])), 5
		default:
			return 0, nil, nil, errKey
		}
	}
	if n < 0 || n > len(data)-hdr {
		return 0, nil, nil, errKey
	}
	return tag, data[hdr : hdr+n], data[hdr+n:], nil
}

// FormatFingerprint groups a fingerprint in fours, as Docker's docs show it.
func FormatFingerprint(fpr string) string {
	fpr = compactFingerprint(fpr)
	var parts []string
	for i := 0; i < len(fpr); i += 4 {
		end := i + 4
		if end > len(fpr) {
			end = len(fpr)
		}
		parts = append(parts, fpr[i:end])
	}
	return strings.Join(parts, " ")
}
