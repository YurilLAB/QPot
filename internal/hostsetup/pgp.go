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

// KeyFingerprint returns the upper-case hex v4 fingerprint of the one
// primary public key in an ASCII-armored OpenPGP public key block. It
// rejects anything else: no armor, a bad checksum, a second primary key
// (which apt or rpm would also trust), packets that do not belong in a public
// key file, or a key version other than 4.
func KeyFingerprint(armored []byte) (string, error) {
	if len(armored) > maxKeySize {
		return "", errKey
	}
	raw, err := dearmor(armored)
	if err != nil {
		return "", err
	}
	var fpr string
	primaries := 0
	for len(raw) > 0 {
		tag, body, rest, err := nextPacket(raw)
		if err != nil {
			return "", err
		}
		raw = rest
		switch tag {
		case 6: // public key
			primaries++
			if len(body) < 1 || body[0] != 4 || len(body) > 0xffff {
				return "", errKey
			}
			h := sha1.New() // #nosec G401 -- v4 fingerprint definition (RFC 4880 12.2)
			h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
			h.Write(body)
			fpr = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
		case 2, 12, 13, 14, 17: // signature, trust, user ID, public subkey, user attribute
		default:
			return "", errKey
		}
	}
	if primaries != 1 {
		return "", errKey
	}
	return fpr, nil
}

// dearmor decodes an ASCII-armored public key block and checks its CRC-24
// when one is present.
func dearmor(data []byte) ([]byte, error) {
	const begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	const end = "-----END PGP PUBLIC KEY BLOCK-----"
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	i := strings.Index(text, begin)
	if i < 0 {
		return nil, errKey
	}
	text = text[i+len(begin):]
	j := strings.Index(text, end)
	if j < 0 {
		return nil, errKey
	}
	// Nothing but whitespace may follow: a second block would be a second key.
	if strings.TrimSpace(text[j+len(end):]) != "" {
		return nil, errKey
	}
	lines := strings.Split(text[:j], "\n")
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
			crc = l[1:]
		default:
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
