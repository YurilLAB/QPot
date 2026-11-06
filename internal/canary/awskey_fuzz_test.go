package canary

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

// FuzzAWSKeyID: every key id awsKeyID lays out, from any byte stream, is an
// AKIA id of the post-2019 layout whose account (as scanners decode it) is a
// 12-digit one; and AWSAccountOfKey reads anything without failing, naming an
// account only for a 20-character AKIA/ASIA id.
func FuzzAWSKeyID(f *testing.F) {
	// key-shaped seeds are built here, not written out, for the secret scanner's sake
	for _, s := range []string{"", "seed", "AKIA" + "IOSFODNN7" + "EXAMPLE", "AS" + "IA" + strings.Repeat("Q7", 8), "AKIA====",
		"AKIA0000000000000000", "akiaiosfodnn7example", "AKIA" + "IOSFODNN7" + "EXAMPL\xff"} {
		f.Add([]byte(s), s)
	}
	f.Fuzz(func(t *testing.T, seed []byte, s string) {
		// a stream of bytes from the seed, as the deriver's reader gives one
		var block []byte
		var n uint32
		next := func() byte {
			if len(block) == 0 {
				h := sha256.New()
				h.Write(seed)
				h.Write(binary.BigEndian.AppendUint32(nil, n))
				block = h.Sum(nil)
				n++
			}
			b := block[0]
			block = block[1:]
			return b
		}
		id := awsKeyID(next)
		account, ok := AWSAccountOfKey(id)
		if len(id) != 20 || !strings.HasPrefix(id, "AKIA") || !ok || account >= awsAccounts ||
			!strings.ContainsRune("QRSTUVWXYZ234567", rune(id[4])) {
			t.Fatalf("awsKeyID gave %q (account %d, ok %v)", id, account, ok)
		}
		if strings.Trim(id[4:], "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
			t.Fatalf("%q is not base32 without padding", id)
		}

		account, ok = AWSAccountOfKey(s)
		if ok && (len(s) != 20 || !(strings.HasPrefix(s, "AKIA") || strings.HasPrefix(s, "ASIA")) || account >= 1<<40) {
			t.Fatalf("AWSAccountOfKey(%q) = %d, true", s, account)
		}
	})
}
