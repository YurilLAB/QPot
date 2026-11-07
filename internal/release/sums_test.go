package release

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const (
	hashA = "1111111111111111111111111111111111111111111111111111111111111111"
	hashB = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
)

func TestParseSumsAcceptsWhatSha256sumWrites(t *testing.T) {
	cases := map[string]Sums{
		hashA + "  qpot_0.1.0_linux_amd64.tar.gz\n":                                  {"qpot_0.1.0_linux_amd64.tar.gz": hashA},
		hashA + "  a.zip\n" + hashB + " *b.tar.gz\n":                                 {"a.zip": hashA, "b.tar.gz": hashB},
		hashA + "  no-final-newline":                                                 {"no-final-newline": hashA},
		hashA + "  " + strings.Repeat("x", MaxNameLen) + "\n":                        {strings.Repeat("x", MaxNameLen): hashA},
		hashB + "  qpot_0.2.0-rc.1_darwin_arm64.tar.gz\n" + hashA + "  v+meta.txt\n": {"qpot_0.2.0-rc.1_darwin_arm64.tar.gz": hashB, "v+meta.txt": hashA},
	}
	for in, want := range cases {
		got, err := ParseSums([]byte(in))
		if err != nil {
			t.Errorf("ParseSums(%q): %v", in, err)
			continue
		}
		if len(got) != len(want) {
			t.Errorf("ParseSums(%q) = %v, want %v", in, got, want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("ParseSums(%q)[%s] = %q, want %q", in, k, got[k], v)
			}
		}
	}
}

func TestParseSumsRefusesAnythingElse(t *testing.T) {
	ok := hashA + "  qpot.tar.gz"
	cases := []string{
		"",
		"\n",
		ok + "\n\n",                      // a blank line
		"\n" + ok,                        // a blank first line
		ok + "\r\n",                      // CRLF
		strings.ToUpper(hashB) + "  x\n", // upper-case hex: not what sha256sum writes
		hashA[:63] + "  x\n",             // short checksum
		hashA + "1  x\n",                 // long checksum
		hashA + " x\n",                   // one space
		hashA + "\tx\n",                  // a tab
		hashA + "   x\n",                 // three spaces: the name would start with a space
		hashA + "  x \n",                 // trailing space
		hashA + "  ../x\n",               // a path
		hashA + "  a/b\n",                // a folder
		hashA + "  a\\b\n",               // a Windows folder
		hashA + "  a..b\n",               // ".." anywhere
		hashA + "  .hidden\n",            // must start with a letter or digit
		hashA + "  -x\n",
		hashA + "  " + strings.Repeat("x", MaxNameLen+1) + "\n",
		hashA + "  x\x00\n",       // NUL
		hashA + "  caf\xc3\xa9\n", // non-ASCII
		ok + "\n" + ok + "\n",     // listed twice
		ok + "\n" + hashB + "  qpot.tar.gz\n",
		"# comment\n" + ok,
		hashA + "  x\n" + "garbage\n",
		"g" + hashA[1:] + "  x\n",
	}
	for _, in := range cases {
		if s, err := ParseSums([]byte(in)); err == nil {
			t.Errorf("ParseSums(%q) accepted it: %v", in, s)
		}
	}
}

func TestParseSumsLimits(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxSumsEntries; i++ {
		b.WriteString(hashA + "  f" + strings.Repeat("0", 4) + itoa(i) + "\n")
	}
	if _, err := ParseSums([]byte(b.String())); err != nil {
		t.Fatalf("%d entries refused: %v", MaxSumsEntries, err)
	}
	b.WriteString(hashA + "  one-more\n")
	if _, err := ParseSums([]byte(b.String())); err == nil {
		t.Fatalf("%d entries accepted", MaxSumsEntries+1)
	}
	big := bytes.Repeat([]byte("x"), MaxSumsSize+1)
	if _, err := ParseSums(big); !errors.Is(err, ErrSumsTooLarge) {
		t.Fatalf("a list over 64 KiB: %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(rune('0'+i%10)) + s
	}
	return s
}

func TestFormatRoundTripsAndVerify(t *testing.T) {
	data := []byte("the archive")
	d, err := Digest(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	s := Sums{"b.zip": hashB, "a.tar.gz": d}
	text := s.Format()
	if want := d + "  a.tar.gz\n" + hashB + "  b.zip\n"; string(text) != want {
		t.Fatalf("Format = %q, want %q", text, want)
	}
	back, err := ParseSums(text)
	if err != nil || len(back) != 2 || back["a.tar.gz"] != d {
		t.Fatalf("round trip: %v %v", back, err)
	}
	if err := back.Verify("a.tar.gz", bytes.NewReader(data)); err != nil {
		t.Fatalf("Verify of the right file: %v", err)
	}
	if err := back.Verify("a.tar.gz", bytes.NewReader([]byte("the archivE"))); !errors.Is(err, ErrMismatch) {
		t.Fatalf("Verify of a changed file: %v", err)
	}
	if err := back.Verify("c.zip", bytes.NewReader(data)); !errors.Is(err, ErrNoEntry) {
		t.Fatalf("Verify without an entry: %v", err)
	}
}

func TestFormatRefusesBadEntries(t *testing.T) {
	for _, s := range []Sums{{"a/b": hashA}, {"x": "ABC"}, {"": hashA}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Format(%v) did not panic", s)
				}
			}()
			s.Format()
		}()
	}
}

func FuzzParseSums(f *testing.F) {
	f.Add([]byte(hashA + "  qpot_0.1.0_linux_amd64.tar.gz\n" + hashB + " *qpot_0.1.0_windows_amd64.zip\n"))
	f.Add([]byte(hashA + "  x"))
	f.Add([]byte(hashA + "  x\r\n"))
	f.Add([]byte(hashA + "  ../../etc/passwd\n"))
	f.Add([]byte(""))
	f.Add([]byte("\n\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseSums(data)
		if err != nil {
			if s != nil {
				t.Fatal("an error with a result")
			}
			return
		}
		if len(data) > MaxSumsSize || len(s) == 0 || len(s) > MaxSumsEntries {
			t.Fatalf("accepted %d bytes with %d entries", len(data), len(s))
		}
		for name, hash := range s {
			if !ValidName(name) || !isLowerHex64(hash) {
				t.Fatalf("accepted entry %q %q", name, hash)
			}
		}
		// What the parser accepts, Format writes back and the parser reads
		// to the same entries.
		again, err := ParseSums(s.Format())
		if err != nil || len(again) != len(s) {
			t.Fatalf("round trip: %v", err)
		}
		for k, v := range s {
			if again[k] != v {
				t.Fatalf("round trip changed %s", k)
			}
		}
	})
}
