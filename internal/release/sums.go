// Package release builds QPot's release archives and the SHA256SUMS file
// the installers check them against, and parses that file the same strict
// way the installers do (scripts/install.sh and scripts/install.ps1 carry
// the same rules; a test runs them side by side).
package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Limits of a SHA256SUMS file. A real one lists a handful of archives; the
// installers refuse anything larger before reading it.
const (
	MaxSumsSize    = 64 << 10
	MaxSumsEntries = 256
	MaxNameLen     = 128
)

// Sums is a parsed SHA256SUMS file: file name to lower-case hex SHA-256.
type Sums map[string]string

// Errors from ParseSums and Verify.
var (
	ErrSumsTooLarge = errors.New("the checksum list is larger than 64 KiB")
	ErrSumsEmpty    = errors.New("the checksum list has no entries")
	ErrNoEntry      = errors.New("the checksum list has no entry for this file")
	ErrMismatch     = errors.New("the file does not match its checksum")
)

// SumsLineError reports the first line of a SHA256SUMS file that breaks the
// format.
type SumsLineError struct {
	Line   int
	Reason string
}

func (e *SumsLineError) Error() string {
	return fmt.Sprintf("checksum list line %d: %s", e.Line, e.Reason)
}

// ValidName reports whether name may appear in a SHA256SUMS file: a plain
// file name (no folders), 1 to 128 characters of letters, digits and
// ". _ + -", starting with a letter or digit. Anything else (spaces, path
// separators, "..", control characters, non-ASCII) is refused, so a name can
// never point outside the download folder.
func ValidName(name string) bool {
	if name == "" || len(name) > MaxNameLen || strings.Contains(name, "..") {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if i == 0 && !alnum {
			return false
		}
		if !alnum && c != '.' && c != '_' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ParseSums reads a SHA256SUMS file in the format sha256sum writes:
//
//	<64 lower-case hex digits><two spaces, or space and '*'><file name>
//
// one entry per line, lines ending in "\n" (the last line may lack it).
// The whole file is refused when any line breaks the format, a name is
// listed twice, it has no entries, or it is larger than MaxSumsSize: a list
// that is not exactly what the release wrote is not trusted at all.
func ParseSums(data []byte) (Sums, error) {
	if len(data) > MaxSumsSize {
		return nil, ErrSumsTooLarge
	}
	text := string(data)
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil, ErrSumsEmpty
	}
	lines := strings.Split(text, "\n")
	if len(lines) > MaxSumsEntries {
		return nil, &SumsLineError{MaxSumsEntries + 1, "too many entries"}
	}
	sums := make(Sums, len(lines))
	for i, line := range lines {
		n := i + 1
		if len(line) < 67 {
			return nil, &SumsLineError{n, "too short"}
		}
		hash, sep, name := line[:64], line[64:66], line[66:]
		switch {
		case !isLowerHex64(hash):
			return nil, &SumsLineError{n, "the checksum is not 64 lower-case hex digits"}
		case sep != "  " && sep != " *":
			return nil, &SumsLineError{n, "the checksum and the name are not separated by two spaces"}
		case !ValidName(name):
			return nil, &SumsLineError{n, "the file name is not a plain file name"}
		}
		if _, dup := sums[name]; dup {
			return nil, &SumsLineError{n, "the file name is listed twice"}
		}
		sums[name] = hash
	}
	return sums, nil
}

// Format writes the list the way sha256sum does, sorted by name. It panics
// on a name or checksum ParseSums would refuse: the release must never
// publish a list the installers reject.
func (s Sums) Format() []byte {
	names := make([]string, 0, len(s))
	for n := range s {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		if !ValidName(n) || !isLowerHex64(s[n]) {
			panic(fmt.Sprintf("release: bad checksum entry %q", n))
		}
		b.WriteString(s[n] + "  " + n + "\n")
	}
	return []byte(b.String())
}

// Digest returns the lower-case hex SHA-256 of everything r yields.
func Digest(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Verify checks that the file called name, read from r, has the checksum
// the list gives for it.
func (s Sums) Verify(name string, r io.Reader) error {
	want, ok := s[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNoEntry, name)
	}
	got, err := Digest(r)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%w: %s: expected %s, got %s", ErrMismatch, name, want, got)
	}
	return nil
}
