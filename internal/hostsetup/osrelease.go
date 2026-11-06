package hostsetup

import (
	"bufio"
	"bytes"
	"strings"
)

// OSRelease is the parsed content of /etc/os-release (os-release(5)).
type OSRelease map[string]string

// maxOSReleaseSize bounds what is read: the real file is under 1 KiB.
const maxOSReleaseSize = 64 << 10

// ParseOSRelease parses os-release(5): KEY=value lines, where the value may
// be unquoted or in single or double quotes, with backslash escapes inside
// double quotes. Comments, blank lines and malformed lines are skipped. The
// file is never executed (it is shell syntax, so sourcing it would run code).
func ParseOSRelease(data []byte) OSRelease {
	if len(data) > maxOSReleaseSize {
		data = data[:maxOSReleaseSize]
	}
	out := OSRelease{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxOSReleaseSize)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok || !validOSReleaseKey(key) {
			continue
		}
		val, ok := unquoteOSRelease(raw)
		if !ok {
			continue
		}
		out[key] = val
	}
	return out
}

func validOSReleaseKey(k string) bool {
	if k == "" || len(k) > 64 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'A' && c <= 'Z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// unquoteOSRelease decodes one value. Values holding characters that are not
// printable (control bytes) are rejected; the caller skips the line.
func unquoteOSRelease(raw string) (string, bool) {
	var val string
	switch {
	case len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"':
		var b strings.Builder
		in := raw[1 : len(raw)-1]
		for i := 0; i < len(in); i++ {
			c := in[i]
			if c == '\\' && i+1 < len(in) && strings.IndexByte("\"\\$`", in[i+1]) >= 0 {
				i++
				c = in[i]
			} else if c == '"' {
				return "", false // an unescaped quote inside: not a valid value
			}
			b.WriteByte(c)
		}
		val = b.String()
	case len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'':
		val = raw[1 : len(raw)-1]
		if strings.ContainsRune(val, '\'') {
			return "", false
		}
	default:
		if strings.ContainsAny(raw, " \t\"'\\$`") {
			return "", false
		}
		val = raw
	}
	for _, r := range val {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return val, true
}

// ID returns the lower-case distribution ID, e.g. "ubuntu".
func (o OSRelease) ID() string { return strings.ToLower(o["ID"]) }

// Like returns ID followed by the ID_LIKE entries.
func (o OSRelease) Like() []string {
	return append([]string{o.ID()}, strings.Fields(strings.ToLower(o["ID_LIKE"]))...)
}

// IsLike reports whether the distribution is id or declares itself like id.
func (o OSRelease) IsLike(id string) bool {
	for _, x := range o.Like() {
		if x == id {
			return true
		}
	}
	return false
}

// MajorVersion returns VERSION_ID up to the first dot ("9" for "9.4").
func (o OSRelease) MajorVersion() string {
	v, _, _ := strings.Cut(o["VERSION_ID"], ".")
	return v
}

// Pretty returns a human-readable name for messages.
func (o OSRelease) Pretty() string {
	if p := o["PRETTY_NAME"]; p != "" {
		return p
	}
	if n := o["NAME"]; n != "" {
		return strings.TrimSpace(n + " " + o["VERSION_ID"])
	}
	return "an unknown Linux distribution"
}
