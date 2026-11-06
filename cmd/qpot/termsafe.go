package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// termSafe makes attacker-controlled text safe to print to a terminal: honeypot
// logs, event summaries and joiner-supplied names can carry control sequences
// that retitle the terminal, write the clipboard (OSC 52) or move the cursor to
// erase lines. C0 controls (except tab), DEL, C1 controls, bytes that are not
// UTF-8 (an 8-bit terminal reads 0x9b as CSI) and bidi overrides are shown as
// \xNN or \uNNNN instead.
func termSafe(s string) string {
	clean := true
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if unsafeRune(r, size) {
			clean = false
			break
		}
		i += size
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unsafeRune(r, size) && r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case unsafeRune(r, size):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// termSafeWriter passes output through termSafe line by line. Call Flush
// after the last write.
type termSafeWriter struct {
	w   io.Writer
	buf []byte
}

func (t *termSafeWriter) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	for {
		i := bytes.IndexByte(t.buf, '\n')
		if i < 0 {
			break
		}
		if _, err := io.WriteString(t.w, termSafe(string(t.buf[:i]))+"\n"); err != nil {
			return len(p), err
		}
		t.buf = t.buf[i+1:]
	}
	if len(t.buf) > 64<<10 { // an endless line: do not buffer it all
		t.Flush()
	}
	return len(p), nil
}

// Flush writes what is left of an unterminated last line.
func (t *termSafeWriter) Flush() {
	if len(t.buf) > 0 {
		_, _ = io.WriteString(t.w, termSafe(string(t.buf)))
		t.buf = t.buf[:0]
	}
}

func unsafeRune(r rune, size int) bool {
	switch {
	case r == utf8.RuneError && size <= 1:
		return true
	case r < 0x20:
		return r != '\t'
	case r >= 0x7f && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
