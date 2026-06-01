package main

import (
	"testing"
	"unicode/utf8"
)

// FuzzTruncate ensures truncate never panics and never returns more than maxLen
// bytes for any input / length (including negative and multibyte UTF-8).
func FuzzTruncate(f *testing.F) {
	f.Add("hello world", 5)
	f.Add("", 0)
	f.Add("abc", -1)
	f.Add("héllo wörld €", 4)
	f.Add("ünïcödé", 2)
	f.Fuzz(func(t *testing.T, s string, maxLen int) {
		out := truncate(s, maxLen) // must not panic
		if maxLen <= 0 && out != "" {
			t.Errorf("truncate(%q, %d) = %q, want empty", s, maxLen, out)
		}
		if maxLen > 0 && len(out) > maxLen {
			t.Errorf("truncate(%q, %d) returned %d bytes (> maxLen)", s, maxLen, len(out))
		}
	})
}

// FuzzDeriveHoneypot ensures deriveHoneypot never panics on arbitrary container
// names and always returns a value (possibly the input).
func FuzzDeriveHoneypot(f *testing.F) {
	for _, s := range []string{"qpot_cowrie", "inst-dionaea-1", "", "_", "-", "a_b_c", "x-1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		_ = deriveHoneypot(name) // must not panic
	})
}

// FuzzExtractHealth ensures extractHealth never panics and only returns the
// known status vocabulary for any docker status string.
func FuzzExtractHealth(f *testing.F) {
	allowed := map[string]bool{
		"healthy": true, "unhealthy": true, "starting": true,
		"running": true, "exited": true, "unknown": true,
	}
	for _, s := range []string{"Up 3 hours (healthy)", "Exited (1)", "", "UP", "weird \x00 status"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, status string) {
		got := extractHealth(status)
		if !allowed[got] {
			t.Errorf("extractHealth(%q) = %q, not in known vocabulary", status, got)
		}
		// sanity: output is always valid UTF-8
		if !utf8.ValidString(got) {
			t.Errorf("extractHealth returned invalid UTF-8")
		}
	})
}
