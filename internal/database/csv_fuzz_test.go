package database

import "testing"

// FuzzCSVRoundTrip verifies the export→import field round-trip: any field
// values, once chCSVEscape'd and joined into a CSV line, must split back to the
// exact same values via splitCSVLine. This guards data integrity of the
// ExportData/ImportData path against commas, quotes, newlines, and control
// bytes in attacker-controlled fields (usernames, commands, etc.).
func FuzzCSVRoundTrip(f *testing.F) {
	f.Add("root", "wget http://x/y", "ssh")
	f.Add("a,b", `quote"inside`, "line\nbreak")
	f.Add("", `"`, `""`)
	f.Add("\r\n,\"", "\x00\x01", "trailing,")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		in := []string{a, b, c}
		line := chCSVEscape(a) + "," + chCSVEscape(b) + "," + chCSVEscape(c)
		got := splitCSVLine(line) // must not panic
		if len(got) != len(in) {
			t.Fatalf("round-trip field count: got %d (%q), want %d (line=%q)", len(got), got, len(in), line)
		}
		for i := range in {
			if got[i] != in[i] {
				t.Errorf("field %d round-trip mismatch: got %q, want %q (line=%q)", i, got[i], in[i], line)
			}
		}
	})
}
