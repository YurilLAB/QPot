package instance

import "testing"

// FuzzParseComposePS fuzzes the `docker compose ps --format json` parser with
// arbitrary bytes (JSON, JSONL, garbage, truncated, huge). It must never panic
// and every returned entry must be keyed by a non-empty service name.
func FuzzParseComposePS(f *testing.F) {
	f.Add(`{"Name":"a_cowrie","Service":"cowrie","State":"running"}`)
	f.Add(`[{"Service":"x","State":"running"},{"Service":"y","State":"exited"}]`)
	f.Add("")
	f.Add("not json at all")
	f.Add(`{"Service":"a","State":"running"}` + "\n" + `{broken`)
	f.Add(`[1,2,3]`)
	f.Add(`{"Service":"` + "\x00\xff" + `","State":"running"}`)
	f.Fuzz(func(t *testing.T, in string) {
		m := parseComposePS([]byte(in)) // must not panic
		for k, e := range m {
			if k == "" {
				t.Error("parseComposePS produced an empty service key")
			}
			if e.Service != k {
				t.Errorf("entry keyed by %q but Service=%q", k, e.Service)
			}
		}
	})
}
