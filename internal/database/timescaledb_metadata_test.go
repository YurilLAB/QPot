package database

import (
	"encoding/json"
	"maps"
	"testing"
	"unicode/utf8"
)

// The metadata column is JSONB and takes any JSON; reading it must not fail
// whatever a row holds.
func TestPGEventMetadataReadsAnyJSON(t *testing.T) {
	cases := []struct {
		name, in string
		want     map[string]string
	}{
		{"what the collector stores", `{"session": "s1", "version": "SSH-2.0-x"}`, map[string]string{"session": "s1", "version": "SSH-2.0-x"}},
		{"a number, a boolean and null", `{"n": 5, "ok": true, "none": null, "f": 1.5}`, map[string]string{"n": "5", "ok": "true", "none": "", "f": "1.5"}},
		{"an object and a list", `{"a": {"b": 1}, "l": [1, "x"]}`, map[string]string{"a": `{"b": 1}`, "l": `[1, "x"]`}},
		{"an escaped string", `{"k": "a\"b\\c\u00e9"}`, map[string]string{"k": "a\"b\\c\u00e9"}},
		{"an empty object", `{}`, map[string]string{}},
		{"a list", `[1, 2]`, nil},
		{"a string", `"text"`, nil},
		{"a number", `7`, nil},
		{"null", `null`, nil},
	}
	for _, c := range cases {
		// A destination that already holds something, as a reused struct would.
		event := Event{Metadata: map[string]string{"stale": "x"}}
		if err := json.Unmarshal([]byte(c.in), (*pgEventMetadata)(&event.Metadata)); err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !maps.Equal(event.Metadata, c.want) || (c.want == nil) != (event.Metadata == nil) {
			t.Errorf("%s: read %#v, want %#v", c.name, event.Metadata, c.want)
		}
	}
}

// FuzzPGEventMetadata: any JSON value the database can return is read without
// an error, and what the collector stores comes back as it was stored.
func FuzzPGEventMetadata(f *testing.F) {
	for _, seed := range []string{`{"a":"b"}`, `{"a":{"b":[1,2,{"c":null}]}}`, `[]`, `""`, `{"":""}`, `{"a":1e400}`, `{"a":"\ud83d\ude00"}`, `0`} {
		f.Add(seed, "session", "s1")
	}
	f.Fuzz(func(t *testing.T, doc, key, value string) {
		if json.Valid([]byte(doc)) {
			var got pgEventMetadata
			if err := json.Unmarshal([]byte(doc), &got); err != nil {
				t.Fatalf("reading %q failed: %v", doc, err)
			}
		}
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return
		}
		stored, err := json.Marshal(map[string]string{key: value})
		if err != nil {
			t.Fatal(err)
		}
		var back pgEventMetadata
		if err := json.Unmarshal(stored, &back); err != nil || len(back) != 1 || back[key] != value {
			t.Fatalf("a flat map of strings came back as %#v, %v; stored %s", back, err, stored)
		}
	})
}
