package yuril

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/database"
)

// FuzzTranslateIOC throws arbitrary IOC field values at the QPot->Yuril
// translation path and asserts its invariants. This code sits on the outbound
// intel boundary, so it must never panic and must only ever emit items whose
// type is in the Yuril vocabulary, with a confidence in range.
func FuzzTranslateIOC(f *testing.F) {
	seeds := []struct {
		typ, val string
		count    int64
	}{
		{"ip", "203.0.113.1", 1},
		{"domain", "evil.com", 10},
		{"url", "http://evil.com/x", 0},
		{"hash", "d41d8cd98f00b204e9800998ecf8427e", 9999},
		{"credential", "root:root", 3},
		{"", "", -5},
		{"IP", strings.Repeat("a", 4000), 1 << 62},
		{"unknown_type", "x", -1},
	}
	for _, s := range seeds {
		f.Add(s.typ, s.val, s.count)
	}

	validTypes := map[string]bool{"ip": true, "domain": true, "url": true, "hash": true}

	f.Fuzz(func(t *testing.T, typ, val string, count int64) {
		ioc := &database.IOC{
			Type:     typ,
			Value:    val,
			Count:    count,
			Metadata: map[string]string{"k": val, "context": typ},
			Honeypot: "cowrie",
			SourceIP: "203.0.113.9",
		}

		item, ok := translateIOC(ioc) // must not panic
		if !ok {
			return // unmapped type — correctly dropped
		}

		if !validTypes[item.Type] {
			t.Errorf("translated item has out-of-vocabulary type %q (from %q)", item.Type, typ)
		}
		if item.Confidence > 100 {
			t.Errorf("confidence %d exceeds 100", item.Confidence)
		}
		// translateIOC preserves the value verbatim.
		if item.Value != val {
			t.Errorf("value mutated: got %q want %q", item.Value, val)
		}
	})
}

// FuzzConfidenceFromCount ensures the confidence mapping is always in [0,100]
// for any count, including negatives and extremes.
func FuzzConfidenceFromCount(f *testing.F) {
	for _, n := range []int64{-1 << 62, -1, 0, 1, 4, 5, 24, 25, 1 << 62} {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, n int64) {
		c := confidenceFromCount(n)
		if c > 100 {
			t.Errorf("confidenceFromCount(%d) = %d, exceeds 100", n, c)
		}
	})
}
