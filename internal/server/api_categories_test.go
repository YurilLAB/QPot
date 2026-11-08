package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// GET /api/categories lists every category, in the catalogue's order, with
// its label and the number of recent events carrying it. A CVE stored after
// exploit-attempt is not a category and is not counted as one.
func TestCategoriesEndpoint(t *testing.T) {
	a := newAPITestServer(t, "api-categories", nil)
	db := &orderDB{evs: []*database.Event{
		{Categories: []string{"path-traversal", "scanning"}},
		{Categories: []string{"exploit-attempt", "CVE-2021-44228", "code-injection"}},
		{Categories: []string{"scanning"}},
		{},
	}}
	a.s.database = db
	assertAuthRequired(t, a.h, http.MethodGet, "/api/categories", "")
	if rec := a.do(http.MethodPost, "/api/categories", `{}`); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}

	rec := a.do(http.MethodGet, "/api/categories", "")
	var got []struct {
		ID, Label, Description string
		Count                  int
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	cats := intelligence.Categories()
	if len(got) != len(cats) {
		t.Fatalf("%d categories, want %d", len(got), len(cats))
	}
	want := map[string]int{"path-traversal": 1, "scanning": 2, "exploit-attempt": 1, "code-injection": 1}
	for i, c := range got {
		if c.ID != cats[i].ID || c.Label != cats[i].Label || c.Description == "" {
			t.Errorf("entry %d = %+v, want %+v", i, c, cats[i])
		}
		if c.Count != want[c.ID] {
			t.Errorf("%s count %d, want %d", c.ID, c.Count, want[c.ID])
		}
	}

	a.s.database = nil
	if rec := a.do(http.MethodGet, "/api/categories", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no database: %d", rec.Code)
	}
}
