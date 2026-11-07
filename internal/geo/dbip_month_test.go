package geo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestFallbackIsThePreviousMonth: the "last month" fallback was now minus one
// month, which Go normalises: on March 29-31 it is still March (February 31
// is March 3), so the fallback asked for the same file again. Every day of
// the year now falls back to the month before.
func TestFallbackIsThePreviousMonth(t *testing.T) {
	var mu sync.Mutex
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path)
		mu.Unlock()
		http.NotFound(w, r)
	}))
	defer srv.Close()
	defer func(f func(time.Time) string) { dbipURL = f }(dbipURL)
	dbipURL = func(m time.Time) string { return srv.URL + "/" + m.Format("2006-01") }

	dest := filepath.Join(t.TempDir(), "x.mmdb")
	for day := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC); day.Year() == 2026; day = day.AddDate(0, 0, 1) {
		mu.Lock()
		hits = nil
		mu.Unlock()
		_ = DownloadDBIPCountry(context.Background(), srv.Client(), dest, day)
		want := []string{"/" + day.Format("2006-01"), "/" + time.Date(day.Year(), day.Month()-1, 1, 0, 0, 0, 0, time.UTC).Format("2006-01")}
		mu.Lock()
		got := append([]string(nil), hits...)
		mu.Unlock()
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("on %s: requested %v, want %v", day.Format("2006-01-02"), got, want)
		}
	}
}
