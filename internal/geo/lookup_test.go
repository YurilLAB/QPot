package geo

import (
	"path/filepath"
	"testing"

	"github.com/qpot/qpot/internal/geo/geotest"
)

func TestLookupIP(t *testing.T) {
	db := geotest.WriteMMDB(t)
	got, err := LookupIP(db, geotest.KnownIP)
	if err != nil || got != (Place{Country: geotest.Country, City: geotest.City, ASN: geotest.ASN}) {
		t.Fatalf("%s: %+v, %v", geotest.KnownIP, got, err)
	}
	// An address the database does not know: no place, no error.
	if got, err := LookupIP(db, "10.1.2.3"); err != nil || got != (Place{}) {
		t.Fatalf("10.1.2.3: %+v, %v", got, err)
	}
	if _, err := LookupIP(db, "not-an-ip"); err == nil {
		t.Fatal("a non-address was looked up")
	}
	if _, err := LookupIP(filepath.Join(t.TempDir(), "missing.mmdb"), geotest.KnownIP); err == nil {
		t.Fatal("a missing database gave no error")
	}
}
