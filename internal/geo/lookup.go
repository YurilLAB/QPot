package geo

import (
	"fmt"
	"net"
	"strconv"

	"github.com/oschwald/maxminddb-golang"
)

// Place is where an address is, as a MaxMind-format database records it:
// the country's ISO code, the city's English name and the network's AS number.
// A country database (DB-IP Lite) has no city or AS number.
type Place struct {
	Country string
	City    string
	ASN     string
}

// mmdbRecord holds the fields QPot reads from a record, the same ones the
// collector's GeoIP step stores with every event.
type mmdbRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	ASN uint `maxminddb:"autonomous_system_number"`
}

// LookupIP looks ip up in the MaxMind-format database at dbPath. It returns an
// empty Place, and no error, for an address the database does not know.
func LookupIP(dbPath, ip string) (Place, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return Place{}, fmt.Errorf("not an IP address: %q", ip)
	}
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return Place{}, fmt.Errorf("open GeoIP database: %w", err)
	}
	defer db.Close()
	var rec mmdbRecord
	if err := db.Lookup(addr, &rec); err != nil {
		return Place{}, fmt.Errorf("GeoIP lookup: %w", err)
	}
	p := Place{Country: rec.Country.ISOCode, City: rec.City.Names["en"]}
	if rec.ASN != 0 {
		p.ASN = strconv.FormatUint(uint64(rec.ASN), 10)
	}
	return p, nil
}
