// Package geo provides the coordinates QPot's attack map plots: approximate
// country centroids looked up by ISO-3166-1 alpha-2 code (the country the
// collector's GeoIP enrichment tags each event with), the sensor's own country
// inferred locally from the system time zone, and the free DB-IP Lite country
// database that `qpot setup --geoip` / `qpot geoip update` provision.
package geo

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Country is a country with an approximate centroid.
type Country struct {
	Code string
	Name string
	Lat  float64
	Lon  float64
}

// Lookup returns the country for an ISO-3166-1 alpha-2 code (any case).
func Lookup(code string) (Country, bool) {
	c, ok := countries[strings.ToUpper(strings.TrimSpace(code))]
	return c, ok
}

// zoneTabs are the tz database tables mapping zones to countries.
var zoneTabs = []string{"/usr/share/zoneinfo/zone1970.tab", "/usr/share/zoneinfo/zone.tab"}

// HostCountry infers the country this host is in from its configured time
// zone (TZ, /etc/timezone, or the /etc/localtime link) and the tz database's
// zone table. It reads local files only - no network lookup of the host's
// public address. Returns false when it cannot tell (UTC, unknown zone).
func HostCountry() (Country, bool) {
	zone := hostZone()
	if zone == "" {
		return Country{}, false
	}
	for _, tab := range zoneTabs {
		if code := countryForZone(tab, zone); code != "" {
			return Lookup(code)
		}
	}
	return Country{}, false
}

func hostZone() string {
	if tz := strings.TrimPrefix(os.Getenv("TZ"), ":"); tz != "" && !strings.HasPrefix(tz, "/") {
		return tz
	}
	if b, err := os.ReadFile("/etc/timezone"); err == nil {
		if z := strings.TrimSpace(string(b)); z != "" {
			return z
		}
	}
	if target, err := filepath.EvalSymlinks("/etc/localtime"); err == nil {
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			return target[i+len("zoneinfo/"):]
		}
	}
	return ""
}

// countryForZone returns the first country code listed for zone in a
// zone.tab / zone1970.tab file (columns: codes, coordinates, TZ, comments).
func countryForZone(tab, zone string) string {
	f, err := os.Open(tab)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) >= 3 && fields[2] == zone {
			return strings.Split(fields[0], ",")[0]
		}
	}
	return ""
}
