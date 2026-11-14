package instance

// What this instance's Conpot device says of itself and its site, worked out
// here as the container works it out: honeypotfiles/conpot/site_identity.py
// and the mounted tank gauge draw these values from the site seed QPot passes
// (conpotSiteSeed), and this file draws the same ones from the same seed.
//
// Nothing here reaches the device. It is for what QPot writes elsewhere about
// that device (the support host's maintenance archive, bait_industrial.go):
// a visitor who reads the archive and then asks the device must hear the
// same names. TestConpotSiteMirror holds the two together.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/qpot/qpot/internal/config"
)

// The lists site_identity.py picks from, in its order.
var (
	siteStations     = []string{"NWD", "ELM", "RVS", "HLD", "KGS", "WTN", "BRK", "ASH", "MRL", "FRD", "LKS", "OAK", "STN", "CLF", "GRV", "PKH"}
	siteBays         = []string{"T1E", "T2E", "T1W", "T2W", "E01", "E02", "K1", "K2", "Bay 3", "Bay 5"}
	siteContacts     = []string{"SCADA Operations", "IT Service Desk", "Network Control", "OT Support", "Control Room", "Grid Operations", "Telecontrol Group", "Protection and Control"}
	siteBMCNames     = []string{"bmc%02d", "ipmi-node%02d", "srv%02d-bmc", "mgmt%02d", "node%02d-ipmi", "esx%02d-bmc", "stor%02d-bmc"}
	siteMeterServers = []string{"kap%02d.meter.local", "ami-head%02d.int.local", "mdm%02d.util.local", "hes%02d.grid.local", "collector%02d.ami.local", "pwr-ctrl-%02d.int.local"}
	siteRooms        = []string{"Plant Room", "Technikraum UG", "Mechanical Room 1", "Roof Plant Room", "Basement Plant", "Heizzentrale", "Energy Centre", "MER 01"}
)

// The lists guardian_ast_server.py picks from, in its order.
var (
	gaugeNames = []string{
		"QUICK STOP", "MAIN ST FUEL", "HILLSIDE MARKET", "RIVER RD TRAVEL CTR", "CORNER PANTRY",
		"VALLEY GAS & GO", "LAKESIDE FUEL STOP", "NORTHGATE EXPRESS", "FOUR CORNERS MART", "PINE RIDGE FUEL",
		"COUNTY LINE STORE", "BRIDGE ST SERVICE", "EASTSIDE FOOD MART", "PRAIRIE TRAVEL PLAZA", "MILL CREEK FUEL",
	}
	gaugeStreets = []string{"MAIN ST", "OAK ST", "HIGHWAY 9", "STATE ROUTE 12", "MAPLE AVE", "COUNTY RD 41", "CHURCH ST", "US HWY 60", "ELM ST", "INDUSTRIAL BLVD"}
	gaugeLineups = [][]string{
		{"REGULAR", "PLUS", "PREMIUM", "DIESEL"},
		{"UNLEADED", "PREMIUM", "DIESEL"},
		{"REGULAR UNLEADED", "PREMIUM UNLEADED", "DIESEL", "KEROSENE"},
		{"REGULAR", "MIDGRADE", "PREMIUM", "DIESEL #2"},
		{"UNLEADED 87", "UNLEADED 93", "DIESEL"},
	}
	// Nominal capacity in gallons.
	gaugeTanks = []int{6000, 8000, 10000, 10000, 12000, 15000}
)

// conpotTank is one tank of the gauge: its number, the product on its label
// and its nominal capacity in gallons.
type conpotTank struct {
	Number      int    `json:"tank"`
	Product     string `json:"product"`
	CapacityGal int    `json:"nominal_capacity_gal"`
}

// conpotSite is what a profile's device says of itself where QPot decides
// it. A field is empty when the profile's device says nothing of the kind.
type conpotSite struct {
	// Name is the name the device gives itself: the RTU's SNMP sysName, the
	// BMC's system name, the first line of the gauge's report header.
	Name string
	// Station is the station code an RTU and an ICCP server are named for.
	Station string
	// Facility, Location and Contact are the RTU's facility name and SNMP
	// sysLocation and sysContact; Location is also the building
	// controller's room and the second line of the gauge's header.
	Facility, Location, Contact string
	// Domain is the ICCP server's domain.
	Domain string
	// ReportsTo and ReportsToIP are the server a meter reports to.
	ReportsTo, ReportsToIP string
	// Tanks are the gauge's tanks as it labels them when first started.
	Tanks []conpotTank
}

// siteDraw is site_identity.py's draw: a number below n that depends only
// on the seed and what is asked.
func siteDraw(seed, what string, n int) int {
	sum := sha256.Sum256([]byte(seed + "\x00" + what))
	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(n))
}

func sitePick(seed, what string, values []string) string {
	return values[siteDraw(seed, what, len(values))]
}

// gaugeDraw is guardian_ast_server.py's _draw: a number in [0, 1).
func gaugeDraw(seed string, what ...string) float64 {
	sum := sha256.Sum256([]byte(strings.Join(append([]string{seed}, what...), "\x00")))
	return float64(binary.BigEndian.Uint64(sum[:8])) / (1 << 64)
}

// gaugeIndex is the index its _pick takes from a list of n values.
func gaugeIndex(seed string, n int, what ...string) int {
	return int(gaugeDraw(seed, what...)*float64(n)) % n
}

// conpotSiteFor returns what the device of profile says of itself at the
// site of seed (a conpotSiteSeed).
func conpotSiteFor(profile, seed string) conpotSite {
	station := fmt.Sprintf("%s%02d", sitePick(seed, "station", siteStations), 1+siteDraw(seed, "station-number", 24))
	switch profile {
	case "IEC104":
		return conpotSite{
			Station:  station,
			Name:     fmt.Sprintf("%s-RTU%d", station, 1+siteDraw(seed, "rtu", 3)),
			Facility: station + " Substation",
			Location: station + ", " + sitePick(seed, "bay", siteBays),
			Contact:  sitePick(seed, "contact", siteContacts),
		}
	case "iccp":
		return conpotSite{Station: station, Domain: station + "_ICC"}
	case "ipmi":
		return conpotSite{Name: fmt.Sprintf(sitePick(seed, "bmc", siteBMCNames), 1+siteDraw(seed, "bmc-number", 48))}
	case "kamstrup_382":
		return conpotSite{
			ReportsTo:   fmt.Sprintf(sitePick(seed, "meter-server", siteMeterServers), 1+siteDraw(seed, "meter-server-number", 8)),
			ReportsToIP: fmt.Sprintf("10.%d.%d.%d", siteDraw(seed, "kap-a", 256), siteDraw(seed, "kap-b", 256), 2+siteDraw(seed, "kap-c", 250)),
		}
	case "building_automation":
		return conpotSite{Location: sitePick(seed, "room", siteRooms)}
	case "guardian_ast":
		// The gauge's own seed, as gauge_seed draws it from the site's.
		sum := sha256.Sum256([]byte("qpot-gauge\x00" + seed))
		g := hex.EncodeToString(sum[:])[:32]
		site := conpotSite{
			Name:     fmt.Sprintf("%s #%d", gaugeNames[gaugeIndex(g, len(gaugeNames), "name")], 100+int(gaugeDraw(g, "number")*8900)),
			Location: fmt.Sprintf("%d %s", 100+int(gaugeDraw(g, "street-number")*9800), gaugeStreets[gaugeIndex(g, len(gaugeStreets), "street")]),
		}
		for i, product := range gaugeLineups[gaugeIndex(g, len(gaugeLineups), "lineup")] {
			number := fmt.Sprint(i + 1)
			site.Tanks = append(site.Tanks, conpotTank{Number: i + 1, Product: product,
				CapacityGal: gaugeTanks[gaugeIndex(g, len(gaugeTanks), "tank", number)]})
		}
		return site
	}
	return conpotSite{}
}

// conpotSiteOf returns what this instance's Conpot device says of itself.
func conpotSiteOf(cfg *config.Config) conpotSite {
	return conpotSiteFor(ConpotProfile(cfg).ID, conpotSiteSeed(cfg))
}

// SiteFact is one thing a device says of itself: what it is and the value.
type SiteFact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// facts lists what the site holds, in the words the support host's handover
// note uses; none for a device that reports no names.
func (s conpotSite) facts() []SiteFact {
	var out []SiteFact
	add := func(label, value string) {
		if value != "" {
			out = append(out, SiteFact{Label: label, Value: value})
		}
	}
	add("Device name", s.Name)
	add("Site", s.Facility)
	add("Location", s.Location)
	add("Site contact", s.Contact)
	add("ICCP domain", s.Domain)
	if s.ReportsTo != "" {
		add("Reports to", s.ReportsTo+" ("+s.ReportsToIP+")")
	}
	for _, t := range s.Tanks {
		add(fmt.Sprintf("Tank %d", t.Number), fmt.Sprintf("%s, %d gal nominal", t.Product, t.CapacityGal))
	}
	return out
}

// ConpotSiteFacts returns what this instance's Conpot device would say of
// itself as the device of profile id: the names a visitor reads from it, and
// the ones the industrial support archive (cowrie bait_profile=industrial)
// repeats. Empty for a profile whose device reports no site names, and for
// an unknown id.
func ConpotSiteFacts(cfg *config.Config, id string) []SiteFact {
	return conpotSiteFor(id, conpotSiteSeed(cfg)).facts()
}
