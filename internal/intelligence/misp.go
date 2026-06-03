package intelligence

import (
	"fmt"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// MISP export. MISP (https://www.misp-project.org) is the de-facto standard for
// sharing threat indicators between honeypots, SIEMs and threat-intel
// platforms. Exporting QPot's extracted IOCs as a MISP event lets an operator
// pull honeypot findings straight into their TIP/SIEM - the standards-based,
// in-tree equivalent of T-Pot's community sharing, with no external dependency.
//
// The shape produced is a minimal-but-importable MISP event
// ({"Event": {... "Attribute": [...]}}); MISP's importer accepts it directly.

// MISPExport is the top-level object MISP imports.
type MISPExport struct {
	Event MISPEvent `json:"Event"`
}

type MISPEvent struct {
	Info          string          `json:"info"`
	Date          string          `json:"date"`
	ThreatLevelID string          `json:"threat_level_id"` // 1 high .. 4 undefined
	Analysis      string          `json:"analysis"`        // 2 = completed
	Distribution  string          `json:"distribution"`    // 0 = your org only
	Attribute     []MISPAttribute `json:"Attribute"`
	Tag           []MISPTag       `json:"Tag,omitempty"`
}

type MISPAttribute struct {
	Type     string `json:"type"`
	Category string `json:"category"`
	Value    string `json:"value"`
	ToIDS    bool   `json:"to_ids"`
	Comment  string `json:"comment,omitempty"`
}

type MISPTag struct {
	Name string `json:"name"`
}

// mispAttr maps a QPot IOC to a MISP attribute type+category, or returns
// ok=false for IOC kinds that have no useful MISP representation (commands,
// credentials) and should be skipped.
func mispAttr(ioc *database.IOC) (mtype, category string, toIDS, ok bool) {
	switch ioc.Type {
	case IOCTypeIP:
		return "ip-dst", "Network activity", true, true
	case IOCTypeDomain:
		return "domain", "Network activity", true, true
	case IOCTypeURL:
		return "url", "Network activity", true, true
	case IOCTypeUserAgent:
		// Useful for correlation but noisy; don't flag for automated blocking.
		return "user-agent", "Network activity", false, true
	case IOCTypeHash:
		switch len(ioc.Value) {
		case 32:
			return "md5", "Payload delivery", true, true
		case 40:
			return "sha1", "Payload delivery", true, true
		case 64:
			return "sha256", "Payload delivery", true, true
		case 128:
			return "sha512", "Payload delivery", true, true
		}
		return "", "", false, false
	case IOCTypeWallet:
		// MISP has a native btc type; ETH (0x...) has no core type, so record it
		// as text under the same category so it still shares/searches.
		if strings.HasPrefix(ioc.Value, "0x") {
			return "text", "Financial fraud", false, true
		}
		return "btc", "Financial fraud", true, true
	default:
		// command, credential, etc. - not standard MISP indicators.
		return "", "", false, false
	}
}

// BuildMISPEvent converts extracted IOCs into a single importable MISP event.
// Attributes are de-duplicated by (type,value); unsupported IOC kinds are
// skipped. instance labels the event so multiple QPot sensors stay distinct.
func BuildMISPEvent(iocs []*database.IOC, instance string, now time.Time) MISPExport {
	if instance == "" {
		instance = "qpot"
	}
	ev := MISPEvent{
		Info:          fmt.Sprintf("QPot honeypot IOCs - %s - %s", instance, now.UTC().Format("2006-01-02")),
		Date:          now.UTC().Format("2006-01-02"),
		ThreatLevelID: "2", // medium
		Analysis:      "2", // completed
		Distribution:  "0", // your organisation only (operator re-shares deliberately)
		Tag: []MISPTag{
			{Name: "qpot"},
			{Name: "tlp:amber"},
			{Name: `type:OSINT`},
		},
		Attribute: []MISPAttribute{},
	}

	seen := make(map[string]bool)
	for _, ioc := range iocs {
		if ioc == nil || ioc.Value == "" {
			continue
		}
		mtype, category, toIDS, ok := mispAttr(ioc)
		if !ok {
			continue
		}
		key := mtype + "\x00" + ioc.Value
		if seen[key] {
			continue
		}
		seen[key] = true

		comment := fmt.Sprintf("QPot/%s", instance)
		if ioc.Honeypot != "" {
			comment += " via " + ioc.Honeypot
		}
		if ioc.Count > 0 {
			comment += fmt.Sprintf(" (count %d)", ioc.Count)
		}
		if !ioc.LastSeen.IsZero() {
			comment += " last_seen " + ioc.LastSeen.UTC().Format(time.RFC3339)
		}

		ev.Attribute = append(ev.Attribute, MISPAttribute{
			Type:     mtype,
			Category: category,
			Value:    ioc.Value,
			ToIDS:    toIDS,
			Comment:  comment,
		})
	}

	return MISPExport{Event: ev}
}
