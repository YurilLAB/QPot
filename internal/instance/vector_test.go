package instance

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

func genVector(t *testing.T, dbType string) string {
	t.Helper()
	cfg := config.Default("vec-test")
	cfg.QPotID = "qp_vectorvectorvectorvecto"
	cfg.Database.Type = dbType
	for _, n := range []string{"cowrie"} {
		hp := cfg.Honeypots[n]
		hp.Enabled = true
		cfg.Honeypots[n] = hp
	}
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	g := &ComposeGenerator{Config: cfg, Sandbox: sb}
	out, err := g.GenerateVectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestVectorClickHouseDataPathCorrectness asserts the schema-correctness fixes
// in the ClickHouse data path (the default backend).
func TestVectorClickHouseDataPathCorrectness(t *testing.T) {
	out := genVector(t, "clickhouse")

	// The enriched event carries non-column fields; ClickHouse must be told to
	// skip them or every insert fails on the first unknown column.
	if !strings.Contains(out, "skip_unknown_fields: true") {
		t.Error("clickhouse sink missing skip_unknown_fields: true")
	}
	// The pipeline must set honeypot and event_type (required / used in GROUP BY).
	if !strings.Contains(out, ".honeypot =") {
		t.Error("vector pipeline never sets .honeypot")
	}
	if !strings.Contains(out, ".event_type =") {
		t.Error("vector pipeline never sets .event_type")
	}
	// Metadata must be stamped AFTER the JSON merge so it can't be clobbered:
	// the qpot_id assignment must come after the merge() call.
	mergeIdx := strings.Index(out, "merge(")
	idIdx := strings.LastIndex(out, ".qpot_id =")
	if mergeIdx < 0 || idIdx < 0 || idIdx < mergeIdx {
		t.Error("qpot_id/timestamp must be stamped after the JSON merge to avoid clobbering")
	}
}

// TestVectorTimescaleHasNoPhantomColumns guards that qpot_id/qpot_instance —
// which are NOT columns in the events table — are not in the postgres sink's
// only_fields (they broke the INSERT).
func TestVectorTimescaleHasNoPhantomColumns(t *testing.T) {
	out := genVector(t, "timescaledb")
	// Look only at the only_fields block.
	start := strings.Index(out, "only_fields:")
	if start < 0 {
		t.Skip("no only_fields block")
	}
	block := out[start:]
	end := strings.Index(block, "batch:")
	if end > 0 {
		block = block[:end]
	}
	for _, phantom := range []string{"- qpot_id", "- qpot_instance"} {
		if strings.Contains(block, phantom) {
			t.Errorf("timescale only_fields still lists phantom column %q", phantom)
		}
	}
	if !strings.Contains(block, "- honeypot") {
		t.Error("timescale only_fields missing required honeypot column")
	}
}

func genVectorCfg(t *testing.T, mut func(*config.Config)) string {
	t.Helper()
	cfg := config.Default("vec-test")
	cfg.QPotID = "qp_vectorvectorvectorvecto"
	hp := cfg.Honeypots["cowrie"]
	hp.Enabled = true
	cfg.Honeypots["cowrie"] = hp
	if mut != nil {
		mut(cfg)
	}
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).GenerateVectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestVectorSuricataIngestion verifies T-Pot's Suricata EVE alerts are ingested
// into the same events store (so they show up in QPot's dashboards/attack map),
// mapped onto the shared schema, with only alert events kept.
func TestVectorSuricataIngestion(t *testing.T) {
	out := genVectorCfg(t, nil) // IngestSuricata defaults true, GeoIP off
	for _, want := range []string{
		"suricata_eve:",
		"/data/suricata/log/eve.json",
		"suricata_events:",
		`.honeypot = "suricata"`,
		`!= "alert"`, // non-alert events dropped
		"abort",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("vector config missing Suricata marker %q", want)
		}
	}
	// With GeoIP off, Suricata events join the stealth filter directly.
	fs := out[strings.Index(out, "filter_stealth:"):]
	fs = fs[:strings.Index(fs, "condition:")]
	if !strings.Contains(fs, "- suricata_events") {
		t.Error("filter_stealth should take suricata_events as input when GeoIP is off")
	}
	// Suricata alerts must bypass the stealth probe-drop.
	if !strings.Contains(out, `sensor == "suricata"`) {
		t.Error("stealth filter must never drop Suricata IDS alerts")
	}
}

// TestVectorSuricataWithGeoIP verifies Suricata events are geo-enriched (joined
// at enrich_geoip) rather than added a second time at the filter.
func TestVectorSuricataWithGeoIP(t *testing.T) {
	out := genVectorCfg(t, func(c *config.Config) {
		c.Collector.GeoIPDBPath = "/usr/share/GeoIP/GeoLite2-City.mmdb"
	})
	eg := out[strings.Index(out, "enrich_geoip:"):]
	eg = eg[:strings.Index(eg, "source:")]
	if !strings.Contains(eg, "- suricata_events") {
		t.Error("enrich_geoip should geo-enrich suricata_events when GeoIP is on")
	}
	// It must not ALSO be added directly at the filter (it arrives via geoip).
	fs := out[strings.Index(out, "filter_stealth:"):]
	fs = fs[:strings.Index(fs, "condition:")]
	if strings.Contains(fs, "- suricata_events") {
		t.Error("suricata_events must not feed filter_stealth directly when GeoIP is on (double ingest)")
	}
}

// TestVectorP0fFattIngestion verifies p0f and fatt NSM sensors are ingested and
// mapped onto the events schema, joining the same downstream as honeypot logs.
func TestVectorP0fFattIngestion(t *testing.T) {
	out := genVectorCfg(t, nil) // p0f + fatt default on, GeoIP off
	for _, want := range []string{
		"p0f_log:", "/data/p0f/log/p0f.json", "p0f_events:",
		`.honeypot = "p0f"`, `.source_ip = to_string(.client_ip)`,
		"fatt_log:", "/data/fatt/log/fatt.log", "fatt_events:",
		`.honeypot = "fatt"`, `.source_ip = to_string(.sourceIp)`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("vector config missing p0f/fatt marker %q", want)
		}
	}
	// All three sensors join the stealth filter directly (GeoIP off).
	fs := out[strings.Index(out, "filter_stealth:"):]
	fs = fs[:strings.Index(fs, "condition:")]
	for _, s := range []string{"- suricata_events", "- p0f_events", "- fatt_events"} {
		if !strings.Contains(fs, s) {
			t.Errorf("filter_stealth missing sensor input %q (GeoIP off)", s)
		}
	}
	// All NSM sensors bypass the stealth probe-drop.
	for _, s := range []string{`sensor == "suricata"`, `sensor == "p0f"`, `sensor == "fatt"`} {
		if !strings.Contains(out, s) {
			t.Errorf("stealth filter must never drop sensor %q", s)
		}
	}
}

// TestVectorSensorsGeoIP verifies all NSM sensors are geo-enriched at
// enrich_geoip (and not double-added at the filter) when GeoIP is on.
func TestVectorSensorsGeoIP(t *testing.T) {
	out := genVectorCfg(t, func(c *config.Config) {
		c.Collector.GeoIPDBPath = "/usr/share/GeoIP/GeoLite2-City.mmdb"
	})
	eg := out[strings.Index(out, "enrich_geoip:"):]
	eg = eg[:strings.Index(eg, "source:")]
	for _, s := range []string{"- suricata_events", "- p0f_events", "- fatt_events"} {
		if !strings.Contains(eg, s) {
			t.Errorf("enrich_geoip missing sensor input %q", s)
		}
	}
	fs := out[strings.Index(out, "filter_stealth:"):]
	fs = fs[:strings.Index(fs, "condition:")]
	if strings.Contains(fs, "- p0f_events") || strings.Contains(fs, "- fatt_events") {
		t.Error("sensors must not feed filter_stealth directly when GeoIP is on (double ingest)")
	}
}

// TestVectorAllSensorsDisabled verifies turning every NSM sensor off removes all
// their sources/transforms and leaves the filter fed only by the honeypot path.
func TestVectorAllSensorsDisabled(t *testing.T) {
	out := genVectorCfg(t, func(c *config.Config) {
		c.Collector.IngestSuricata = false
		c.Collector.IngestP0f = false
		c.Collector.IngestFatt = false
	})
	// The sensor sources/transforms and their inputs must be gone. (The stealth
	// bypass lists the sensor names unconditionally, which is harmless when no
	// such events exist, so it is not asserted here.)
	for _, marker := range []string{
		"suricata_eve", "suricata_events:", "p0f_log", "p0f_events:",
		"fatt_log", "fatt_events:", "/data/suricata", "/data/p0f", "/data/fatt",
		"- suricata_events", "- p0f_events", "- fatt_events",
	} {
		if strings.Contains(out, marker) {
			t.Errorf("sensor config present despite all sensors disabled: %q", marker)
		}
	}
}

// TestVectorSuricataDisabled verifies the Suricata source/transform vanish when
// ingestion is turned off.
func TestVectorSuricataDisabled(t *testing.T) {
	out := genVectorCfg(t, func(c *config.Config) { c.Collector.IngestSuricata = false })
	for _, marker := range []string{"suricata_eve", "suricata_events", "/data/suricata"} {
		if strings.Contains(out, marker) {
			t.Errorf("Suricata config present despite IngestSuricata=false: %q", marker)
		}
	}
}

// TestVectorGeoIPOptional verifies GeoIP enrichment is omitted unless a DB path
// is configured, so Vector starts without a MaxMind mmdb (its absence
// previously prevented the collector from starting at all).
func TestVectorGeoIPOptional(t *testing.T) {
	cfg := config.Default("geo-test")
	cfg.QPotID = "qp_geogeogeogeogeogeogeo1"
	for _, n := range []string{"cowrie"} {
		hp := cfg.Honeypots[n]
		hp.Enabled = true
		cfg.Honeypots[n] = hp
	}
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatal(err)
	}

	// Default: no GeoIP path -> no enrichment table / transform, filter feeds
	// directly from add_qpot_metadata.
	g := &ComposeGenerator{Config: cfg, Sandbox: sb}
	out, err := g.GenerateVectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "enrichment_tables:") || strings.Contains(out, "get_enrichment_table_record") {
		t.Error("GeoIP enrichment present despite no configured DB path")
	}
	if !strings.Contains(out, "- add_qpot_metadata") {
		t.Error("filter_stealth should feed from add_qpot_metadata when GeoIP is off")
	}

	// Configured: enrichment table + transform appear.
	cfg.Collector.GeoIPDBPath = "/usr/share/GeoIP/GeoLite2-City.mmdb"
	out2, err := g.GenerateVectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2, "enrichment_tables:") || !strings.Contains(out2, "get_enrichment_table_record") {
		t.Error("GeoIP enrichment missing despite configured DB path")
	}
	if !strings.Contains(out2, "- enrich_geoip") {
		t.Error("filter_stealth should feed from enrich_geoip when GeoIP is on")
	}
}
