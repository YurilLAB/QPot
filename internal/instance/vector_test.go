package instance

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

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
	// the sensor_id assignment must come after the merge() call.
	mergeIdx := strings.Index(out, "merge(")
	idIdx := strings.Index(out, ".sensor_id =")
	if mergeIdx < 0 || idIdx < 0 || idIdx < mergeIdx {
		t.Error("sensor_id/timestamp must be stamped after the JSON merge to avoid clobbering")
	}
}

// A honeypot log line is attacker-controlled and merged into the event, and
// the ClickHouse sink stores any key that names a column. Every column the
// intelligence worker owns must be deleted after that merge, or a line could
// plant its own classification (or, with a wrongly typed categories value,
// fail the whole insert batch).
func TestVectorDropsWorkerOwnedFields(t *testing.T) {
	out := genVector(t, "clickhouse")
	merge := strings.Index(out, "merge(")
	for _, f := range []string{"event_id", "technique_id", "technique_name", "tactic_id", "tactic_name",
		"kill_chain_stage", "confidence", "classified", "categories"} {
		at := strings.Index(out, "del(."+f+")")
		if at < 0 || at < merge {
			t.Errorf("the honeypot remap does not delete .%s after merging the log line", f)
		}
	}
}

// TestVectorTimescaleSink pins the postgres sink shape that actually inserts:
// Vector's postgres sink has no `encoding` option (an encoding block makes the
// whole collector config invalid), and it writes NULL for every column it is
// not given, so it must target the events_ingest view (defaults apply) and
// receive the hex-encoded payload from pg_prepare.
func TestVectorTimescaleSink(t *testing.T) {
	out := genVector(t, "timescaledb")
	start := strings.Index(out, "  timescaledb:\n    type: postgres")
	if start < 0 {
		t.Fatal("no timescaledb sink")
	}
	block := out[start:]
	if end := strings.Index(block, "batch:"); end > 0 {
		block = block[:end]
	}
	if strings.Contains(block, "encoding:") || strings.Contains(block, "only_fields") {
		t.Error("postgres sink carries an encoding block Vector rejects")
	}
	if !strings.Contains(block, "table: events_ingest") {
		t.Error("postgres sink does not target the events_ingest view")
	}
	if !strings.Contains(block, "- pg_prepare") {
		t.Error("postgres sink is not fed by pg_prepare")
	}
	if !strings.Contains(out, `encode_base16(`) {
		t.Error("payload is not hex-encoded for BYTEA")
	}
	if ch := genVector(t, "clickhouse"); strings.Contains(ch, "pg_prepare") {
		t.Error("pg_prepare emitted for the clickhouse backend")
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
	// With GeoIP off, Suricata events join the scanner tag directly.
	fs := out[strings.Index(out, "tag_scanners:"):]
	fs = fs[:strings.Index(fs, "source:")]
	if !strings.Contains(fs, "- suricata_events") {
		t.Error("tag_scanners should take suricata_events as input when GeoIP is off")
	}
	// Suricata alerts name scanners in rule text: they are not tagged.
	if !strings.Contains(out, `sensor != "suricata"`) {
		t.Error("the scanner tag must skip Suricata IDS alerts")
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
	fs := out[strings.Index(out, "tag_scanners:"):]
	fs = fs[:strings.Index(fs, "source:")]
	if strings.Contains(fs, "- suricata_events") {
		t.Error("suricata_events must not feed tag_scanners directly when GeoIP is on (double ingest)")
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
	// All three sensors join the scanner tag directly (GeoIP off).
	fs := out[strings.Index(out, "tag_scanners:"):]
	fs = fs[:strings.Index(fs, "source:")]
	for _, s := range []string{"- suricata_events", "- p0f_events", "- fatt_events"} {
		if !strings.Contains(fs, s) {
			t.Errorf("tag_scanners missing sensor input %q (GeoIP off)", s)
		}
	}
	// No NSM sensor event is tagged.
	for _, s := range []string{`sensor != "suricata"`, `sensor != "p0f"`, `sensor != "fatt"`} {
		if !strings.Contains(out, s) {
			t.Errorf("the scanner tag must skip sensor events (%s)", s)
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
	fs := out[strings.Index(out, "tag_scanners:"):]
	fs = fs[:strings.Index(fs, "source:")]
	if strings.Contains(fs, "- p0f_events") || strings.Contains(fs, "- fatt_events") {
		t.Error("sensors must not feed tag_scanners directly when GeoIP is on (double ingest)")
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
		t.Error("tag_scanners should feed from add_qpot_metadata when GeoIP is off")
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
		t.Error("tag_scanners should feed from enrich_geoip when GeoIP is on")
	}
}

// Docker client proxy defaults must never send internal event batches to an
// external HTTP proxy. Generated ClickHouse config fixes the internal endpoint.
func TestVectorClickHouseDatabaseStaysInternal(t *testing.T) {
	out := genVector(t, "clickhouse")
	var cfg struct {
		Sinks map[string]struct {
			Endpoint string `yaml:"endpoint"`
			Proxy    struct {
				Enabled *bool `yaml:"enabled"`
			} `yaml:"proxy"`
		} `yaml:"sinks"`
	}
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatal(err)
	}
	sink := cfg.Sinks["clickhouse"]
	if sink.Endpoint != "http://database:8123" || sink.Proxy.Enabled == nil || *sink.Proxy.Enabled {
		t.Fatalf("internal ClickHouse requests can inherit an external proxy: %+v", sink)
	}
}
