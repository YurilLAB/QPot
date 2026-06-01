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
