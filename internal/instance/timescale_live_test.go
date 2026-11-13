package instance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// timescaleLive connects to the TimescaleDB server QPOT_TEST_PG_* names and
// gives it the production schema, twice over, on an empty database. It skips
// unless QPOT_TEST_TIMESCALE=1. The server must be TimescaleDB itself (the
// pinned image): the schema is a hypertable with a continuous aggregate.
func timescaleLive(t *testing.T) (*config.DatabaseConfig, *pgx.Conn, *database.TimescaleDB) {
	t.Helper()
	if os.Getenv("QPOT_TEST_TIMESCALE") != "1" {
		t.Skip("set QPOT_TEST_TIMESCALE=1 (and QPOT_TEST_PG_*) to run against a real TimescaleDB")
	}
	env := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return def
	}
	port, err := strconv.Atoi(env("QPOT_TEST_PG_PORT", "5432"))
	if err != nil {
		t.Fatalf("QPOT_TEST_PG_PORT: %v", err)
	}
	dbc := &config.DatabaseConfig{Type: "timescaledb", Host: env("QPOT_TEST_PG_HOST", "127.0.0.1"), Port: port,
		Username: env("QPOT_TEST_PG_USER", "postgres"), Password: env("QPOT_TEST_PG_PASS", "postgres"),
		Database: env("QPOT_TEST_PG_DB", "qpot_test"), SSLMode: "disable"}
	ctx := t.Context()
	dsn := (&url.URL{Scheme: "postgres", User: url.UserPassword(dbc.Username, dbc.Password),
		Host: net.JoinHostPort(dbc.Host, strconv.Itoa(dbc.Port)), Path: "/" + dbc.Database, RawQuery: "sslmode=disable"}).String()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	for _, q := range []string{
		"DROP MATERIALIZED VIEW IF EXISTS events_hourly CASCADE",
		"DROP VIEW IF EXISTS events_ingest CASCADE",
		"DROP TABLE IF EXISTS events CASCADE",
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	ts, err := database.NewTimescaleDB(dbc)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { ts.Close() })
	// Every start runs it again: the second run must find nothing to do.
	for run := 1; run <= 2; run++ {
		if err := ts.InitializeSchema(ctx); err != nil {
			t.Fatalf("InitializeSchema, run %d: %v", run, err)
		}
	}
	// What the collector inserts into, what stores a batch sent twice once,
	// and what the worker's batch query is answered from.
	for _, object := range []string{"events_ingest", "idx_events_observation", "idx_events_unclassified"} {
		var found int
		if err := conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_views WHERE viewname = $1) +
			(SELECT count(*) FROM pg_indexes WHERE tablename = 'events' AND indexname = $1)`, object).Scan(&found); err != nil || found != 1 {
			t.Fatalf("the production schema has %d of %s (%v)", found, object, err)
		}
	}
	return dbc, conn, ts
}

// runCollectorIntoTimescale runs the real collector over lines ("<file>\t<log
// line>" each) with the transforms and the database sink of the configuration
// QPot generates, the sink pointed at the test server, and returns what the
// collector logged.
func runCollectorIntoTimescale(t *testing.T, dbc *config.DatabaseConfig, mut func(*config.Config), lines []string) string {
	t.Helper()
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker is not available")
	}
	if exec.Command(docker, "image", "inspect", CollectorImage).Run() != nil {
		t.Skip("the collector image is not present locally")
	}
	out := genVectorCfg(t, func(c *config.Config) {
		c.Database.Type = "timescaledb"
		if mut != nil {
			mut(c)
		}
	})
	var generated struct {
		Transforms map[string]map[string]any `yaml:"transforms"`
		Sinks      map[string]map[string]any `yaml:"sinks"`
	}
	if err := yaml.Unmarshal([]byte(out), &generated); err != nil {
		t.Fatalf("the generated collector configuration is not YAML: %v", err)
	}
	sink := generated.Sinks["timescaledb"]
	if sink == nil || fmt.Sprint(sink["inputs"]) != "[pg_prepare]" || sink["table"] != "events_ingest" {
		t.Fatalf("the generated database sink is not what this test drives: %v", sink)
	}
	sink["endpoint"] = (&url.URL{Scheme: "postgres", User: url.UserPassword(dbc.Username, dbc.Password),
		Host: net.JoinHostPort(dbc.Host, strconv.Itoa(dbc.Port)), Path: "/" + dbc.Database}).String()
	transforms := map[string]any{
		"split": map[string]any{"type": "remap", "inputs": []string{"in"},
			"source": "parts = split(string!(.message), \"\\t\", 2)\n.file = parts[0]\n.message = parts[1]\n"},
	}
	previous := "split"
	for _, name := range []string{"add_qpot_metadata", "tag_scanners", "pg_prepare"} {
		source, _ := generated.Transforms[name]["source"].(string)
		if source == "" {
			t.Fatalf("the generated configuration has no %s step", name)
		}
		transforms[name] = map[string]any{"type": "remap", "inputs": []string{previous}, "source": source}
		previous = name
	}
	dir := t.TempDir()
	harness, err := yaml.Marshal(map[string]any{
		"data_dir":   "/tmp",
		"sources":    map[string]any{"in": map[string]any{"type": "stdin"}},
		"transforms": transforms,
		"sinks":      map[string]any{"timescaledb": sink},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "vector.yaml")
	if err := os.WriteFile(cfgPath, harness, 0o644); err != nil {
		t.Fatal(err)
	}
	// The server listens on this host: the collector shares its network, as
	// it shares the instance's with the database in production.
	cmd := exec.Command(docker, "run", "--rm", "-i", "--network", "host", "-v", dir+":"+dir+":ro", CollectorImage, "--config", cfgPath)
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Run(); err != nil {
		t.Fatalf("the collector failed: %v\n%s", err, log.String())
	}
	return log.String()
}

// TestTimescaleCollectorStoresHostileEventsLive sends, in one batch, plain
// events and events PostgreSQL cannot store as they are through the real
// collector into a real TimescaleDB with the production schema.
//
// PostgreSQL refuses a whole batch for one such value, and the collector then
// drops the batch. On a live instance a visitor who ran "echo a\0b" in cowrie
// (one NUL character) removed 103 events from the database, among them every
// connection other sources made in the same five seconds. Every event of the
// batch must be stored, the hostile ones with the unstorable part removed
// (the payload column is bytes, and keeps every byte).
func TestTimescaleCollectorStoresHostileEventsLive(t *testing.T) {
	dbc, conn, ts := timescaleLive(t)
	ctx := t.Context()

	// The JSON escape of NUL, built here so that no editor or tool ever
	// holds the character itself.
	nul := "\\" + "u0000"
	// Not compressible: an index entry may not be compressed below its limit.
	var long strings.Builder
	for i := 0; long.Len() < 12000; i++ {
		sum := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		long.WriteString(hex.EncodeToString(sum[:]))
	}
	const cowrie = "/data/honeypots/cowrie/logs/cowrie.json\t"
	const hellpot = "/data/honeypots/hellpot/logs/hellpot.log\t"
	lines := []string{
		cowrie + `{"eventid":"cowrie.session.connect","src_ip":"203.0.113.1","src_port":40001,"dst_port":22,"session":"plain1","protocol":"ssh"}`,
		// What cowrie wrote for "echo a\0b; uname -a" on the live instance.
		cowrie + `{"eventid":"cowrie.command.input","input":"echo a` + nul + `b; uname -a","message":"CMD: echo a` + nul + `b; uname -a","src_ip":"203.0.113.2","session":"nulcmd","protocol":"ssh"}`,
		cowrie + `{"eventid":"cowrie.login.failed","username":"ro` + nul + `ot","password":"pa` + nul + `ss","src_ip":"203.0.113.3","session":"nullogin","protocol":"ssh"}`,
		cowrie + `{"eventid":"cowrie.client.version","version":"SSH-2.0-a` + nul + `b","src_ip":"203.0.113.4","session":"nul` + nul + `meta","protocol":"s` + nul + `sh"}`,
		// A key and a value no column takes: the sink used to send them too.
		cowrie + `{"eventid":"cowrie.session.connect","src_ip":"203.0.113.5","session":"nulraw","we` + nul + `ird":"x` + nul + `y","nested":{"deep` + nul + `":["` + nul + `"]}}`,
		// A name too long for an index entry, and a URL that is the payload.
		cowrie + `{"eventid":"` + long.String() + `","src_ip":"203.0.113.6","session":"longname","url":"http://198.51.100.9/` + nul + `x"}`,
		cowrie + `{"eventid":"cowrie.session.connect","src_ip":"203.0.113.7","src_port":1e30,"dst_port":-5,"session":"oddports"}`,
		hellpot + `{"level":"info","USERAGENT":"x","REMOTE_ADDR":"203.0.113.8","URL":"/.env` + nul + `","time":"2026-11-02T08:47:50Z","message":"NEW"}`,
		// Fields no column takes, nested deep and with numbers past every range.
		cowrie + `{"eventid":"cowrie.session.connect","src_ip":"203.0.113.10","session":"deep","blob":` + strings.Repeat("[", 100) + strings.Repeat("]", 100) + `,"big":123456789012345678901234567890,"neg":-1e308,"tiny":1e-320}`,
		// A line whose own fields carry the names of the stored columns, with
		// types none of them holds.
		cowrie + `{"eventid":"cowrie.session.connect","src_ip":"203.0.113.11","session":"colliding","timestamp":{"a":1},"honeypot":["x"],"source_ip":5,"source_port":"x","dest_port":[],"payload":{"k":1},"command":7,"username":["a"],"password":{"p":1},"protocol":9,"event_type":{"e":1},"country":5,"city":[1],"asn":{"a":1},"metadata":"str","categories":"x","confidence":"high","classified":"yes","technique_id":5,"event_id":7}`,
		cowrie + `{"eventid":"cowrie.session.connect","src_ip":"203.0.113.9","src_port":40009,"dst_port":22,"session":"plain2","protocol":"ssh"}`,
	}
	log := runCollectorIntoTimescale(t, dbc, func(c *config.Config) {
		hp := c.Honeypots["hellpot"]
		hp.Enabled = true
		c.Honeypots["hellpot"] = hp
	}, lines)
	if strings.Contains(log, "dropping the request") || strings.Contains(log, "Events dropped") {
		t.Errorf("the collector dropped events:\n%s", log)
	}

	type stored struct {
		eventType, user, pass, command, payload, session, version, protocol string
		sourcePort, destPort                                                int
		id                                                                  *string
	}
	got := map[string]stored{}
	rows, err := conn.Query(ctx, `SELECT host(source_ip), event_type, COALESCE(username, ''), COALESCE(password, ''),
		COALESCE(command, ''), payload, COALESCE(metadata->>'session', ''),
		COALESCE(metadata->>'version', ''), COALESCE(protocol, ''), source_port, dest_port, event_id::text FROM events`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var ip string
		var s stored
		var payload []byte
		if err := rows.Scan(&ip, &s.eventType, &s.user, &s.pass, &s.command, &payload, &s.session, &s.version, &s.protocol, &s.sourcePort, &s.destPort, &s.id); err != nil {
			t.Fatal(err)
		}
		s.payload = string(payload)
		got[ip] = s
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(lines) {
		t.Fatalf("%d of %d events were stored: %v\ncollector output:\n%s", len(got), len(lines), got, log)
	}
	for ip, s := range got {
		if s.id == nil || !eventUUID.MatchString(*s.id) {
			t.Errorf("%s has no observation ID: %v", ip, s.id)
		}
	}
	if s := got["203.0.113.1"]; s.eventType != "cowrie.session.connect" || s.session != "plain1" || s.sourcePort != 40001 || s.destPort != 22 {
		t.Errorf("the plain event before the hostile ones: %+v", s)
	}
	if s := got["203.0.113.9"]; s.session != "plain2" || s.sourcePort != 40009 {
		t.Errorf("the plain event after the hostile ones: %+v", s)
	}
	if s := got["203.0.113.2"]; s.command != "echo ab; uname -a" {
		t.Errorf("the command holding a NUL is stored as %q, want it without the NUL", s.command)
	}
	if s := got["203.0.113.3"]; s.user != "root" || s.pass != "pass" {
		t.Errorf("the login holding NULs is stored as %q / %q", s.user, s.pass)
	}
	if s := got["203.0.113.4"]; s.version != "SSH-2.0-ab" || s.session != "nulmeta" || s.protocol != "ssh" {
		t.Errorf("metadata and protocol holding NULs: %+v", s)
	}
	if s := got["203.0.113.5"]; s.session != "nulraw" {
		t.Errorf("the event with a NUL in fields no column takes: %+v", s)
	}
	if s := got["203.0.113.6"]; len(s.eventType) != 256 || !strings.HasPrefix(long.String(), s.eventType) || s.payload != "http://198.51.100.9/\x00x" {
		t.Errorf("the event with an over-long name: type of %d bytes, payload %q", len(s.eventType), s.payload)
	}
	if s := got["203.0.113.7"]; s.sourcePort != 0 || s.destPort != 0 {
		t.Errorf("ports no port column holds are stored as %d and %d, want 0", s.sourcePort, s.destPort)
	}
	if s := got["203.0.113.10"]; s.session != "deep" || s.eventType != "cowrie.session.connect" {
		t.Errorf("the event with deep and out-of-range fields no column takes: %+v", s)
	}
	if s := got["203.0.113.11"]; s.session != "colliding" || s.eventType != "cowrie.session.connect" || s.user != "" || s.command != "" || s.protocol != "" {
		t.Errorf("the event whose own fields carry the stored columns' names: %+v", s)
	}
	if s := got["203.0.113.8"]; s.payload != "/.env\x00" || s.eventType != "hellpot.new" {
		t.Errorf("the hellpot request holding a NUL: %+v", s)
	}

	// What the dashboard and the worker read must be readable too.
	events, err := ts.GetUnclassifiedEvents(ctx, 100)
	if err != nil || len(events) != len(lines) {
		t.Fatalf("GetUnclassifiedEvents = %d events, %v", len(events), err)
	}
	if listed, err := ts.GetEvents(ctx, database.EventFilter{Limit: 100}); err != nil || len(listed) != len(lines) {
		t.Fatalf("GetEvents = %d events, %v", len(listed), err)
	}

	// The same lines again are the same observations: the worker's sweep
	// keeps one row of each, whatever the collector's second reading stored.
	time.Sleep(10 * time.Millisecond)
	runCollectorIntoTimescale(t, dbc, func(c *config.Config) {
		hp := c.Honeypots["hellpot"]
		hp.Enabled = true
		c.Honeypots["hellpot"] = hp
	}, lines)
	var total, distinct int
	if err := conn.QueryRow(ctx, "SELECT count(*), count(DISTINCT event_id) FROM events").Scan(&total, &distinct); err != nil {
		t.Fatal(err)
	}
	if distinct != len(lines) || total < distinct {
		t.Fatalf("after a second reading: %d rows of %d observations, want %d observations", total, distinct, len(lines))
	}
	again, err := ts.GetUnclassifiedEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, removed, err := ts.RemoveReplayedEvents(ctx, again); err != nil || removed != total-distinct {
		t.Fatalf("RemoveReplayedEvents removed %d rows, %v; want %d", removed, err, total-distinct)
	}
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM events").Scan(&total); err != nil || total != len(lines) {
		t.Fatalf("%d rows left after the sweep, %v; want %d", total, err, len(lines))
	}
}
