package database

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// chMaxQuerySize is ClickHouse's default max_query_size. The server refuses
// to parse a longer statement (code 62), and only INSERT data after VALUES is
// exempt. clickhouse-go binds "?" arguments into the statement text on the
// client, so every bound value counts.
const chMaxQuerySize = 262144

// sizeLimitedConn stands in for a ClickHouse server that enforces the default
// max_query_size on queries and mutations. It sizes a statement the way
// clickhouse-go renders it: a string is quoted with ' and \ escaped, and a
// slice becomes a comma-separated list.
type sizeLimitedConn struct {
	driver.Conn
	sizes  []int
	batch  *countingBatch
	stored map[string]uint64 // value -> stored count of a ("ip", value, "cowrie") row
}

func renderedSize(query string, args ...any) int {
	n := len(query)
	for _, a := range args {
		switch v := a.(type) {
		case string:
			n += len(v) + 2 + strings.Count(v, `\`) + strings.Count(v, `'`)
		case []string:
			for _, s := range v {
				n += len(s) + 4 + strings.Count(s, `\`) + strings.Count(s, `'`)
			}
		case []float64:
			n += 24 * len(v)
		default:
			n += 24
		}
	}
	return n
}

func (c *sizeLimitedConn) check(query string, args ...any) error {
	n := renderedSize(query, args...)
	c.sizes = append(c.sizes, n)
	if n > chMaxQuerySize {
		return fmt.Errorf("code: 62, message: Max query size exceeded (%d bytes)", n)
	}
	return nil
}

func (c *sizeLimitedConn) Query(_ context.Context, query string, args ...any) (driver.Rows, error) {
	if err := c.check(query, args...); err != nil {
		return nil, err
	}
	r := &storedRows{}
	if vs, ok := args[0].([]string); ok {
		for _, v := range vs {
			if n, ok := c.stored[v]; ok {
				r.rows = append(r.rows, storedRow{v, n})
			}
		}
	}
	return r, nil
}

type storedRow struct {
	value string
	count uint64
}

// storedRows answers the fold SELECT with ("ip", value, "cowrie") rows.
type storedRows struct {
	driver.Rows
	rows []storedRow
	i    int
}

func (r *storedRows) Next() bool { r.i++; return r.i <= len(r.rows) }
func (r *storedRows) Scan(dest ...any) error {
	row := r.rows[r.i-1]
	*dest[0].(*string), *dest[1].(*string), *dest[2].(*string) = "ip", row.value, "cowrie"
	*dest[3].(*time.Time), *dest[4].(*time.Time) = time.Unix(0, 0).UTC(), time.Unix(0, 0).UTC()
	*dest[5].(*uint64), *dest[6].(*string) = row.count, ""
	return nil
}
func (r *storedRows) Err() error   { return nil }
func (r *storedRows) Close() error { return nil }

func (c *sizeLimitedConn) Exec(_ context.Context, query string, args ...any) error {
	return c.check(query, args...)
}

func (c *sizeLimitedConn) PrepareBatch(context.Context, string, ...driver.PrepareBatchOption) (driver.Batch, error) {
	c.batch = &countingBatch{}
	return c.batch, nil
}

type countingBatch struct {
	driver.Batch
	rows   int
	sent   bool
	counts map[string]int64 // value -> count written
}

func (b *countingBatch) Append(v ...any) error {
	b.rows++
	if b.counts == nil {
		b.counts = map[string]int64{}
	}
	b.counts[v[1].(string)+":"+v[2].(string)] = v[8].(int64)
	return nil
}
func (b *countingBatch) Send() error { b.sent = true; return nil }

// Split into several SELECTs, every stored sighting must still be folded in
// exactly once: a value read by two chunks would be counted twice. The same
// value under two IOC types (as an ip and a url here) reaches the fold twice.
func TestClickHouseFoldAcrossChunksCountsOnce(t *testing.T) {
	conn := &sizeLimitedConn{stored: map[string]uint64{}}
	ch := &ClickHouse{conn: conn}
	now := time.Now().UTC()
	var iocs []*IOC
	for i := 0; i < 3000; i++ {
		v := fmt.Sprintf("198.51.%d.%d", i/250, i%250) + strings.Repeat("x", 100)
		conn.stored[v] = 5
		for _, typ := range []string{"ip", "ip", "url"} { // two ip sightings, one url
			iocs = append(iocs, &IOC{ID: typ + ":" + v + ":cowrie", Type: typ, Value: v, Honeypot: "cowrie", FirstSeen: now, LastSeen: now, Count: 1})
		}
	}
	if err := ch.InsertIOCs(context.Background(), iocs); err != nil {
		t.Fatalf("InsertIOCs: %v", err)
	}
	if len(conn.sizes) < 2 {
		t.Fatalf("%d fold queries, want the values split across several", len(conn.sizes))
	}
	for k, c := range conn.batch.counts {
		want := int64(1)
		if strings.HasPrefix(k, "ip:") {
			want = 7 // 5 stored + 2 new
		}
		if c != want {
			t.Fatalf("%s written with count %d, want %d", k, c, want)
		}
	}
	if len(conn.batch.counts) != 6000 {
		t.Fatalf("%d indicators written, want 6000", len(conn.batch.counts))
	}
}

// The worker writes a cycle's IOCs in one call, and foldStoredIOCs bound every
// value into a single "value IN ?" SELECT. Attacker commands are IOC values
// (Vector passes log lines up to 100 KiB), so three long commands in one cycle
// took the statement past max_query_size: the SELECT failed and every IOC of
// the cycle, other attackers' included, was dropped.
func TestClickHouseInsertIOCsStaysUnderMaxQuerySize(t *testing.T) {
	conn := &sizeLimitedConn{}
	ch := &ClickHouse{conn: conn}
	now := time.Now().UTC()
	var iocs []*IOC
	for i := 0; i < 3; i++ {
		v := fmt.Sprintf("echo %d '", i) + strings.Repeat("f0VMRgIBAQ", 9000) + "' | base64 -d > /tmp/x"
		iocs = append(iocs, &IOC{ID: "command:" + v + ":cowrie", Type: "command", Value: v, Honeypot: "cowrie", FirstSeen: now, LastSeen: now, Count: 1})
	}
	for i := 0; i < 500; i++ {
		v := fmt.Sprintf("198.51.%d.%d", i/250, i%250)
		iocs = append(iocs, &IOC{ID: "ip:" + v + ":cowrie", Type: "ip", Value: v, Honeypot: "cowrie", FirstSeen: now, LastSeen: now, Count: 1})
	}
	if err := ch.InsertIOCs(context.Background(), iocs); err != nil {
		t.Fatalf("InsertIOCs: %v", err)
	}
	if conn.batch == nil || !conn.batch.sent || conn.batch.rows != len(iocs) {
		t.Fatalf("batch = %+v, want all %d IOCs sent", conn.batch, len(iocs))
	}
	for _, n := range conn.sizes {
		if n > chMaxQuerySize {
			t.Errorf("a %d-byte statement was sent", n)
		}
	}
}

// TagEvents tagged up to 1000 events per mutation. Every event id appears
// seven times in that statement (six transform() maps and the IN list), about
// 400 bytes per event, so a worker batch over ~650 events (worker_batch_size
// is configurable) exceeded max_query_size. Tagging then failed on every
// cycle: the same events came back each time, were never marked classified,
// and had their IOCs counted again.
func TestClickHouseTagEventsStaysUnderMaxQuerySize(t *testing.T) {
	conn := &sizeLimitedConn{}
	ch := &ClickHouse{conn: conn}
	now := time.Now().UTC()
	events := make([]*Event, 1000)
	for i := range events {
		events[i] = &Event{
			ID:          fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i),
			Timestamp:   now.Add(time.Duration(i) * time.Millisecond),
			TechniqueID: "T1110.001", TechniqueName: "Brute Force: Password Guessing",
			TacticID: "TA0006", TacticName: "Credential Access", KillChainStage: "initial-access",
			Confidence: 0.85,
		}
	}
	if err := ch.TagEvents(context.Background(), events); err != nil {
		t.Fatalf("TagEvents: %v", err)
	}
	for _, n := range conn.sizes {
		if n > chMaxQuerySize {
			t.Errorf("a %d-byte mutation was sent", n)
		}
	}
}
