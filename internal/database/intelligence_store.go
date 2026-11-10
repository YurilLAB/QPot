package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/qpot/qpot/internal/config"
)

var _ IntelligenceStore = (*ClickHouse)(nil)
var _ IntelligenceStore = (*TimescaleDB)(nil)
var _ IntelligenceStore = (*Elasticsearch)(nil)

func (ch *ClickHouse) initializeIntelligenceSchema(ctx context.Context) error {
	for _, query := range []string{`CREATE TABLE IF NOT EXISTS intelligence_checkpoint (id UInt8, revision UInt64, payload String) ENGINE = ReplacingMergeTree(revision) ORDER BY id`,
		`
		CREATE TABLE IF NOT EXISTS intelligence_iocs (
			revision UInt64,
			id String,
			type LowCardinality(String),
			value String,
			honeypot LowCardinality(String),
			source_ip String,
			technique_id String,
			first_seen DateTime64(3),
			last_seen DateTime64(3),
			count UInt64,
			metadata Map(String, String)
		) ENGINE = ReplacingMergeTree(revision)
		ORDER BY (type, value, honeypot)
	`, `
		CREATE TABLE IF NOT EXISTS intelligence_sessions (
			revision UInt64,
			session_id String,
			campaign_fingerprint String,
			source_ips Array(String),
			shared_infrastructure UInt8,
			kill_chain_stages Array(String),
			techniques Array(String),
			ioc_ids Array(String),
			event_count UInt64,
			first_seen DateTime64(3),
			last_seen DateTime64(3),
			confidence Float64
		) ENGINE = ReplacingMergeTree(revision)
		ORDER BY session_id
	`} {
		if err := ch.conn.Exec(ctx, query); err != nil {
			return fmt.Errorf("initialize intelligence: %w", err)
		}
	}
	return nil
}
func (ch *ClickHouse) LoadIntelligenceCheckpoint(ctx context.Context) (*IntelligenceCheckpoint, error) {
	if cp, handled, err := intelligenceLeaseLoad(ctx, ch); handled {
		return cp, err
	}
	return ch.loadLegacyIntelligenceCheckpoint(ctx)
}
func (ch *ClickHouse) loadLegacyIntelligenceCheckpoint(ctx context.Context) (*IntelligenceCheckpoint, error) {
	if ch.conn == nil {
		return nil, fmt.Errorf("not connected")
	}
	rows, err := ch.conn.Query(ctx, "SELECT payload FROM intelligence_checkpoint FINAL WHERE id = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var payload string
	if err = rows.Scan(&payload); err != nil {
		return nil, err
	}
	var cp IntelligenceCheckpoint
	if err = json.Unmarshal([]byte(payload), &cp); err != nil {
		return nil, err
	}
	return &cp, rows.Err()
}
func (ch *ClickHouse) SaveIntelligenceCheckpoint(ctx context.Context, cp *IntelligenceCheckpoint) error {
	if handled, err := intelligenceLeaseSave(ctx, ch, cp); handled {
		return err
	}
	return ch.saveLegacyIntelligenceCheckpoint(ctx, cp)
}
func (ch *ClickHouse) saveLegacyIntelligenceCheckpoint(ctx context.Context, cp *IntelligenceCheckpoint) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}
	payload, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	batch, err := ch.conn.PrepareBatch(ctx, "INSERT INTO intelligence_checkpoint (id, revision, payload)")
	if err != nil {
		return err
	}
	defer batch.Abort()
	if err = batch.Append(uint8(1), cp.Revision, string(payload)); err != nil {
		return err
	}
	return batch.Send()
}
func (ch *ClickHouse) ReplaceIntelligenceIOCs(ctx context.Context, revision uint64, iocs []*IOC) error {
	if _, leased := intelligenceLeaseFromContext(ctx); !leased && len(iocs) == 0 {
		return nil
	}
	approved, err := intelligenceLeaseIOCs(ctx, ch, revision, iocs)
	if err != nil {
		return err
	}
	return ch.replaceLegacyIntelligenceIOCs(ctx, revision, approved)
}
func (ch *ClickHouse) replaceLegacyIntelligenceIOCs(ctx context.Context, revision uint64, iocs []*IOC) error {
	if len(iocs) == 0 {
		return nil
	}
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}
	batch, err := ch.conn.PrepareBatch(ctx, "INSERT INTO intelligence_iocs")
	if err != nil {
		return err
	}
	defer batch.Abort()
	for _, i := range iocs {
		if err = batch.Append(revision, i.ID, i.Type, i.Value, i.Honeypot, i.SourceIP, i.TechniqueID, i.FirstSeen, i.LastSeen, uint64(i.Count), i.Metadata); err != nil {
			return err
		}
	}
	return batch.Send()
}
func (ch *ClickHouse) ReplaceIntelligenceSessions(ctx context.Context, revision uint64, sessions []*TTPSession) error {
	if _, leased := intelligenceLeaseFromContext(ctx); !leased && len(sessions) == 0 {
		return nil
	}
	approved, err := intelligenceLeaseSessions(ctx, ch, revision, sessions)
	if err != nil {
		return err
	}
	return ch.replaceLegacyIntelligenceSessions(ctx, revision, approved)
}
func (ch *ClickHouse) replaceLegacyIntelligenceSessions(ctx context.Context, revision uint64, sessions []*TTPSession) error {
	if len(sessions) == 0 {
		return nil
	}
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}
	batch, err := ch.conn.PrepareBatch(ctx, "INSERT INTO intelligence_sessions")
	if err != nil {
		return err
	}
	defer batch.Abort()
	for _, s := range sessions {
		if err = batch.Append(revision, s.SessionID, s.CampaignFingerprint, s.SourceIPs, s.SharedInfrastructure, s.KillChainStages, s.Techniques, s.IOCIDs, uint64(s.EventCount), s.FirstSeen, s.LastSeen, s.Confidence); err != nil {
			return err
		}
	}
	return batch.Send()
}
func (ts *TimescaleDB) initializeIntelligenceSchema(ctx context.Context) error {
	for _, query := range []string{`CREATE TABLE IF NOT EXISTS intelligence_checkpoint (id integer PRIMARY KEY CHECK (id=1), revision bigint NOT NULL, payload jsonb NOT NULL)`, `ALTER TABLE iocs ADD COLUMN IF NOT EXISTS intelligence_revision bigint NOT NULL DEFAULT 0`, `ALTER TABLE ttp_sessions ADD COLUMN IF NOT EXISTS intelligence_revision bigint NOT NULL DEFAULT 0`} {
		if _, err := ts.pool.Exec(ctx, query); err != nil {
			return err
		}
	}
	return nil
}
func (ts *TimescaleDB) LoadIntelligenceCheckpoint(ctx context.Context) (*IntelligenceCheckpoint, error) {
	if cp, handled, err := intelligenceLeaseLoad(ctx, ts); handled {
		return cp, err
	}
	return ts.loadLegacyIntelligenceCheckpoint(ctx)
}
func (ts *TimescaleDB) loadLegacyIntelligenceCheckpoint(ctx context.Context) (*IntelligenceCheckpoint, error) {
	if ts.pool == nil {
		return nil, fmt.Errorf("not connected")
	}
	var payload []byte
	err := ts.pool.QueryRow(ctx, "SELECT payload FROM intelligence_checkpoint WHERE id=1").Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cp IntelligenceCheckpoint
	err = json.Unmarshal(payload, &cp)
	return &cp, err
}
func (ts *TimescaleDB) SaveIntelligenceCheckpoint(ctx context.Context, cp *IntelligenceCheckpoint) error {
	if handled, err := intelligenceLeaseSave(ctx, ts, cp); handled {
		return err
	}
	return ts.saveLegacyIntelligenceCheckpoint(ctx, cp)
}
func (ts *TimescaleDB) saveLegacyIntelligenceCheckpoint(ctx context.Context, cp *IntelligenceCheckpoint) error {
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}
	payload, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	_, err = ts.pool.Exec(ctx, `INSERT INTO intelligence_checkpoint (id,revision,payload) VALUES (1,$1,$2) ON CONFLICT(id) DO UPDATE SET revision=EXCLUDED.revision,payload=EXCLUDED.payload WHERE intelligence_checkpoint.revision <= EXCLUDED.revision`, int64(cp.Revision), payload)
	return err
}
func (ts *TimescaleDB) ReplaceIntelligenceIOCs(ctx context.Context, revision uint64, iocs []*IOC) error {
	if _, leased := intelligenceLeaseFromContext(ctx); !leased && len(iocs) == 0 {
		return nil
	}
	if err := validateIntelligenceTextIOCs("timescaledb", true, iocs); err != nil {
		return err
	}
	approved, err := intelligenceLeaseIOCs(ctx, ts, revision, iocs)
	if err != nil {
		return err
	}
	return ts.replaceLegacyIntelligenceIOCs(ctx, revision, approved)
}
func (ts *TimescaleDB) replaceLegacyIntelligenceIOCs(ctx context.Context, revision uint64, iocs []*IOC) error {
	if err := validateIntelligenceTextIOCs("timescaledb", true, iocs); err != nil {
		return err
	}
	if len(iocs) == 0 {
		return nil
	}
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}
	tx, err := ts.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, i := range iocs {
		_, err = tx.Exec(ctx, `INSERT INTO iocs (id,type,value,honeypot,source_ip,technique_id,first_seen,last_seen,count,metadata,intelligence_revision) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(type,md5(value),honeypot) DO UPDATE SET source_ip=EXCLUDED.source_ip,technique_id=EXCLUDED.technique_id,first_seen=EXCLUDED.first_seen,last_seen=EXCLUDED.last_seen,count=EXCLUDED.count,metadata=EXCLUDED.metadata,intelligence_revision=EXCLUDED.intelligence_revision WHERE iocs.intelligence_revision <= EXCLUDED.intelligence_revision`, i.ID, i.Type, i.Value, i.Honeypot, i.SourceIP, i.TechniqueID, i.FirstSeen, i.LastSeen, i.Count, i.Metadata, int64(revision))
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (ts *TimescaleDB) ReplaceIntelligenceSessions(ctx context.Context, revision uint64, sessions []*TTPSession) error {
	if _, leased := intelligenceLeaseFromContext(ctx); !leased && len(sessions) == 0 {
		return nil
	}
	if err := validateIntelligenceTextSessions("timescaledb", true, sessions); err != nil {
		return err
	}
	approved, err := intelligenceLeaseSessions(ctx, ts, revision, sessions)
	if err != nil {
		return err
	}
	return ts.replaceLegacyIntelligenceSessions(ctx, revision, approved)
}
func (ts *TimescaleDB) replaceLegacyIntelligenceSessions(ctx context.Context, revision uint64, sessions []*TTPSession) error {
	if err := validateIntelligenceTextSessions("timescaledb", true, sessions); err != nil {
		return err
	}
	if len(sessions) == 0 {
		return nil
	}
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}
	tx, err := ts.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, s := range sessions {
		_, err = tx.Exec(ctx, `INSERT INTO ttp_sessions (session_id,campaign_fingerprint,source_ips,shared_infrastructure,kill_chain_stages,techniques,ioc_ids,event_count,first_seen,last_seen,confidence,intelligence_revision) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(session_id) DO UPDATE SET campaign_fingerprint=EXCLUDED.campaign_fingerprint,source_ips=EXCLUDED.source_ips,shared_infrastructure=EXCLUDED.shared_infrastructure,kill_chain_stages=EXCLUDED.kill_chain_stages,techniques=EXCLUDED.techniques,ioc_ids=EXCLUDED.ioc_ids,event_count=EXCLUDED.event_count,first_seen=EXCLUDED.first_seen,last_seen=EXCLUDED.last_seen,confidence=EXCLUDED.confidence,intelligence_revision=EXCLUDED.intelligence_revision WHERE ttp_sessions.intelligence_revision <= EXCLUDED.intelligence_revision`, s.SessionID, s.CampaignFingerprint, s.SourceIPs, s.SharedInfrastructure, s.KillChainStages, s.Techniques, s.IOCIDs, s.EventCount, s.FirstSeen, s.LastSeen, s.Confidence, int64(revision))
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// A revision guard makes delayed responses and retries harmless without relying
// on Elasticsearch's internal document version or event timestamps.
const intelligenceReplaceScript = `if (!ctx._source.containsKey('intelligence_revision') || ctx._source.intelligence_revision <= params.revision) { ctx._source = params.doc; } else { ctx.op = 'noop'; }`

func (es *Elasticsearch) replaceIntelligenceDocument(ctx context.Context, index, id string, revision uint64, doc map[string]interface{}) error {
	doc["intelligence_revision"] = revision
	body, err := json.Marshal(map[string]interface{}{"script": map[string]interface{}{"lang": "painless", "source": intelligenceReplaceScript, "params": map[string]interface{}{"revision": revision, "doc": doc}}, "upsert": doc})
	if err != nil {
		return err
	}
	data, status, err := es.esRequest(ctx, http.MethodPost, "/"+index+"/_update/"+url.PathEscape(esDocID(id))+"?refresh=wait_for&retry_on_conflict=3", body)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("replace intelligence document returned status %d", status)
	}
	return validateIntelligenceAcknowledgment(data, index, esDocID(id), true)
}

// Bulk the projections so refresh visibility costs one round trip per batch,
// not one refresh interval for every indicator in a worker cycle.
func (es *Elasticsearch) replaceIntelligenceDocuments(ctx context.Context, index string, revision uint64, ids []string, docs []map[string]interface{}) error {
	// Measure complete NDJSON rows, including JSON escaping, scripts, actions,
	// and both copies of each document. Elasticsearch commonly limits requests
	// to 100 MiB; keep individual exceptional rows well below that boundary.
	const targetBytes = 8 << 20
	const maxRowBytes = 64 << 20
	if len(ids) != len(docs) {
		return fmt.Errorf("intelligence bulk has %d identities for %d documents", len(ids), len(docs))
	}
	var body bytes.Buffer
	var batchIDs []string
	rows := 0
	flush := func() error {
		if rows == 0 {
			return nil
		}
		data, status, err := es.esRequest(ctx, http.MethodPost, "/_bulk?refresh=wait_for", body.Bytes())
		if err != nil {
			return err
		}
		if status >= 300 {
			return fmt.Errorf("replace intelligence documents returned status %d", status)
		}
		// Every chunk needs its own complete acknowledgment. Already written
		// chunks are harmless on replay because the same revision/rows are reused.
		expected := make([]esBulkExpectation, 0, len(batchIDs))
		for _, id := range batchIDs {
			expected = append(expected, esBulkExpectation{Operation: "update", Index: index, ID: id})
		}
		if err := checkBulkErrors(data, expected); err != nil {
			return fmt.Errorf("intelligence bulk acknowledgment: %w", err)
		}
		body.Reset()
		batchIDs = batchIDs[:0]
		rows = 0
		return nil
	}
	for n, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		docs[n]["intelligence_revision"] = revision
		var row bytes.Buffer
		if err := json.NewEncoder(&row).Encode(map[string]interface{}{"update": map[string]interface{}{"_index": index, "_id": esDocID(id), "retry_on_conflict": 3}}); err != nil {
			return err
		}
		if err := json.NewEncoder(&row).Encode(map[string]interface{}{"script": map[string]interface{}{"lang": "painless", "source": intelligenceReplaceScript, "params": map[string]interface{}{"revision": revision, "doc": docs[n]}}, "upsert": docs[n]}); err != nil {
			return err
		}
		if row.Len() > maxRowBytes {
			return fmt.Errorf("intelligence bulk row %d encodes to %d bytes, exceeding the safe %d-byte limit", n, row.Len(), maxRowBytes)
		}
		if rows > 0 && body.Len()+row.Len() > targetBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		_, _ = body.Write(row.Bytes())
		batchIDs = append(batchIDs, esDocID(id))
		rows++
		// A row larger than the target is a bounded standalone request.
		if body.Len() >= targetBytes {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}
func (es *Elasticsearch) ReplaceIntelligenceIOCs(ctx context.Context, revision uint64, iocs []*IOC) error {
	if _, leased := intelligenceLeaseFromContext(ctx); !leased && len(iocs) == 0 {
		return nil
	}
	if err := validateIntelligenceTextIOCs("elasticsearch", false, iocs); err != nil {
		return err
	}
	approved, err := intelligenceLeaseIOCs(ctx, es, revision, iocs)
	if err != nil {
		return err
	}
	return es.replaceLegacyIntelligenceIOCs(ctx, revision, approved)
}
func (es *Elasticsearch) replaceLegacyIntelligenceIOCs(ctx context.Context, revision uint64, iocs []*IOC) error {
	if err := validateIntelligenceTextIOCs("elasticsearch", false, iocs); err != nil {
		return err
	}
	ids := make([]string, 0, len(iocs))
	docs := make([]map[string]interface{}, 0, len(iocs))
	for _, i := range iocs {
		ids = append(ids, i.ID)
		docs = append(docs, iocToESDoc(i))
	}
	return es.replaceIntelligenceDocuments(ctx, "qpot-iocs", revision, ids, docs)
}
func (es *Elasticsearch) ReplaceIntelligenceSessions(ctx context.Context, revision uint64, sessions []*TTPSession) error {
	if _, leased := intelligenceLeaseFromContext(ctx); !leased && len(sessions) == 0 {
		return nil
	}
	if err := validateIntelligenceTextSessions("elasticsearch", false, sessions); err != nil {
		return err
	}
	approved, err := intelligenceLeaseSessions(ctx, es, revision, sessions)
	if err != nil {
		return err
	}
	return es.replaceLegacyIntelligenceSessions(ctx, revision, approved)
}
func (es *Elasticsearch) replaceLegacyIntelligenceSessions(ctx context.Context, revision uint64, sessions []*TTPSession) error {
	if err := validateIntelligenceTextSessions("elasticsearch", false, sessions); err != nil {
		return err
	}
	ids := make([]string, 0, len(sessions))
	docs := make([]map[string]interface{}, 0, len(sessions))
	for _, s := range sessions {
		ids = append(ids, s.SessionID)
		docs = append(docs, map[string]interface{}{"session_id": s.SessionID, "campaign_fingerprint": s.CampaignFingerprint, "source_ips": s.SourceIPs, "shared_infrastructure": s.SharedInfrastructure, "kill_chain_stages": s.KillChainStages, "techniques": s.Techniques, "ioc_ids": s.IOCIDs, "event_count": s.EventCount, "first_seen": s.FirstSeen.UTC().Format(time.RFC3339Nano), "last_seen": s.LastSeen.UTC().Format(time.RFC3339Nano), "confidence": s.Confidence})
	}
	return es.replaceIntelligenceDocuments(ctx, "qpot-ttp-sessions", revision, ids, docs)
}

func (es *Elasticsearch) initializeIntelligenceSchema(ctx context.Context) error {
	body := []byte(`{"settings":{"number_of_shards":1,"number_of_replicas":0},"mappings":{"properties":{"payload":{"type":"text","index":false},"intelligence_revision":{"type":"long"}}}}`)
	data, status, err := es.esRequest(ctx, http.MethodPut, "/qpot-intelligence-checkpoint", body)
	if err != nil {
		return err
	}
	if !successfulIndexCreation(status, data) {
		return fmt.Errorf("create intelligence checkpoint index returned status %d", status)
	}
	return nil
}

// SQL backends match the full value regardless of its size; reads are unbounded
// within each bounded key chunk, so pagination cannot drop tied indicators.
func readIntelligenceSQLIOCs(ctx context.Context, db Database, wanted []*IOC) ([]*IOC, error) {
	var out []*IOC
	for start := 0; start < len(wanted); {
		end, size := start, 0
		for end < len(wanted) {
			i := wanted[end]
			n := 80
			for _, v := range []string{i.Type, i.Value, i.Honeypot} {
				n += len(v) + strings.Count(v, `\`) + strings.Count(v, `'`) + 4
			}
			if end > start && (size+n > foldChunkBytes || end-start >= 500) {
				break
			}
			size += n
			end++
		}
		rows, err := db.GetIOCs(ctx, IOCFilter{intelligenceKeys: wanted[start:end]})
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
		start = end
	}
	return out, nil
}
func (ch *ClickHouse) ReadIntelligenceIOCs(ctx context.Context, wanted []*IOC) ([]*IOC, error) {
	return readIntelligenceSQLIOCs(ctx, ch, wanted)
}
func (ts *TimescaleDB) ReadIntelligenceIOCs(ctx context.Context, wanted []*IOC) ([]*IOC, error) {
	if err := validateIntelligenceTextIOCs("timescaledb", true, wanted); err != nil {
		return nil, err
	}
	return readIntelligenceSQLIOCs(ctx, ts, wanted)
}

// _mget uses document identity, not keyword indexes (which intentionally omit
// values over 8191 characters). It is realtime and needs no search pagination.
func (es *Elasticsearch) ReadIntelligenceIOCs(ctx context.Context, wanted []*IOC) ([]*IOC, error) {
	if err := validateIntelligenceTextIOCs("elasticsearch", false, wanted); err != nil {
		return nil, err
	}
	var out []*IOC
	for start := 0; start < len(wanted); start += 500 {
		end := min(start+500, len(wanted))
		ids := make([]string, 0, end-start)
		for _, i := range wanted[start:end] {
			ids = append(ids, esDocID(i.ID))
		}
		body, err := json.Marshal(map[string]interface{}{"ids": ids})
		if err != nil {
			return nil, err
		}
		data, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-iocs/_mget", body)
		if err != nil {
			return nil, err
		}
		if status >= 300 {
			return nil, fmt.Errorf("read intelligence iocs returned status %d", status)
		}
		var response struct {
			Docs []struct {
				ID     string          `json:"_id"`
				Found  *bool           `json:"found"`
				Source *IOC            `json:"_source"`
				Error  json.RawMessage `json:"error"`
			} `json:"docs"`
		}
		if err = json.Unmarshal(data, &response); err != nil {
			return nil, err
		}
		if len(response.Docs) != len(ids) {
			return nil, fmt.Errorf("read intelligence iocs returned %d of %d results", len(response.Docs), len(ids))
		}
		for n, d := range response.Docs {
			if d.ID != ids[n] || len(d.Error) > 0 && string(d.Error) != "null" {
				return nil, fmt.Errorf("read intelligence ioc %q failed: %s", ids[n], d.Error)
			}
			if d.Found == nil {
				return nil, fmt.Errorf("missing intelligence ioc existence acknowledgment")
			}
			if !*d.Found {
				continue
			}
			if d.Source == nil {
				return nil, fmt.Errorf("missing intelligence ioc source")
			}
			key := wanted[start+n]
			if d.Source.Type != key.Type || d.Source.Value != key.Value || d.Source.Honeypot != key.Honeypot {
				return nil, fmt.Errorf("intelligence ioc identity mismatch")
			}
			out = append(out, d.Source)
		}
	}
	return out, nil
}

// IntelligenceLockIdentity identifies the storage namespace without including
// credentials. It is used only for local worker ownership, not as a DB lease.
func intelligenceLockIdentity(kind string, cfg *config.DatabaseConfig, defaultPort int, namespace string) string {
	host := "localhost"
	port := defaultPort
	if cfg != nil {
		if strings.TrimSpace(cfg.Host) != "" {
			host = strings.TrimSpace(cfg.Host)
		}
		if cfg.Port > 0 {
			port = cfg.Port
		}
		if namespace == "" {
			namespace = cfg.Database
		}
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
		if ip.IsLoopback() {
			host = "localhost"
		}
	}
	raw := kind + "\x00" + net.JoinHostPort(host, strconv.Itoa(port)) + "\x00" + namespace
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
func (ch *ClickHouse) IntelligenceLockIdentity() string {
	return intelligenceLockIdentity("clickhouse", ch.config, 9000, "")
}
func (ts *TimescaleDB) IntelligenceLockIdentity() string {
	return intelligenceLockIdentity("timescaledb", ts.config, 5432, "")
}
func (es *Elasticsearch) IntelligenceLockIdentity() string {
	// Elasticsearch uses fixed qpot-* indices, independent of config.Database.
	return intelligenceLockIdentity("elasticsearch", es.config, 9200, "qpot")
}
