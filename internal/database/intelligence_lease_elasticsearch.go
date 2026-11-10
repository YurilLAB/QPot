package database

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"time"
)

const esIntelligenceLeaseControlID = "lease-control"

type esIntelligenceLeaseRecord struct {
	State        *intelligenceLeaseState `json:"state"`
	ObservedMS   *int64                  `json:"observed_ms"`
	InspectNonce string                  `json:"inspect_nonce"`
}

// Every transition runs against the latest document on its primary, using
// Elasticsearch's own update timestamp. A response/no-op is not an election:
// callers also require their unique operation nonce in the acknowledged source.
const esIntelligenceLeaseScript = `
def o = params.operation;
long n = ctx._now;
if (ctx.op == 'create') {
  if (o.kind != 'acquire') { throw new IllegalStateException('qpot_lease_lost'); }
  ctx._source.state = new HashMap(params.initial);
} else if (!ctx._source.containsKey('state') || ctx._source.state == null) {
  throw new IllegalStateException('qpot_lease_invalid');
}
def s = ctx._source.state;
if (s.namespace == null || s.namespace.length() != 32 || s.owner == null ||
    s.fence == null || s.fence < 0 || s.fence >= Long.MAX_VALUE ||
    s.reserved == null || s.reserved < 0 || s.reserved >= Long.MAX_VALUE ||
    s.checkpoint_revision == null || s.checkpoint_revision < 0 || s.checkpoint_revision > s.reserved ||
    s.checkpoint_digest == null || s.expires_ms == null || s.expires_ms < 0 ||
    (s.checkpoint_revision == 0 && s.checkpoint_digest.length() != 0) ||
    (s.checkpoint_revision != 0 && s.checkpoint_digest.length() != 64) ||
    (ctx.op != 'create' && s.fence == 0)) {
  throw new IllegalStateException('qpot_lease_invalid');
}
if (o.kind == 'acquire') {
  if (s.owner != '' && s.expires_ms > n) { throw new IllegalStateException('qpot_lease_busy'); }
  if (s.fence >= Long.MAX_VALUE - 1L || n > Long.MAX_VALUE - o.ttl_ms) {
    throw new IllegalStateException('qpot_lease_exhausted');
  }
  s.fence = s.fence + 1L;
  s.owner = o.owner;
  s.expires_ms = n + o.ttl_ms;
  // Painless Math.max overloads can use double; keep counters exact as longs.
  long highest = (long)s.reserved;
  if ((long)o.minimum > highest) { highest = (long)o.minimum; }
  if ((long)s.checkpoint_revision > highest) { highest = (long)s.checkpoint_revision; }
  s.reserved = highest;
} else {
  if (s.owner == '' || s.owner != o.owner || s.fence != o.fence ||
      s.namespace != o.namespace || s.expires_ms <= n) {
    throw new IllegalStateException('qpot_lease_lost');
  }
  if (o.kind == 'renew') {
    if (n > Long.MAX_VALUE - o.ttl_ms) { throw new IllegalStateException('qpot_lease_exhausted'); }
    s.expires_ms = n + o.ttl_ms;
  } else if (o.kind == 'release') {
    s.owner = '';
    s.expires_ms = 0L;
  } else if (o.kind == 'reserve') {
    long m = (long)s.reserved;
    if ((long)o.minimum > m) { m = (long)o.minimum; }
    if ((long)s.checkpoint_revision > m) { m = (long)s.checkpoint_revision; }
    if (m >= Long.MAX_VALUE - 1L) { throw new IllegalStateException('qpot_lease_exhausted'); }
    s.reserved = m + 1L;
  } else if (o.kind == 'publish') {
    if (o.revision == 0 || o.revision > s.reserved || o.revision < s.checkpoint_revision ||
        o.digest.length() != 64 || (o.revision == s.checkpoint_revision && o.digest != s.checkpoint_digest)) {
      throw new IllegalStateException('qpot_lease_checkpoint_conflict');
    }
    s.checkpoint_revision = o.revision;
    s.checkpoint_digest = o.digest;
  } else { throw new IllegalStateException('qpot_lease_invalid'); }
}
s.operation = o.nonce;
ctx._source.observed_ms = n;
ctx._source.inspect_nonce = '';
`

const esIntelligenceLeaseInspectScript = `
if (!ctx._source.containsKey('state') || ctx._source.state == null) {
  throw new IllegalStateException('qpot_lease_invalid');
}
ctx._source.observed_ms = ctx._now;
ctx._source.inspect_nonce = params.nonce;
`

func esIntelligenceLeasePath() string {
	// Ownership reads use real-time document operations and acknowledged source,
	// so waiting for a search refresh would only consume lease lifetime.
	return "/" + intelligenceCheckpointIndex + "/_update/" + esIntelligenceLeaseControlID + "?_source=true&refresh=false&retry_on_conflict=3&wait_for_active_shards=all"
}

func validateESIntelligenceLeaseAck(data []byte, id string) error {
	if err := validateIntelligenceAcknowledgment(data, intelligenceCheckpointIndex, id, false); err != nil {
		return err
	}
	var ack struct {
		Shards struct {
			Total      int `json:"total"`
			Successful int `json:"successful"`
			Failed     int `json:"failed"`
		} `json:"_shards"`
	}
	if err := json.Unmarshal(data, &ack); err != nil {
		return err
	}
	if ack.Shards.Total < 1 || ack.Shards.Successful != ack.Shards.Total || ack.Shards.Failed != 0 {
		return fmt.Errorf("intelligence lease write was not acknowledged by every shard copy")
	}
	return nil
}

func decodeESIntelligenceLeaseAck(data []byte) (*esIntelligenceLeaseRecord, error) {
	if err := validateESIntelligenceLeaseAck(data, esIntelligenceLeaseControlID); err != nil {
		return nil, err
	}
	var ack struct {
		Get *struct {
			Source *esIntelligenceLeaseRecord `json:"_source"`
		} `json:"get"`
	}
	if err := json.Unmarshal(data, &ack); err != nil {
		return nil, err
	}
	if ack.Get == nil || ack.Get.Source == nil || ack.Get.Source.State == nil || ack.Get.Source.ObservedMS == nil || *ack.Get.Source.ObservedMS < 0 {
		return nil, fmt.Errorf("incomplete intelligence lease acknowledgment")
	}
	if err := validateIntelligenceLeaseState(*ack.Get.Source.State); err != nil {
		return nil, err
	}
	return ack.Get.Source, nil
}

func esIntelligenceLeaseFailure(data []byte, status int, acquiring bool) error {
	var problem struct {
		Error json.RawMessage `json:"error"`
	}
	_ = json.Unmarshal(data, &problem)
	var inspect func(json.RawMessage) error
	inspect = func(raw json.RawMessage) error {
		var node struct {
			Reason    string            `json:"reason"`
			CausedBy  json.RawMessage   `json:"caused_by"`
			RootCause []json.RawMessage `json:"root_cause"`
		}
		if json.Unmarshal(raw, &node) != nil {
			return nil
		}
		switch node.Reason {
		case "qpot_lease_busy":
			return ErrIntelligenceLeaseBusy
		case "qpot_lease_lost":
			return ErrIntelligenceLeaseLost
		}
		if len(node.CausedBy) > 0 {
			if err := inspect(node.CausedBy); err != nil {
				return err
			}
		}
		for _, child := range node.RootCause {
			if err := inspect(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := inspect(problem.Error); err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return ErrIntelligenceLeaseLost
	}
	if status == http.StatusConflict && acquiring {
		return ErrIntelligenceLeaseBusy
	}
	return fmt.Errorf("atomic intelligence lease operation returned status %d", status)
}

func (es *Elasticsearch) intelligenceLeaseRead(ctx context.Context) (*intelligenceLeaseState, time.Time, error) {
	nonce, err := intelligenceLeaseNonce()
	if err != nil {
		return nil, time.Time{}, err
	}
	body, err := json.Marshal(map[string]any{"script": map[string]any{"lang": "painless", "source": esIntelligenceLeaseInspectScript, "params": map[string]any{"nonce": nonce}}})
	if err != nil {
		return nil, time.Time{}, err
	}
	data, status, err := es.esRequest(ctx, http.MethodPost, esIntelligenceLeasePath(), body)
	if err != nil {
		return nil, time.Time{}, err
	}
	if status == http.StatusNotFound {
		return nil, time.Time{}, nil
	}
	if status < 200 || status >= 300 {
		return nil, time.Time{}, esIntelligenceLeaseFailure(data, status, false)
	}
	record, err := decodeESIntelligenceLeaseAck(data)
	if err != nil {
		return nil, time.Time{}, err
	}
	if record.InspectNonce != nonce {
		return nil, time.Time{}, fmt.Errorf("intelligence lease inspection was not acknowledged")
	}
	return record.State, time.UnixMilli(*record.ObservedMS).UTC(), nil
}

func validateESIntelligenceLeaseOperation(op intelligenceLeaseOperation) error {
	if op.Nonce == "" || !intelligenceLeaseOwner(op.Owner) || op.Minimum >= math.MaxInt64-1 {
		return fmt.Errorf("invalid intelligence lease operation")
	}
	if op.Kind == "acquire" || op.Kind == "renew" {
		if op.TTLMillis < 1000 || op.TTLMillis > 300000 {
			return fmt.Errorf("invalid intelligence lease TTL")
		}
	}
	if len(op.Namespace) != 32 {
		return fmt.Errorf("invalid intelligence lease namespace")
	}
	if op.Kind != "acquire" && (op.Fence == 0 || op.Fence >= math.MaxInt64) {
		return ErrIntelligenceLeaseLost
	}
	switch op.Kind {
	case "acquire", "renew", "release", "reserve":
	case "publish":
		if op.Revision == 0 || op.Revision >= math.MaxInt64 || len(op.Digest) != 64 {
			return fmt.Errorf("invalid intelligence checkpoint publication")
		}
	default:
		return fmt.Errorf("unknown intelligence lease operation")
	}
	return nil
}

func (es *Elasticsearch) intelligenceLeaseMutate(ctx context.Context, op intelligenceLeaseOperation) (intelligenceLeaseState, error) {
	var empty intelligenceLeaseState
	if err := validateESIntelligenceLeaseOperation(op); err != nil {
		return empty, err
	}
	initial := intelligenceLeaseState{Namespace: op.Namespace}
	if op.Kind == "acquire" {
		// Only bootstrap an absent control document. A concurrent first owner is
		// resolved by Elasticsearch's atomic scripted upsert, never this read.
		data, status, err := es.esRequest(ctx, http.MethodGet, "/"+intelligenceCheckpointIndex+"/_doc/"+esIntelligenceLeaseControlID, nil)
		if err != nil {
			return empty, err
		}
		if status == http.StatusNotFound {
			cp, err := es.loadLegacyIntelligenceCheckpoint(ctx)
			if err != nil {
				return empty, err
			}
			if cp != nil {
				digest, err := intelligenceLeaseDigest(cp)
				if err != nil {
					return empty, err
				}
				if err := es.intelligenceLeaseStoreCheckpoint(ctx, cp, digest); err != nil {
					return empty, err
				}
				initial.Reserved, initial.CheckpointRevision, initial.CheckpointDigest = cp.Revision, cp.Revision, digest
			}
		} else if status < 200 || status >= 300 {
			return empty, esIntelligenceLeaseFailure(data, status, true)
		} else {
			var existing struct {
				ID     string                     `json:"_id"`
				Index  string                     `json:"_index"`
				Found  bool                       `json:"found"`
				Source *esIntelligenceLeaseRecord `json:"_source"`
			}
			if json.Unmarshal(data, &existing) != nil || !existing.Found || existing.ID != esIntelligenceLeaseControlID || existing.Index != intelligenceCheckpointIndex || existing.Source == nil || existing.Source.State == nil || validateIntelligenceLeaseState(*existing.Source.State) != nil {
				return empty, fmt.Errorf("incomplete intelligence lease existence read")
			}
		}
	}
	body, err := json.Marshal(map[string]any{
		"script":          map[string]any{"lang": "painless", "source": esIntelligenceLeaseScript, "params": map[string]any{"operation": op, "initial": initial}},
		"scripted_upsert": true, "upsert": map[string]any{},
	})
	if err != nil {
		return empty, err
	}
	data, status, err := es.esRequest(ctx, http.MethodPost, esIntelligenceLeasePath(), body)
	if err != nil {
		return empty, err
	}
	if status < 200 || status >= 300 {
		return empty, esIntelligenceLeaseFailure(data, status, op.Kind == "acquire")
	}
	record, err := decodeESIntelligenceLeaseAck(data)
	if err != nil {
		return empty, err
	}
	if record.State.Operation != op.Nonce {
		return empty, fmt.Errorf("intelligence lease mutation was not acknowledged")
	}
	if op.Kind == "acquire" && record.State.Owner != op.Owner || op.Kind != "acquire" && (record.State.Fence != op.Fence || record.State.Namespace != op.Namespace) {
		return empty, ErrIntelligenceLeaseLost
	}
	if op.Kind == "release" && record.State.Owner != "" || op.Kind != "release" && record.State.Owner != op.Owner {
		return empty, ErrIntelligenceLeaseLost
	}
	return *record.State, nil
}

type esIntelligenceLeaseCheckpointDocument struct {
	esIntelligenceCheckpoint
	LeaseCheckpoint bool `json:"lease_checkpoint"`
}

func esIntelligenceLeaseCheckpointID(revision uint64, digest string) string {
	return fmt.Sprintf("lease-checkpoint-%d-%s", revision, digest)
}

func esIntelligenceLeaseChunkID(revision uint64, digest string, part int) string {
	return fmt.Sprintf("lease-chunk-%d-%s-%d", revision, digest, part)
}

func (es *Elasticsearch) readIntelligenceLeaseCheckpointDocument(ctx context.Context, id string) (*esIntelligenceLeaseCheckpointDocument, error) {
	data, status, err := es.esRequest(ctx, http.MethodGet, "/"+intelligenceCheckpointIndex+"/_doc/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("read immutable intelligence checkpoint returned status %d", status)
	}
	var response struct {
		ID     string                                 `json:"_id"`
		Index  string                                 `json:"_index"`
		Found  bool                                   `json:"found"`
		Source *esIntelligenceLeaseCheckpointDocument `json:"_source"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	if !response.Found || response.ID != id || response.Index != intelligenceCheckpointIndex || response.Source == nil || !response.Source.LeaseCheckpoint {
		return nil, fmt.Errorf("incomplete immutable intelligence checkpoint read")
	}
	return response.Source, nil
}

func (es *Elasticsearch) createIntelligenceLeaseCheckpointDocument(ctx context.Context, id string, doc esIntelligenceLeaseCheckpointDocument) error {
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	data, status, err := es.esRequest(ctx, http.MethodPut, "/"+intelligenceCheckpointIndex+"/_create/"+url.PathEscape(id)+"?wait_for_active_shards=all", body)
	if err != nil {
		return err
	}
	if status == http.StatusConflict {
		stored, err := es.readIntelligenceLeaseCheckpointDocument(ctx, id)
		if err != nil {
			return err
		}
		if stored == nil || !reflect.DeepEqual(*stored, doc) {
			return fmt.Errorf("conflicting immutable intelligence checkpoint")
		}
		return nil
	}
	if status != http.StatusCreated {
		return fmt.Errorf("create immutable intelligence checkpoint returned status %d", status)
	}
	return validateESIntelligenceLeaseAck(data, id)
}

func (es *Elasticsearch) intelligenceLeaseStoreCheckpoint(ctx context.Context, cp *IntelligenceCheckpoint, digest string) error {
	if cp == nil || cp.Revision == 0 || cp.Revision >= math.MaxInt64 {
		return fmt.Errorf("invalid immutable intelligence checkpoint")
	}
	payload, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != digest {
		return fmt.Errorf("immutable intelligence checkpoint digest mismatch")
	}
	doc := esIntelligenceLeaseCheckpointDocument{esIntelligenceCheckpoint: esIntelligenceCheckpoint{Revision: cp.Revision, SHA256: digest, PayloadBytes: len(payload)}, LeaseCheckpoint: true}
	if len(payload) > intelligenceCheckpointChunkBytes {
		doc.ChunkCount = (len(payload)-1)/intelligenceCheckpointChunkBytes + 1
		for part := 0; part < doc.ChunkCount; part++ {
			start, end := part*intelligenceCheckpointChunkBytes, min((part+1)*intelligenceCheckpointChunkBytes, len(payload))
			chunk := esIntelligenceLeaseCheckpointDocument{esIntelligenceCheckpoint: esIntelligenceCheckpoint{Revision: cp.Revision, Chunk: true, Payload: base64.StdEncoding.EncodeToString(payload[start:end]), PayloadBytes: end - start, SHA256: digest}, LeaseCheckpoint: true}
			if err := es.createIntelligenceLeaseCheckpointDocument(ctx, esIntelligenceLeaseChunkID(cp.Revision, digest, part), chunk); err != nil {
				return err
			}
		}
	} else {
		doc.Payload = string(payload)
	}
	return es.createIntelligenceLeaseCheckpointDocument(ctx, esIntelligenceLeaseCheckpointID(cp.Revision, digest), doc)
}

func (es *Elasticsearch) intelligenceLeaseLoadCheckpoint(ctx context.Context, revision uint64, digest string) (*IntelligenceCheckpoint, error) {
	if revision == 0 || revision >= math.MaxInt64 || len(digest) != 64 {
		return nil, fmt.Errorf("invalid immutable intelligence checkpoint reference")
	}
	doc, err := es.readIntelligenceLeaseCheckpointDocument(ctx, esIntelligenceLeaseCheckpointID(revision, digest))
	if err != nil {
		return nil, err
	}
	if doc == nil || doc.Revision != revision || doc.Chunk || doc.SHA256 != digest || doc.PayloadBytes <= 0 {
		return nil, fmt.Errorf("missing or mismatched immutable intelligence checkpoint")
	}
	payload := []byte(doc.Payload)
	if doc.ChunkCount != 0 {
		if doc.Payload != "" || doc.ChunkCount != (doc.PayloadBytes-1)/intelligenceCheckpointChunkBytes+1 {
			return nil, fmt.Errorf("invalid immutable checkpoint chunk manifest")
		}
		payload = nil
		for part := 0; part < doc.ChunkCount; part++ {
			chunk, err := es.readIntelligenceLeaseCheckpointDocument(ctx, esIntelligenceLeaseChunkID(revision, digest, part))
			if err != nil {
				return nil, err
			}
			expected := min(intelligenceCheckpointChunkBytes, doc.PayloadBytes-part*intelligenceCheckpointChunkBytes)
			if chunk == nil || !chunk.Chunk || chunk.Revision != revision || chunk.SHA256 != digest || chunk.PayloadBytes != expected || chunk.ChunkCount != 0 {
				return nil, fmt.Errorf("missing or mismatched immutable checkpoint chunk")
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(chunk.Payload)
			if err != nil || len(decoded) != expected {
				return nil, fmt.Errorf("invalid immutable checkpoint chunk bytes")
			}
			payload = append(payload, decoded...)
		}
	} else if len(payload) != doc.PayloadBytes || len(payload) > intelligenceCheckpointChunkBytes {
		return nil, fmt.Errorf("invalid immutable checkpoint inline bytes")
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("immutable checkpoint content hash mismatch")
	}
	var cp IntelligenceCheckpoint
	if err := json.Unmarshal(payload, &cp); err != nil {
		return nil, err
	}
	if cp.Revision != revision {
		return nil, fmt.Errorf("immutable checkpoint revision mismatch")
	}
	return &cp, nil
}

func (es *Elasticsearch) intelligenceLeaseGCCheckpoints(ctx context.Context, revision uint64) error {
	if revision == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"query": map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"lease_checkpoint": true}},
		map[string]any{"range": map[string]any{"intelligence_revision": map[string]any{"lt": revision}}},
	}}}})
	if err != nil {
		return err
	}
	_, status, err := es.esRequest(ctx, http.MethodPost, "/"+intelligenceCheckpointIndex+"/_delete_by_query?conflicts=proceed", body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("intelligence checkpoint maintenance returned status %d", status)
	}
	return nil
}
