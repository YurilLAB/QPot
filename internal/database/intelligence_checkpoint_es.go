package database

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const intelligenceCheckpointIndex = "qpot-intelligence-checkpoint"

// Keep individual requests far below Elasticsearch's default 100 MiB HTTP
// limit, including JSON escaping and the update script's duplicate document.
// Chunking the complete serialized checkpoint also bounds requests when active
// session state grows independently of the number of events in a batch.
const intelligenceCheckpointChunkBytes = 1 << 20

type esIntelligenceCheckpoint struct {
	Revision     uint64 `json:"intelligence_revision"`
	Payload      string `json:"payload,omitempty"`
	Chunk        bool   `json:"chunk,omitempty"`
	ChunkCount   int    `json:"chunk_count,omitempty"`
	PayloadBytes int    `json:"payload_bytes,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
}

func validateIntelligenceAcknowledgment(data []byte, index, id string, allowNoop bool) error {
	var ack struct {
		Index   string `json:"_index"`
		ID      string `json:"_id"`
		Version int64  `json:"_version"`
		Result  string `json:"result"`
		Shards  *struct {
			Failed     int `json:"failed"`
			Successful int `json:"successful"`
		} `json:"_shards"`
	}
	if err := json.Unmarshal(data, &ack); err != nil {
		return fmt.Errorf("parse intelligence document acknowledgment: %w", err)
	}
	if ack.Index != index || ack.ID != id || ack.Version < 1 {
		return fmt.Errorf("incomplete intelligence document acknowledgment")
	}
	if ack.Shards != nil && ack.Shards.Failed != 0 {
		return fmt.Errorf("intelligence document acknowledgment contains failed shards")
	}
	if allowNoop && ack.Result == "noop" {
		return nil
	}
	if (ack.Result != "created" && ack.Result != "updated") || ack.Shards == nil || ack.Shards.Failed != 0 || ack.Shards.Successful < 1 {
		return fmt.Errorf("intelligence document write was not fully acknowledged")
	}
	return nil
}

func intelligenceChunkID(revision uint64, digest string, part int) string {
	return fmt.Sprintf("chunk-%d-%s-%d", revision, digest, part)
}

func (es *Elasticsearch) readIntelligenceCheckpointDocument(ctx context.Context, id string) (*esIntelligenceCheckpoint, error) {
	data, status, err := es.esRequest(ctx, http.MethodGet, "/"+intelligenceCheckpointIndex+"/_doc/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("load intelligence checkpoint returned status %d", status)
	}
	var response struct {
		ID     string                    `json:"_id"`
		Index  string                    `json:"_index"`
		Found  bool                      `json:"found"`
		Source *esIntelligenceCheckpoint `json:"_source"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	if !response.Found || response.Source == nil || response.ID != id || response.Index != intelligenceCheckpointIndex {
		return nil, fmt.Errorf("incomplete intelligence checkpoint read")
	}
	return response.Source, nil
}

func (es *Elasticsearch) LoadIntelligenceCheckpoint(ctx context.Context) (*IntelligenceCheckpoint, error) {
	if cp, handled, err := intelligenceLeaseLoad(ctx, es); handled {
		return cp, err
	}
	return es.loadLegacyIntelligenceCheckpoint(ctx)
}
func (es *Elasticsearch) loadLegacyIntelligenceCheckpoint(ctx context.Context) (*IntelligenceCheckpoint, error) {
	doc, err := es.readIntelligenceCheckpointDocument(ctx, "worker")
	if err != nil || doc == nil {
		return nil, err
	}
	if doc.Revision == 0 || doc.Chunk {
		return nil, fmt.Errorf("invalid intelligence checkpoint manifest")
	}
	payload := []byte(doc.Payload) // Recover the original inline format too.
	if doc.ChunkCount != 0 {
		digest, err := hex.DecodeString(doc.SHA256)
		if err != nil || len(digest) != sha256.Size || doc.Payload != "" || doc.PayloadBytes <= 0 || doc.ChunkCount != (doc.PayloadBytes-1)/intelligenceCheckpointChunkBytes+1 {
			return nil, fmt.Errorf("invalid chunked intelligence checkpoint manifest")
		}
		// Do not allocate from an unchecked remote byte count. Each part is
		// checked before append and the complete content hash is checked below.
		payload = nil
		for part := 0; part < doc.ChunkCount; part++ {
			chunk, err := es.readIntelligenceCheckpointDocument(ctx, intelligenceChunkID(doc.Revision, doc.SHA256, part))
			if err != nil {
				return nil, err
			}
			if chunk == nil || !chunk.Chunk || chunk.Revision != doc.Revision {
				return nil, fmt.Errorf("missing or mismatched intelligence checkpoint chunk %d", part)
			}
			decoded, err := base64.StdEncoding.DecodeString(chunk.Payload)
			expected := intelligenceCheckpointChunkBytes
			if part == doc.ChunkCount-1 {
				expected = doc.PayloadBytes - part*intelligenceCheckpointChunkBytes
			}
			if err != nil || len(decoded) != expected {
				return nil, fmt.Errorf("invalid intelligence checkpoint chunk %d", part)
			}
			payload = append(payload, decoded...)
		}
		sum := sha256.Sum256(payload)
		if hex.EncodeToString(sum[:]) != doc.SHA256 {
			return nil, fmt.Errorf("intelligence checkpoint digest mismatch")
		}
	} else if doc.SHA256 != "" || doc.PayloadBytes != 0 {
		return nil, fmt.Errorf("incomplete intelligence checkpoint manifest")
	}
	var cp IntelligenceCheckpoint
	if err := json.Unmarshal(payload, &cp); err != nil {
		return nil, err
	}
	if cp.Revision != doc.Revision {
		return nil, fmt.Errorf("intelligence checkpoint revision mismatch")
	}
	return &cp, nil
}

func (es *Elasticsearch) SaveIntelligenceCheckpoint(ctx context.Context, cp *IntelligenceCheckpoint) error {
	if handled, err := intelligenceLeaseSave(ctx, es, cp); handled {
		return err
	}
	return es.saveLegacyIntelligenceCheckpoint(ctx, cp)
}
func (es *Elasticsearch) saveLegacyIntelligenceCheckpoint(ctx context.Context, cp *IntelligenceCheckpoint) error {
	payload, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	var doc map[string]interface{}
	if len(payload) > intelligenceCheckpointChunkBytes {
		sum := sha256.Sum256(payload)
		digest := hex.EncodeToString(sum[:])
		parts := (len(payload)-1)/intelligenceCheckpointChunkBytes + 1
		for part := 0; part < parts; part++ {
			start, end := part*intelligenceCheckpointChunkBytes, (part+1)*intelligenceCheckpointChunkBytes
			if end > len(payload) {
				end = len(payload)
			}
			body, err := json.Marshal(esIntelligenceCheckpoint{Revision: cp.Revision, Chunk: true, Payload: base64.StdEncoding.EncodeToString(payload[start:end])})
			if err != nil {
				return err
			}
			id := intelligenceChunkID(cp.Revision, digest, part)
			// These names contain revision and exact content hash: retries write
			// identical bytes, and a delayed older write cannot alter a new WAL.
			data, status, err := es.esRequest(ctx, http.MethodPut, "/"+intelligenceCheckpointIndex+"/_doc/"+id, body)
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("save intelligence checkpoint chunk returned status %d", status)
			}
			if err := validateIntelligenceAcknowledgment(data, intelligenceCheckpointIndex, id, false); err != nil {
				return err
			}
		}
		doc = map[string]interface{}{"chunk_count": parts, "payload_bytes": len(payload), "sha256": digest}
	} else {
		doc = map[string]interface{}{"payload": string(payload)}
	}
	// Publishing the small revision-guarded manifest is the commit point. All
	// chunks are acknowledged first and real-time GET needs no search refresh.
	if err := es.replaceIntelligenceDocument(ctx, intelligenceCheckpointIndex, "worker", cp.Revision, doc); err != nil {
		return err
	}
	// Old chunks are garbage only after a newer manifest is durable. Best-effort
	// GC cannot invalidate this or a later checkpoint. A delayed old chunk can
	// be recreated, then removed by the next successful save. Failures here do
	// not turn an already committed checkpoint into a processing failure.
	body, _ := json.Marshal(map[string]interface{}{"query": map[string]interface{}{"bool": map[string]interface{}{"filter": []interface{}{map[string]interface{}{"term": map[string]interface{}{"chunk": true}}, map[string]interface{}{"range": map[string]interface{}{"intelligence_revision": map[string]interface{}{"lt": cp.Revision}}}}}}})
	_, _, _ = es.esRequest(ctx, http.MethodPost, "/"+intelligenceCheckpointIndex+"/_delete_by_query?conflicts=proceed", body)
	return nil
}
