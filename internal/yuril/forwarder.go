// Package yuril forwards QPot-classified IOCs into the Yuril Security Suite.
//
// QPot talks to Yuril over the suite's `ingest_intel` HTTP endpoint (served
// by YurilTracking and bridged internally to YurilAntivirus over the
// ECDSA-signed IPC channel). The wire format matches the
// `IngestIntelPayload` / `IntelItem` structs defined in
// `YurilAntivirus/internal/integration/ipc.go` — QPot does not depend on
// the Go types directly but mirrors them field-for-field so the contract
// is version-checked at build time whenever the two sides change in lockstep.
package yuril

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

const (
	defaultSource    = "qpot_honeypot"
	defaultBatchSize = 200
	defaultTimeout   = 10 * time.Second
	// hardCapBatch caps the batch size no matter what the config says.
	// Mirrors the receiver-side limit so we never knowingly get rejected.
	hardCapBatch = 10_000

	// APIVersion is sent on every forwarded batch (and accepted on
	// inbound calls) so the QPot ↔ Yuril contract can evolve without
	// silent breakage. Bump on any wire-format change.
	APIVersion = "1"

	// Retry tunables. Conservative on purpose — Yuril is usually on the
	// same private network so transient blips clear in seconds, and we
	// don't want to amplify load during an outage.
	maxRetries     = 3
	initialBackoff = 500 * time.Millisecond
	maxBackoff     = 5 * time.Second
)

// IntelItem mirrors YurilAntivirus IngestIntel item.
type IntelItem struct {
	Type       string            `json:"type"`
	Value      string            `json:"value"`
	Confidence uint8             `json:"confidence,omitempty"`
	Severity   string            `json:"severity,omitempty"`
	Context    map[string]string `json:"context,omitempty"`
}

// IntelBatch is the payload that the Yuril ingestion endpoint accepts.
type IntelBatch struct {
	BatchID    string      `json:"batch_id"`
	Source     string      `json:"source"`
	ProducedAt time.Time   `json:"produced_at"`
	Items      []IntelItem `json:"items"`
}

// Stats summarises forwarder activity for the yuril status command and
// the health endpoint. All counters are monotonic since process start.
type Stats struct {
	Enabled         bool      `json:"enabled"`
	Endpoint        string    `json:"endpoint"`
	BatchesSent     int64     `json:"batches_sent"`
	ItemsSent       int64     `json:"items_sent"`
	BatchesFailed   int64     `json:"batches_failed"`
	LastSuccessAt   time.Time `json:"last_success_at,omitempty"`
	LastFailureAt   time.Time `json:"last_failure_at,omitempty"`
	LastErrorString string    `json:"last_error,omitempty"`
}

// Forwarder is a reusable HTTP client that pushes IOC batches to Yuril.
// Safe to share across goroutines.
type Forwarder struct {
	endpoint  string
	apiKey    string
	source    string
	batchSize int
	client    *http.Client

	mu    sync.Mutex
	stats Stats
}

// New constructs a Forwarder from a YurilConfig. Returns (nil, nil) if
// forwarding is disabled in the config — callers treat that as an
// expected non-error path.
func New(cfg config.YurilConfig) (*Forwarder, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, fmt.Errorf("yuril forwarder enabled but endpoint is empty")
	}

	source := cfg.Source
	if source == "" {
		source = defaultSource
	}
	batch := cfg.BatchSize
	if batch <= 0 {
		batch = defaultBatchSize
	}
	if batch > hardCapBatch {
		batch = hardCapBatch
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	transport := &http.Transport{
		// VerifyTLS defaults to true at the config layer; only disable
		// when the operator has explicitly said so.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyTLS},
	}

	f := &Forwarder{
		endpoint:  cfg.Endpoint,
		apiKey:    cfg.APIKey,
		source:    source,
		batchSize: batch,
		client:    &http.Client{Timeout: timeout, Transport: transport},
	}
	f.stats.Enabled = true
	f.stats.Endpoint = cfg.Endpoint
	return f, nil
}

// Stats returns a copy of the forwarder's current activity counters.
// Safe to call concurrently with Forward.
func (f *Forwarder) Stats() Stats {
	if f == nil {
		return Stats{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats
}

// Ping submits an empty test batch to confirm endpoint reachability,
// auth, and TLS. Used by `qpot yuril test`. Empty batches are a valid
// payload — Yuril treats them as a no-op and returns 2xx, so this is a
// strict superset of "the endpoint exists" without polluting the
// receiver's IOC store.
func (f *Forwarder) Ping(ctx context.Context) error {
	if f == nil {
		return errors.New("yuril forwarder is not configured")
	}
	batch := IntelBatch{
		BatchID:    fmt.Sprintf("qpot-ping-%d", time.Now().UnixNano()),
		Source:     f.source,
		ProducedAt: time.Now().UTC(),
		Items:      nil, // empty — server-side this is a no-op
	}
	return f.post(ctx, batch)
}

// recordSuccess and recordFailure mutate stats under the lock.
func (f *Forwarder) recordSuccess(items int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats.BatchesSent++
	f.stats.ItemsSent += int64(items)
	f.stats.LastSuccessAt = time.Now().UTC()
	f.stats.LastErrorString = ""
}

func (f *Forwarder) recordFailure(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats.BatchesFailed++
	f.stats.LastFailureAt = time.Now().UTC()
	if err != nil {
		// Cap the recorded error so a giant body doesn't bloat memory.
		msg := err.Error()
		if len(msg) > 512 {
			msg = msg[:512] + "..."
		}
		f.stats.LastErrorString = msg
	}
}

// Forward sends a slice of QPot IOCs to Yuril. Items that can't be mapped
// to an ingest type are silently skipped; if nothing is left after
// mapping, Forward returns without calling the endpoint.
//
// The caller supplies a correlation ID (e.g. a classifier batch id) so
// both ends can match telemetry on failure.
func (f *Forwarder) Forward(ctx context.Context, batchID string, iocs []*database.IOC) error {
	if f == nil || len(iocs) == 0 {
		return nil
	}

	items := make([]IntelItem, 0, len(iocs))
	for _, ioc := range iocs {
		item, ok := translateIOC(ioc)
		if !ok {
			continue
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil
	}

	for start := 0; start < len(items); start += f.batchSize {
		end := start + f.batchSize
		if end > len(items) {
			end = len(items)
		}
		batch := IntelBatch{
			BatchID:    fmt.Sprintf("%s-%d", batchID, start/f.batchSize),
			Source:     f.source,
			ProducedAt: time.Now().UTC(),
			Items:      items[start:end],
		}
		if err := f.postWithRetry(ctx, batch); err != nil {
			f.recordFailure(err)
			return fmt.Errorf("yuril forward (items %d-%d): %w", start, end, err)
		}
		f.recordSuccess(len(batch.Items))
	}
	return nil
}

// postWithRetry wraps post with exponential backoff for transient
// failures (network errors and 5xx responses). 4xx responses are
// returned immediately because retrying a misconfigured request is
// pointless and just wastes the receiver's capacity.
func (f *Forwarder) postWithRetry(ctx context.Context, batch IntelBatch) error {
	backoff := initialBackoff
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
		err := f.post(ctx, batch)
		if err == nil {
			return nil
		}
		lastErr = err
		// Stop retrying on permanent errors so we don't drown the
		// server during a misconfiguration. errPermanentStatus is
		// raised by post() for 4xx responses.
		if errors.Is(err, errPermanentStatus) {
			return err
		}
	}
	return fmt.Errorf("after %d retries: %w", maxRetries, lastErr)
}

// errPermanentStatus is sentinel-wrapped by post() when the server
// returns a 4xx status, signalling postWithRetry to give up immediately.
var errPermanentStatus = errors.New("permanent status")

// post submits a single batch. Treats 2xx as success and anything else
// as a typed error including the response body (truncated) for diagnostics.
func (f *Forwarder) post(ctx context.Context, batch IntelBatch) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "qpot-yuril-forwarder/"+APIVersion)
	req.Header.Set("X-QPot-API-Version", APIVersion)
	if f.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		slog.Debug("Forwarded IOC batch to Yuril",
			"batch_id", batch.BatchID,
			"count", len(batch.Items),
			"status", resp.StatusCode)
		return nil
	}

	// Cap the body at 512 bytes so a hostile server can't blow up logs.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		// Permanent: don't retry 4xx — auth, schema or contract failure.
		return fmt.Errorf("%w: yuril returned %d: %s",
			errPermanentStatus, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return fmt.Errorf("yuril returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
}

// translateIOC maps a QPot IOC into the shared IntelItem wire format.
// Returns (_, false) for IOC types the Yuril side does not recognise so
// we never send payloads that will just be rejected.
func translateIOC(ioc *database.IOC) (IntelItem, bool) {
	if ioc == nil {
		return IntelItem{}, false
	}
	t, ok := mapIntelType(ioc.Type)
	if !ok {
		return IntelItem{}, false
	}

	meta := map[string]string{}
	for k, v := range ioc.Metadata {
		meta[k] = v
	}
	if ioc.Honeypot != "" {
		meta["qpot_honeypot"] = ioc.Honeypot
	}
	if ioc.SourceIP != "" {
		meta["qpot_source_ip"] = ioc.SourceIP
	}
	if ioc.TechniqueID != "" {
		meta["mitre_technique"] = ioc.TechniqueID
	}

	return IntelItem{
		Type:       t,
		Value:      ioc.Value,
		Confidence: confidenceFromCount(ioc.Count),
		Context:    meta,
	}, true
}

// mapIntelType normalises a QPot IOC type to the Yuril vocabulary. Types
// that have no direct counterpart (credential, command, user_agent) are
// dropped rather than mis-translated.
func mapIntelType(t string) (string, bool) {
	switch strings.ToLower(t) {
	case "ip":
		return "ip", true
	case "domain":
		return "domain", true
	case "url":
		return "url", true
	case "hash":
		return "hash", true
	}
	return "", false
}

// confidenceFromCount turns the "how many times we saw this" count into a
// 0..100 confidence value. The mapping is deliberately conservative: a
// single sighting is low-confidence, repeat offenders ramp up quickly.
func confidenceFromCount(n int64) uint8 {
	switch {
	case n <= 0:
		return 25
	case n == 1:
		return 40
	case n < 5:
		return 60
	case n < 25:
		return 80
	default:
		return 95
	}
}
