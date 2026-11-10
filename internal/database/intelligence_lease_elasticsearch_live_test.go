package database

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// This opt-in gate executes the actual Painless transitions in an owned,
// disposable Elasticsearch node. It refuses any pre-existing checkpoint index
// and only deletes the index whose fresh creation this test acknowledged.
func TestElasticsearchIntelligenceLeaseLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_ELASTICSEARCH_LEASE") != "1" {
		t.Skip("set QPOT_TEST_ELASTICSEARCH_LEASE=1 and QPOT_TEST_ELASTICSEARCH_LEASE_URL to an owned disposable loopback Elasticsearch node")
	}
	endpoint, err := url.Parse(os.Getenv("QPOT_TEST_ELASTICSEARCH_LEASE_URL"))
	if err != nil || endpoint == nil || endpoint.Scheme != "http" && endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Path != "" && endpoint.Path != "/" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		t.Fatal("native lease gate requires a plain owned loopback Elasticsearch URL")
	}
	host := endpoint.Hostname()
	if host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
		t.Fatal("native lease gate refuses a non-loopback target")
	}
	if endpoint.Port() == "" {
		t.Fatal("native lease gate requires an explicit disposable-service port")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	makeDB := func(raw string) *Elasticsearch {
		return &Elasticsearch{baseURL: strings.TrimRight(raw, "/"), client: &http.Client{Timeout: 15 * time.Second}, config: &config.DatabaseConfig{
			Username: os.Getenv("QPOT_TEST_ELASTICSEARCH_LEASE_USER"), Password: os.Getenv("QPOT_TEST_ELASTICSEARCH_LEASE_PASSWORD"),
		}}
	}
	firstDB := makeDB(endpoint.String())
	createBody := []byte(`{"settings":{"number_of_shards":1,"number_of_replicas":0}}`)
	data, status, err := firstDB.esRequest(ctx, http.MethodPut, "/"+intelligenceCheckpointIndex, createBody)
	var created struct {
		Acknowledged       bool   `json:"acknowledged"`
		ShardsAcknowledged bool   `json:"shards_acknowledged"`
		Index              string `json:"index"`
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(data, &created) != nil || !created.Acknowledged || !created.ShardsAcknowledged || created.Index != intelligenceCheckpointIndex {
		t.Fatalf("native gate could not create a fresh owned checkpoint index (existing index is never reused): status%d err%v", status, err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_, status, err := firstDB.esRequest(cleanupCtx, http.MethodDelete, "/"+intelligenceCheckpointIndex, nil)
		if err != nil || status != http.StatusOK {
			t.Errorf("remove owned native lease index: status%d err%v", status, err)
		}
	})
	alias := *endpoint
	alias.Host = net.JoinHostPort("localhost", endpoint.Port())
	secondDB := makeDB(alias.String())
	// This odd value cannot survive conversion through float64. Native Painless
	// must retain exact integer counters during both acquisition and reservation.
	const minimumRevision = uint64(1<<54 + 3)
	lease, err := firstDB.AcquireIntelligenceLease(ctx, "native-owner-aaaaaaaa", 8*time.Second, minimumRevision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondDB.AcquireIntelligenceLease(ctx, "native-owner-bbbbbbbb", 8*time.Second, 0); !errors.Is(err, ErrIntelligenceLeaseBusy) {
		t.Fatalf("independent alias worker was not excluded: %v", err)
	}
	renewed, err := firstDB.RenewIntelligenceLease(ctx, lease, 8*time.Second)
	if err != nil || renewed.Fence != lease.Fence || renewed.ExpiresAt.Before(lease.ExpiresAt) {
		t.Fatalf("native renewal failed: %v", err)
	}
	lease = renewed
	revision, err := firstDB.ReserveIntelligenceRevision(ctx, lease, minimumRevision)
	if err != nil || revision != minimumRevision+1 {
		t.Fatalf("native global revision reservation failed: %d %v", revision, err)
	}
	largeState, _ := json.Marshal(map[string]string{"padding": strings.Repeat("x", intelligenceCheckpointChunkBytes+211)})
	pending := &IntelligenceCheckpoint{Revision: revision, State: largeState}
	if err := firstDB.SaveIntelligenceCheckpoint(WithIntelligenceLease(ctx, lease), pending); err != nil {
		t.Fatal(err)
	}
	for {
		err := firstDB.ValidateIntelligenceLease(ctx, lease)
		if errors.Is(err, ErrIntelligenceLeaseLost) {
			break
		}
		if err != nil {
			t.Fatalf("native expiry polling failed: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("database-owned lease never expired")
		case <-time.After(100 * time.Millisecond):
		}
	}
	successor, err := secondDB.AcquireIntelligenceLease(ctx, "native-owner-bbbbbbbb", 30*time.Second, 0)
	if err != nil || successor.Fence <= lease.Fence || successor.Namespace != lease.Namespace {
		t.Fatalf("native takeover failed: %+v %v", successor, err)
	}
	for name, call := range map[string]func() error{
		"renew":      func() error { _, err := firstDB.RenewIntelligenceLease(ctx, lease, time.Second); return err },
		"reserve":    func() error { _, err := firstDB.ReserveIntelligenceRevision(ctx, lease, 0); return err },
		"release":    func() error { return firstDB.ReleaseIntelligenceLease(ctx, lease) },
		"checkpoint": func() error { return firstDB.SaveIntelligenceCheckpoint(WithIntelligenceLease(ctx, lease), pending) },
	} {
		if err := call(); !errors.Is(err, ErrIntelligenceLeaseLost) {
			t.Errorf("native stale %s was accepted: %v", name, err)
		}
	}
	successorCtx := WithIntelligenceLease(ctx, successor)
	recovered, err := secondDB.LoadIntelligenceCheckpoint(successorCtx)
	if err != nil || !sameIntelligenceValue(recovered, pending) {
		t.Fatalf("native takeover lost the large durable pending WAL: %v", err)
	}
	conflicting := &IntelligenceCheckpoint{Revision: revision, State: json.RawMessage(`{"different":true}`)}
	conflictingDigest, err := intelligenceLeaseDigest(conflicting)
	if err != nil {
		t.Fatal(err)
	}
	if err := secondDB.intelligenceLeaseStoreCheckpoint(ctx, conflicting, conflictingDigest); err != nil {
		t.Fatalf("native conflict fixture was not stored successfully before its publication test: %v", err)
	}
	if err := secondDB.SaveIntelligenceCheckpoint(successorCtx, conflicting); err == nil {
		t.Fatal("native checkpoint accepted different bytes under the same reserved revision")
	}
	completionRevision, err := secondDB.ReserveIntelligenceRevision(ctx, successor, revision)
	if err != nil || completionRevision <= revision {
		t.Fatalf("native takeover reused a revision: %d %v", completionRevision, err)
	}
	completion := &IntelligenceCheckpoint{Revision: completionRevision, State: largeState, Complete: true}
	if err := secondDB.SaveIntelligenceCheckpoint(successorCtx, completion); err != nil {
		t.Fatal(err)
	}
	if err := secondDB.ReleaseIntelligenceLease(ctx, successor); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var resultMu sync.Mutex
	winners := 0
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := secondDB.AcquireIntelligenceLease(ctx, "native-contender-"+strconv.Itoa(n), 30*time.Second, 0)
			resultMu.Lock()
			defer resultMu.Unlock()
			if err == nil {
				winners++
			} else if !errors.Is(err, ErrIntelligenceLeaseBusy) {
				t.Errorf("native concurrent acquire failed unexpectedly: %v", err)
			}
		}(n)
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("native atomic contention admitted %d owners", winners)
	}
	current, err := secondDB.LoadIntelligenceCheckpoint(ctx)
	if err != nil || !sameIntelligenceValue(current, completion) {
		t.Fatalf("native contention changed checkpoint authority: %v", err)
	}
	t.Log("actual Elasticsearch Painless: alias exclusion, renewal/expiry/takeover, fencing, globally monotonic revisions, large immutable WAL and concurrent owners passed")
}
