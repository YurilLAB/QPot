package cluster

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSanitizeClusterConfigNil(t *testing.T) {
	c := sanitizeClusterConfig(nil)
	if c == nil || c.GossipInterval <= 0 || c.SyncInterval <= 0 || c.SuspicionMult < 1 {
		t.Fatalf("nil config not defaulted to a sane config: %+v", c)
	}
}

func TestSanitizeClusterConfigClampsHostileValues(t *testing.T) {
	bad := &ClusterConfig{
		GossipInterval: 0,                // would panic time.NewTicker
		SyncInterval:   -5 * time.Second, // negative
		SuspicionMult:  1 << 30,          // overflow driver for the failure deadline
		ProbeInterval:  0,
		ProbeTimeout:   0,
		RetransmitMult: -1,
	}
	c := sanitizeClusterConfig(bad)

	if c.GossipInterval <= 0 || c.GossipInterval > maxGossipInterval {
		t.Errorf("GossipInterval not clamped: %v", c.GossipInterval)
	}
	if c.SyncInterval <= 0 {
		t.Errorf("SyncInterval not clamped: %v", c.SyncInterval)
	}
	if c.SuspicionMult < minSuspicionMult || c.SuspicionMult > maxSuspicionMult {
		t.Errorf("SuspicionMult not clamped: %d", c.SuspicionMult)
	}

	// The failure-detection deadline computation (gossip()) must not overflow
	// to a future/negative time with the clamped values.
	deadline := time.Now().Add(-3 * c.GossipInterval * time.Duration(c.SuspicionMult*10))
	if !deadline.Before(time.Now()) {
		t.Errorf("failure deadline is not in the past (overflow): %v", deadline)
	}
}

// TestClusterJoinBodyLimit ensures an oversized join body is rejected rather
// than read entirely into memory (DoS guard on the unauthenticated endpoint).
func TestClusterJoinBodyLimit(t *testing.T) {
	m := &Manager{}
	huge := strings.NewReader(strings.Repeat("A", maxClusterBodyBytes+1024))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/join", huge)
	rec := httptest.NewRecorder()

	m.handleJoinHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("oversized join body was accepted (status 200); MaxBytesReader not enforced")
	}
}
