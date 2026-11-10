package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

var (
	ErrIntelligenceLeaseBusy        = errors.New("intelligence database already has an active worker")
	ErrIntelligenceLeaseLost        = errors.New("intelligence database worker lease was lost")
	ErrIntelligenceLeaseUnavailable = errors.New("intelligence database cannot provide atomic worker coordination")
)

// IntelligenceLease is a database-issued capability for one worker lifetime.
// Its private handle binds it to the issuing store and an immutable durable WAL.
type IntelligenceLease struct {
	Owner     string
	Fence     uint64
	ExpiresAt time.Time
	Namespace string
	handle    *intelligenceLeaseHandle
}

// IntelligenceLeaser coordinates all runtime workers through their database.
// Implementations must use an atomic owner/epoch/expiry condition and reserve
// revisions globally; a local file lock or read-then-write election is insufficient.
type IntelligenceLeaser interface {
	AcquireIntelligenceLease(context.Context, string, time.Duration, uint64) (IntelligenceLease, error)
	RenewIntelligenceLease(context.Context, IntelligenceLease, time.Duration) (IntelligenceLease, error)
	ReleaseIntelligenceLease(context.Context, IntelligenceLease) error
	ReserveIntelligenceRevision(context.Context, IntelligenceLease, uint64) (uint64, error)
	ValidateIntelligenceLease(context.Context, IntelligenceLease) error
}

type intelligenceLeaseContextKey struct{}

// WithIntelligenceLease attaches an issued lease to worker-owned database calls.
func WithIntelligenceLease(ctx context.Context, lease IntelligenceLease) context.Context {
	return context.WithValue(ctx, intelligenceLeaseContextKey{}, lease)
}

type intelligenceLeaseHandle struct {
	backend   intelligenceLeaseBackend
	ops       sync.Mutex
	mu        sync.RWMutex
	payload   []byte
	digest    string
	owner     string
	fence     uint64
	namespace string
}

func intelligenceLeaseFromContext(ctx context.Context) (IntelligenceLease, bool) {
	lease, ok := ctx.Value(intelligenceLeaseContextKey{}).(IntelligenceLease)
	return lease, ok
}

func intelligenceLeaseOperationFor(kind string, lease IntelligenceLease) (intelligenceLeaseOperation, error) {
	nonce, err := intelligenceLeaseNonce()
	return intelligenceLeaseOperation{Kind: kind, Owner: lease.Owner, Fence: lease.Fence, Namespace: lease.Namespace, Nonce: nonce}, err
}

func intelligenceLeaseIssuedBy(lease IntelligenceLease, backend intelligenceLeaseBackend) bool {
	h := lease.handle
	return h != nil && h.backend == backend && h.owner == lease.Owner && h.fence == lease.Fence && h.namespace == lease.Namespace
}

func acquireIntelligenceLease(ctx context.Context, backend intelligenceLeaseBackend, owner string, ttl time.Duration, minimum uint64) (IntelligenceLease, error) {
	if !intelligenceLeaseOwner(owner) || minimum >= math.MaxInt64-1 {
		return IntelligenceLease{}, fmt.Errorf("invalid intelligence lease acquisition")
	}
	millis, err := intelligenceLeaseTTL(ttl)
	if err != nil {
		return IntelligenceLease{}, err
	}
	nonce, err := intelligenceLeaseNonce()
	if err != nil {
		return IntelligenceLease{}, err
	}
	namespace, err := intelligenceLeaseNonce()
	if err != nil {
		return IntelligenceLease{}, err
	}
	s, err := backend.intelligenceLeaseMutate(ctx, intelligenceLeaseOperation{Kind: "acquire", Owner: owner, TTLMillis: millis, Minimum: minimum, Nonce: nonce, Namespace: namespace})
	if err != nil {
		return IntelligenceLease{}, err
	}
	if validateIntelligenceLeaseState(s) != nil || s.Owner != owner || s.Operation != nonce || s.ExpiresMS <= 0 || s.Reserved < minimum {
		return IntelligenceLease{}, ErrIntelligenceLeaseLost
	}
	h := &intelligenceLeaseHandle{backend: backend, owner: s.Owner, fence: s.Fence, namespace: s.Namespace}
	return IntelligenceLease{Owner: s.Owner, Fence: s.Fence, ExpiresAt: time.UnixMilli(s.ExpiresMS).UTC(), Namespace: s.Namespace, handle: h}, nil
}

func renewIntelligenceLease(ctx context.Context, backend intelligenceLeaseBackend, lease IntelligenceLease, ttl time.Duration) (IntelligenceLease, error) {
	if !intelligenceLeaseIssuedBy(lease, backend) {
		return IntelligenceLease{}, ErrIntelligenceLeaseLost
	}
	lease.handle.ops.Lock()
	defer lease.handle.ops.Unlock()
	op, err := intelligenceLeaseOperationFor("renew", lease)
	if err != nil {
		return IntelligenceLease{}, err
	}
	op.TTLMillis, err = intelligenceLeaseTTL(ttl)
	if err != nil {
		return IntelligenceLease{}, err
	}
	s, err := backend.intelligenceLeaseMutate(ctx, op)
	if err != nil {
		return IntelligenceLease{}, err
	}
	if validateIntelligenceLeaseState(s) != nil || s.Operation != op.Nonce || s.Owner != lease.Owner || s.Fence != lease.Fence || s.Namespace != lease.Namespace {
		return IntelligenceLease{}, ErrIntelligenceLeaseLost
	}
	lease.ExpiresAt = time.UnixMilli(s.ExpiresMS).UTC()
	return lease, nil
}

func releaseIntelligenceLease(ctx context.Context, backend intelligenceLeaseBackend, lease IntelligenceLease) error {
	if !intelligenceLeaseIssuedBy(lease, backend) {
		return ErrIntelligenceLeaseLost
	}
	lease.handle.ops.Lock()
	defer lease.handle.ops.Unlock()
	op, err := intelligenceLeaseOperationFor("release", lease)
	if err != nil {
		return err
	}
	s, err := backend.intelligenceLeaseMutate(ctx, op)
	if err != nil {
		return err
	}
	if s.Operation != op.Nonce || s.Owner != "" || s.Fence != lease.Fence || s.Namespace != lease.Namespace {
		return ErrIntelligenceLeaseLost
	}
	return nil
}

func reserveIntelligenceRevision(ctx context.Context, backend intelligenceLeaseBackend, lease IntelligenceLease, minimum uint64) (uint64, error) {
	if !intelligenceLeaseIssuedBy(lease, backend) || minimum >= math.MaxInt64-1 {
		return 0, ErrIntelligenceLeaseLost
	}
	lease.handle.ops.Lock()
	defer lease.handle.ops.Unlock()
	op, err := intelligenceLeaseOperationFor("reserve", lease)
	if err != nil {
		return 0, err
	}
	op.Minimum = minimum
	s, err := backend.intelligenceLeaseMutate(ctx, op)
	if err != nil {
		return 0, err
	}
	if validateIntelligenceLeaseState(s) != nil || s.Operation != op.Nonce || s.Owner != lease.Owner || s.Fence != lease.Fence || s.Namespace != lease.Namespace || s.Reserved <= minimum {
		return 0, ErrIntelligenceLeaseLost
	}
	return s.Reserved, nil
}

func validateIntelligenceLease(ctx context.Context, backend intelligenceLeaseBackend, lease IntelligenceLease) (*intelligenceLeaseState, error) {
	if !intelligenceLeaseIssuedBy(lease, backend) {
		return nil, ErrIntelligenceLeaseLost
	}
	s, now, err := backend.intelligenceLeaseRead(ctx)
	if err != nil {
		return nil, err
	}
	if s == nil || validateIntelligenceLeaseState(*s) != nil || s.Owner != lease.Owner || s.Fence != lease.Fence || s.Namespace != lease.Namespace || s.ExpiresMS <= now.UnixMilli() {
		return nil, ErrIntelligenceLeaseLost
	}
	return s, nil
}

func intelligenceLeaseLoad(ctx context.Context, backend intelligenceLeaseBackend) (*IntelligenceCheckpoint, bool, error) {
	lease, leased := intelligenceLeaseFromContext(ctx)
	var s *intelligenceLeaseState
	var err error
	if leased {
		s, err = validateIntelligenceLease(ctx, backend, lease)
	} else {
		s, _, err = backend.intelligenceLeaseRead(ctx)
	}
	if err != nil {
		return nil, true, err
	}
	if s == nil {
		return nil, false, nil
	}
	if validateIntelligenceLeaseState(*s) != nil {
		return nil, true, fmt.Errorf("invalid intelligence lease control record")
	}
	if s.CheckpointRevision == 0 {
		return nil, true, nil
	}
	cp, err := backend.intelligenceLeaseLoadCheckpoint(ctx, s.CheckpointRevision, s.CheckpointDigest)
	if err != nil {
		return nil, true, err
	}
	if cp == nil || cp.Revision != s.CheckpointRevision {
		return nil, true, fmt.Errorf("missing intelligence checkpoint payload")
	}
	digest, err := intelligenceLeaseDigest(cp)
	if err != nil || digest != s.CheckpointDigest {
		return nil, true, fmt.Errorf("intelligence checkpoint content mismatch")
	}
	if leased {
		if err := cacheIntelligenceCheckpoint(lease, cp, digest); err != nil {
			return nil, true, err
		}
	}
	return cp, true, nil
}

func intelligenceLeaseSave(ctx context.Context, backend intelligenceLeaseBackend, cp *IntelligenceCheckpoint) (bool, error) {
	lease, leased := intelligenceLeaseFromContext(ctx)
	if !leased {
		s, _, err := backend.intelligenceLeaseRead(ctx)
		if err != nil {
			return true, err
		}
		if s != nil {
			return true, ErrIntelligenceLeaseLost
		}
		return false, nil
	}
	if _, err := validateIntelligenceLease(ctx, backend, lease); err != nil {
		return true, err
	}
	if cp == nil || cp.Revision == 0 || cp.Revision >= math.MaxInt64 {
		return true, fmt.Errorf("invalid intelligence checkpoint revision")
	}
	data, err := json.Marshal(cp)
	if err != nil {
		return true, err
	}
	var immutable IntelligenceCheckpoint
	if err := json.Unmarshal(data, &immutable); err != nil {
		return true, err
	}
	cp = &immutable
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	// The record is immutable and may become an orphan after ownership loss.
	// Only the atomic manifest publication below makes it authoritative.
	if err := backend.intelligenceLeaseStoreCheckpoint(ctx, cp, digest); err != nil {
		return true, err
	}
	err = func() error {
		lease.handle.ops.Lock()
		defer lease.handle.ops.Unlock()
		op, err := intelligenceLeaseOperationFor("publish", lease)
		if err != nil {
			return err
		}
		op.Revision, op.Digest = cp.Revision, digest
		s, err := backend.intelligenceLeaseMutate(ctx, op)
		if err != nil {
			return err
		}
		if s.Operation != op.Nonce || s.Owner != lease.Owner || s.Fence != lease.Fence || s.Namespace != lease.Namespace || s.CheckpointRevision != cp.Revision || s.CheckpointDigest != digest {
			return ErrIntelligenceLeaseLost
		}
		return cacheIntelligenceCheckpoint(lease, cp, digest)
	}()
	if err != nil {
		return true, err
	}
	if cp.Complete {
		if gc, ok := backend.(interface {
			intelligenceLeaseGCCheckpoints(context.Context, uint64) error
		}); ok {
			// Publication is already durable. Maintenance neither holds the
			// ownership-operation mutex nor changes its acknowledged outcome.
			maintenance, cancel := context.WithTimeout(ctx, 2*time.Second)
			_ = gc.intelligenceLeaseGCCheckpoints(maintenance, cp.Revision)
			cancel()
		}
	}
	return true, nil
}

func cacheIntelligenceCheckpoint(lease IntelligenceLease, cp *IntelligenceCheckpoint, digest string) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	lease.handle.mu.Lock()
	lease.handle.payload, lease.handle.digest = data, digest
	lease.handle.mu.Unlock()
	return nil
}

func intelligencePreparedCheckpoint(ctx context.Context, backend intelligenceLeaseBackend) (*IntelligenceCheckpoint, bool, error) {
	lease, leased := intelligenceLeaseFromContext(ctx)
	if !leased {
		s, _, err := backend.intelligenceLeaseRead(ctx)
		if err != nil {
			return nil, false, err
		}
		if s != nil {
			return nil, false, ErrIntelligenceLeaseLost
		}
		return nil, false, nil
	}
	s, err := validateIntelligenceLease(ctx, backend, lease)
	if err != nil {
		return nil, true, err
	}
	lease.handle.mu.RLock()
	data, digest := append([]byte(nil), lease.handle.payload...), lease.handle.digest
	lease.handle.mu.RUnlock()
	var cp IntelligenceCheckpoint
	if len(data) == 0 || digest != s.CheckpointDigest || json.Unmarshal(data, &cp) != nil || cp.Revision != s.CheckpointRevision || cp.Complete {
		return nil, true, ErrIntelligenceLeaseLost
	}
	return &cp, true, nil
}

func sameIntelligenceValue(a, b any) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	return err == nil && string(x) == string(y)
}

func intelligenceLeaseIOCs(ctx context.Context, backend intelligenceLeaseBackend, revision uint64, rows []*IOC) ([]*IOC, error) {
	cp, leased, err := intelligencePreparedCheckpoint(ctx, backend)
	if err != nil {
		return nil, err
	}
	if !leased {
		return rows, nil
	}
	if cp.Revision != revision || !(len(cp.IOCs) == 0 && len(rows) == 0) && !sameIntelligenceValue(cp.IOCs, rows) {
		return nil, ErrIntelligenceLeaseLost
	}
	return cp.IOCs, nil
}

func intelligenceLeaseSessions(ctx context.Context, backend intelligenceLeaseBackend, revision uint64, rows []*TTPSession) ([]*TTPSession, error) {
	cp, leased, err := intelligencePreparedCheckpoint(ctx, backend)
	if err != nil {
		return nil, err
	}
	if !leased {
		return rows, nil
	}
	if cp.Revision != revision || !(len(cp.Sessions) == 0 && len(rows) == 0) && !sameIntelligenceValue(cp.Sessions, rows) {
		return nil, ErrIntelligenceLeaseLost
	}
	return cp.Sessions, nil
}

func intelligenceLeaseEvents(ctx context.Context, backend intelligenceLeaseBackend, rows []*Event) ([]*Event, error) {
	cp, leased, err := intelligencePreparedCheckpoint(ctx, backend)
	if err != nil {
		return nil, err
	}
	if !leased {
		return rows, nil
	}
	if !(len(cp.Events) == 0 && len(rows) == 0) && !sameIntelligenceValue(cp.Events, rows) {
		return nil, ErrIntelligenceLeaseLost
	}
	return cp.Events, nil
}

func intelligenceLeaseEvent(ctx context.Context, backend intelligenceLeaseBackend, row *Event) (*Event, error) {
	cp, leased, err := intelligencePreparedCheckpoint(ctx, backend)
	if err != nil {
		return nil, err
	}
	if !leased {
		return row, nil
	}
	if row == nil || row.ID == "" {
		return nil, ErrIntelligenceLeaseLost
	}
	var match *Event
	for _, event := range cp.Events {
		if event != nil && event.ID == row.ID {
			if match != nil || !sameIntelligenceValue(event, row) {
				return nil, ErrIntelligenceLeaseLost
			}
			match = event
		}
	}
	if match == nil {
		return nil, ErrIntelligenceLeaseLost
	}
	return match, nil
}

// Backend adapters keep this small control record in an atomic row/document.
// Full checkpoint bytes live separately under their immutable revision/digest.
type intelligenceLeaseState struct {
	Namespace          string `json:"namespace"`
	Owner              string `json:"owner"`
	Fence              uint64 `json:"fence"`
	ExpiresMS          int64  `json:"expires_ms"`
	Reserved           uint64 `json:"reserved"`
	CheckpointRevision uint64 `json:"checkpoint_revision"`
	CheckpointDigest   string `json:"checkpoint_digest"`
	Operation          string `json:"operation"`
}

type intelligenceLeaseOperation struct {
	Kind      string `json:"kind"`
	Owner     string `json:"owner"`
	Fence     uint64 `json:"fence"`
	Namespace string `json:"namespace"`
	TTLMillis int64  `json:"ttl_ms"`
	Minimum   uint64 `json:"minimum"`
	Revision  uint64 `json:"revision"`
	Digest    string `json:"digest"`
	Nonce     string `json:"nonce"`
}

// Mutate must evaluate expiry using database time at its atomic mutation,
// not merely call Read followed by an unconditional write. Read also returns
// database time; a caller's wall clock never authorizes ownership.
type intelligenceLeaseBackend interface {
	intelligenceLeaseRead(context.Context) (*intelligenceLeaseState, time.Time, error)
	intelligenceLeaseMutate(context.Context, intelligenceLeaseOperation) (intelligenceLeaseState, error)
	intelligenceLeaseStoreCheckpoint(context.Context, *IntelligenceCheckpoint, string) error
	intelligenceLeaseLoadCheckpoint(context.Context, uint64, string) (*IntelligenceCheckpoint, error)
}

func intelligenceLeaseNonce() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}

func intelligenceLeaseTTL(ttl time.Duration) (int64, error) {
	if ttl < time.Second || ttl > 5*time.Minute {
		return 0, fmt.Errorf("intelligence lease TTL must be between one second and five minutes")
	}
	return ttl.Milliseconds(), nil
}

func intelligenceLeaseOwner(owner string) bool {
	if len(owner) < 16 || len(owner) > 128 {
		return false
	}
	for _, c := range owner {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func intelligenceLeaseDigest(cp *IntelligenceCheckpoint) (string, error) {
	data, err := json.Marshal(cp)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func validateIntelligenceLeaseState(s intelligenceLeaseState) error {
	namespace, namespaceErr := hex.DecodeString(s.Namespace)
	digest, digestErr := hex.DecodeString(s.CheckpointDigest)
	if len(namespace) != 16 || namespaceErr != nil || s.Fence == 0 || s.Fence >= math.MaxInt64 || s.Reserved >= math.MaxInt64 || s.CheckpointRevision > s.Reserved || s.CheckpointRevision == 0 && s.CheckpointDigest != "" || s.CheckpointRevision != 0 && (digestErr != nil || len(digest) != 32) || s.Owner == "" && s.ExpiresMS != 0 || s.Owner != "" && (!intelligenceLeaseOwner(s.Owner) || s.ExpiresMS <= 0) {
		return fmt.Errorf("invalid intelligence lease control record")
	}
	return nil
}

// applyIntelligenceLeaseOperation is the shared transition specification. SQL
// adapters use it while holding their atomic row lock; CAS adapters additionally
// enforce the observed record version and expiry at the actual write.
func applyIntelligenceLeaseOperation(current *intelligenceLeaseState, op intelligenceLeaseOperation, now time.Time) (intelligenceLeaseState, error) {
	var s intelligenceLeaseState
	if current != nil {
		s = *current
	}
	nowMS := now.UnixMilli()
	if nowMS < 0 || op.Nonce == "" {
		return s, fmt.Errorf("invalid intelligence lease operation")
	}
	if op.Kind == "acquire" {
		if !intelligenceLeaseOwner(op.Owner) || op.TTLMillis < 1000 || op.TTLMillis > 300000 || op.Minimum >= math.MaxInt64-1 {
			return s, fmt.Errorf("invalid intelligence lease acquisition")
		}
		if current == nil {
			s.Namespace = op.Namespace
		} else if err := validateIntelligenceLeaseState(s); err != nil {
			return s, err
		}
		if current != nil && s.Owner != "" && s.ExpiresMS > nowMS {
			return s, ErrIntelligenceLeaseBusy
		}
		if s.Fence >= math.MaxInt64-1 || nowMS > math.MaxInt64-op.TTLMillis {
			return s, fmt.Errorf("intelligence lease counter exhausted")
		}
		s.Fence++
		s.Owner, s.ExpiresMS = op.Owner, nowMS+op.TTLMillis
		s.Reserved = max(s.Reserved, op.Minimum, s.CheckpointRevision)
	} else {
		if current == nil || validateIntelligenceLeaseState(s) != nil || s.Owner != op.Owner || s.Fence != op.Fence || s.Namespace != op.Namespace || s.Owner == "" || s.ExpiresMS <= nowMS {
			return s, ErrIntelligenceLeaseLost
		}
		switch op.Kind {
		case "renew":
			if op.TTLMillis < 1000 || op.TTLMillis > 300000 || nowMS > math.MaxInt64-op.TTLMillis {
				return s, fmt.Errorf("invalid intelligence lease renewal")
			}
			s.ExpiresMS = nowMS + op.TTLMillis
		case "release":
			s.Owner, s.ExpiresMS = "", 0
		case "reserve":
			minimum := max(s.Reserved, s.CheckpointRevision, op.Minimum)
			if minimum >= math.MaxInt64-1 {
				return s, fmt.Errorf("intelligence revision exhausted")
			}
			s.Reserved = minimum + 1
		case "publish":
			if op.Revision == 0 || op.Revision > s.Reserved || op.Revision < s.CheckpointRevision || len(op.Digest) != 64 {
				return s, fmt.Errorf("invalid intelligence checkpoint publication")
			}
			if op.Revision == s.CheckpointRevision && op.Digest != s.CheckpointDigest {
				return s, fmt.Errorf("conflicting intelligence checkpoint payload")
			}
			s.CheckpointRevision, s.CheckpointDigest = op.Revision, op.Digest
		default:
			return s, fmt.Errorf("unknown intelligence lease operation")
		}
	}
	s.Operation = op.Nonce
	return s, nil
}

func (ch *ClickHouse) AcquireIntelligenceLease(ctx context.Context, owner string, ttl time.Duration, minimum uint64) (IntelligenceLease, error) {
	return acquireIntelligenceLease(ctx, ch, owner, ttl, minimum)
}
func (ch *ClickHouse) RenewIntelligenceLease(ctx context.Context, lease IntelligenceLease, ttl time.Duration) (IntelligenceLease, error) {
	return renewIntelligenceLease(ctx, ch, lease, ttl)
}
func (ch *ClickHouse) ReleaseIntelligenceLease(ctx context.Context, lease IntelligenceLease) error {
	return releaseIntelligenceLease(ctx, ch, lease)
}
func (ch *ClickHouse) ReserveIntelligenceRevision(ctx context.Context, lease IntelligenceLease, minimum uint64) (uint64, error) {
	return reserveIntelligenceRevision(ctx, ch, lease, minimum)
}
func (ch *ClickHouse) ValidateIntelligenceLease(ctx context.Context, lease IntelligenceLease) error {
	_, err := validateIntelligenceLease(ctx, ch, lease)
	return err
}

func (ts *TimescaleDB) AcquireIntelligenceLease(ctx context.Context, owner string, ttl time.Duration, minimum uint64) (IntelligenceLease, error) {
	return acquireIntelligenceLease(ctx, ts, owner, ttl, minimum)
}
func (ts *TimescaleDB) RenewIntelligenceLease(ctx context.Context, lease IntelligenceLease, ttl time.Duration) (IntelligenceLease, error) {
	return renewIntelligenceLease(ctx, ts, lease, ttl)
}
func (ts *TimescaleDB) ReleaseIntelligenceLease(ctx context.Context, lease IntelligenceLease) error {
	return releaseIntelligenceLease(ctx, ts, lease)
}
func (ts *TimescaleDB) ReserveIntelligenceRevision(ctx context.Context, lease IntelligenceLease, minimum uint64) (uint64, error) {
	return reserveIntelligenceRevision(ctx, ts, lease, minimum)
}
func (ts *TimescaleDB) ValidateIntelligenceLease(ctx context.Context, lease IntelligenceLease) error {
	_, err := validateIntelligenceLease(ctx, ts, lease)
	return err
}

func (es *Elasticsearch) AcquireIntelligenceLease(ctx context.Context, owner string, ttl time.Duration, minimum uint64) (IntelligenceLease, error) {
	return acquireIntelligenceLease(ctx, es, owner, ttl, minimum)
}
func (es *Elasticsearch) RenewIntelligenceLease(ctx context.Context, lease IntelligenceLease, ttl time.Duration) (IntelligenceLease, error) {
	return renewIntelligenceLease(ctx, es, lease, ttl)
}
func (es *Elasticsearch) ReleaseIntelligenceLease(ctx context.Context, lease IntelligenceLease) error {
	return releaseIntelligenceLease(ctx, es, lease)
}
func (es *Elasticsearch) ReserveIntelligenceRevision(ctx context.Context, lease IntelligenceLease, minimum uint64) (uint64, error) {
	return reserveIntelligenceRevision(ctx, es, lease, minimum)
}
func (es *Elasticsearch) ValidateIntelligenceLease(ctx context.Context, lease IntelligenceLease) error {
	_, err := validateIntelligenceLease(ctx, es, lease)
	return err
}
