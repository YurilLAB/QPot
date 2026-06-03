// Package proxy implements QPot's high-interaction SSH proxy ("HiFi") mode: a
// transparent Layer-4 TCP broker that splices an attacker's connection, byte for
// byte, to a disposable backend container running a REAL OpenSSH daemon.
//
// Why this exists (the protocol-fingerprinting gap):
//
// Low/medium-interaction SSH honeypots (Cowrie, Kippo, and even Cowrie's own
// "proxy" backend mode) terminate the attacker's SSH handshake in a Python
// transport (Twisted/conch). Vetterl & Clayton (USENIX WOOT '18) showed that the
// transport layer of these emulators answers protocol-level edge cases (version
// strings, KEXINIT ordering, malformed packets) differently from OpenSSH, so a
// SINGLE crafted packet reliably classifies the box as a honeypot — regardless of
// how convincing the post-login shell is. Cowrie proxy mode does NOT close this:
// the attacker still completes the SSH handshake against Cowrie's Python server,
// which then re-originates a second SSH session to the backend.
//
// QPot's HiFi mode closes the gap by never speaking SSH at all on the
// attacker-facing path. The broker performs a pure TCP splice: it copies opaque
// bytes between the attacker and a backend `sshd`, so the attacker's handshake
// terminates at genuine OpenSSH. There is no emulated transport to fingerprint.
//
// Security posture: because the broker treats the stream as opaque bytes and
// never parses SSH, its attack surface is tiny (no protocol parser to exploit)
// and it cannot be coerced into dialing attacker-chosen hosts (backends come
// only from a fixed, operator-configured pool — no SSRF). The genuinely
// dangerous part is the backend (real code execution), which the orchestration
// layer isolates (gVisor/Kata), pins to an egress-locked internal network, caps
// for resources, and resets between sessions. See doc/ssh-hifi-proxy.md.
package proxy

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Event is a structured record of one brokered connection (or a rejected
// attempt). It is emitted as newline-delimited JSON so the Vector collector can
// ingest it exactly like any other honeypot log. Every field is derived from
// trusted sources (kernel-reported peer address, operator-configured backend id,
// byte counters) — never from attacker-supplied stream content — so there is no
// log-injection surface, and the bytes themselves are never logged.
type Event struct {
	Timestamp  string `json:"timestamp"`             // RFC3339Nano, UTC
	EventType  string `json:"event_type"`            // see Event* constants
	Honeypot   string `json:"honeypot"`              // logical honeypot name (e.g. "ssh-proxy")
	SrcIP      string `json:"src_ip"`                // attacker IP (from RemoteAddr)
	SrcPort    int    `json:"src_port"`              // attacker source port
	Backend    string `json:"backend,omitempty"`     // backend id the session was spliced to
	BytesIn    int64  `json:"bytes_in,omitempty"`    // attacker -> backend bytes
	BytesOut   int64  `json:"bytes_out,omitempty"`   // backend -> attacker bytes
	DurationMs int64  `json:"duration_ms,omitempty"` // wall-clock session length
	Reason     string `json:"reason,omitempty"`      // why a connection was rejected/closed
}

// Event type constants. These are stable strings the analytics layer keys on.
const (
	// EventSession is a completed brokered session (attacker reached a backend).
	EventSession = "ssh_proxy_session"
	// EventRejected is a connection refused before it ever reached a backend
	// (rate limit, concurrency cap, or pool exhaustion) — a useful abuse signal.
	EventRejected = "ssh_proxy_rejected"
	// EventBackendError is a connection accepted but for which the backend dial
	// failed — an operational signal (backend down), not attacker-controlled.
	EventBackendError = "ssh_proxy_backend_error"
)

// Reasons a connection is rejected or torn down. Kept as constants so dashboards
// can group on them without matching free-form text.
const (
	ReasonRateLimited      = "rate_limited"
	ReasonGlobalCap        = "max_concurrent_reached"
	ReasonPerIPCap         = "max_concurrent_per_ip_reached"
	ReasonPoolExhausted    = "no_backend_available"
	ReasonBackendDialError = "backend_dial_failed"
	ReasonIdleTimeout      = "idle_timeout"
	ReasonSessionTimeout   = "max_session_reached"
	ReasonClosed           = "closed"
)

// EventSink receives Events. Implementations must be safe for concurrent use by
// many connection goroutines.
type EventSink interface {
	Emit(Event)
}

// JSONSink writes each Event as a single JSON line to an io.Writer. Writes are
// serialized by a mutex so concurrent sessions never interleave a line.
type JSONSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewJSONSink returns a JSONSink writing newline-delimited JSON to w.
func NewJSONSink(w io.Writer) *JSONSink {
	return &JSONSink{w: w}
}

// Emit serializes one Event as a JSON line. Encoding errors are dropped rather
// than propagated: logging must never be able to take down the broker, and the
// only inputs are our own trusted fields, so an error here is not actionable.
func (s *JSONSink) Emit(e Event) {
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	s.mu.Lock()
	_, _ = s.w.Write(b)
	s.mu.Unlock()
}

// nopSink discards events; used when no sink is configured so the broker code
// never has to nil-check.
type nopSink struct{}

func (nopSink) Emit(Event) {}
