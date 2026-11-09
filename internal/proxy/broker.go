package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DialFunc dials a backend. It is injectable so tests can supply in-memory
// backends and so the production path can pin a timeout. It is only ever called
// with operator-configured backend addresses, never attacker input.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Config configures a Broker. Zero values get safe defaults via withDefaults.
type Config struct {
	// Honeypot is the logical name used in emitted events (e.g. "ssh-proxy").
	Honeypot string

	// IdleTimeout tears down a session after this long with no bytes in a
	// direction. Bounds slowloris / abandoned sessions. Default 15m.
	IdleTimeout time.Duration
	// MaxSession is an absolute lifetime cap on a cell, from its first
	// connection, regardless of activity: its connections close then. Bounds
	// a single attacker monopolizing a backend. Default 2h.
	MaxSession time.Duration
	// CellHold is how long a source keeps its cell after its last connection
	// closes, so its later connections find the state it left (see cellSet).
	// Zero gives every connection a cell of its own, reset when it closes.
	CellHold time.Duration
	// DialTimeout bounds the backend connect. Default 5s.
	DialTimeout time.Duration

	// Admission control (see limiter). Defaults: 5 conns/sec burst 10 per IP,
	// 3 concurrent per IP, 128 concurrent globally.
	RatePerSecPerIP float64
	BurstPerIP      float64
	MaxConcurrentIP int
	MaxConcurrent   int
	BufferSize      int // splice buffer per direction; default 32 KiB

	// Sink receives connection events; nil discards them.
	Sink EventSink
	// Gate supplies the counter snapshot recorded by the pool's lease hook.
	// It never grants the broker authority to recreate containers itself.
	Gate *GenerationGate
	// Dial overrides the backend dialer; nil uses a net.Dialer with DialTimeout.
	Dial DialFunc
}

func (c *Config) withDefaults() {
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 15 * time.Minute
	}
	if c.MaxSession <= 0 {
		c.MaxSession = 2 * time.Hour
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.RatePerSecPerIP <= 0 {
		c.RatePerSecPerIP = 5
	}
	if c.BurstPerIP <= 0 {
		c.BurstPerIP = 10
	}
	if c.MaxConcurrentIP <= 0 {
		c.MaxConcurrentIP = 3
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 128
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 32 * 1024
	}
	if c.Sink == nil {
		c.Sink = nopSink{}
	}
}

// Broker is a transparent Layer-4 TCP splice that forwards opaque bytes between
// an attacker and a pooled real-OpenSSH backend. It never parses the stream, so
// the attacker's SSH handshake terminates at genuine OpenSSH (no emulated
// transport to fingerprint), and the broker itself has no protocol parser to
// attack.
type Broker struct {
	cfg     Config
	pool    *Pool
	cells   *cellSet
	lim     *limiter
	dial    DialFunc
	wg      sync.WaitGroup
	closing atomic.Bool
}

// NewBroker builds a Broker over a backend pool and config.
func NewBroker(cfg Config, pool *Pool) *Broker {
	cfg.withDefaults()
	b := &Broker{
		cfg:  cfg,
		pool: pool,
		lim:  newLimiter(cfg.RatePerSecPerIP, cfg.BurstPerIP, cfg.MaxConcurrentIP, cfg.MaxConcurrent),
		dial: cfg.Dial,
	}
	b.cells = newCellSet(pool, cfg.Gate, max(cfg.CellHold, 0), cfg.MaxSession, b.freeCell)
	if b.dial == nil {
		d := &net.Dialer{Timeout: cfg.DialTimeout}
		b.dial = d.DialContext
	}
	return b
}

// freeCell asks the host to recreate a cell, then hands its backend back to
// the pool, which takes it into rotation only once the recreation is seen.
// The request goes first: the pool's reset waits for what it starts.
func (b *Broker) freeCell(c *cell, reason string) {
	b.cfg.Sink.Emit(Event{EventType: EventCellReset, Honeypot: b.cfg.Honeypot,
		Backend: c.backend.ID, Generation: c.generation, Reason: reason})
	if c.quarantine {
		b.pool.Quarantine(c.backend)
		return
	}
	b.pool.Release(c.backend)
}

// Serve accepts connections on ln until ctx is cancelled or ln is closed, then
// waits for in-flight sessions to drain. It always closes ln before returning.
func (b *Broker) Serve(ctx context.Context, ln net.Listener) error {
	// A background sweeper bounds the limiter's per-IP map under source churn.
	sweepCtx, stopSweep := context.WithCancel(ctx)
	defer stopSweep()
	go b.sweepLoop(sweepCtx)

	// Closing the listener unblocks Accept on shutdown.
	go func() {
		<-ctx.Done()
		b.closing.Store(true)
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// A closed listener never recovers: stop, whoever closed it.
			// Treating net.ErrClosed as transient spun here forever.
			if b.closing.Load() || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			// Transient accept error (e.g. EMFILE): back off briefly and retry
			// rather than spin or die.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.handle(ctx, conn)
		}()
	}

	b.wg.Wait()
	b.cells.close()
	return ctx.Err()
}

func (b *Broker) sweepLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.lim.sweep()
			// Rejections thinned out since the last logged one, when none
			// followed to carry the count: one summary line (it has no
			// source address, so it stays in the session log).
			if n := b.lim.takeSuppressed(); n > 0 {
				b.cfg.Sink.Emit(Event{EventType: EventRejected, Honeypot: b.cfg.Honeypot,
					Reason: ReasonRejectionsSuppressed, Suppressed: n})
			}
		}
	}
}

// handle processes one attacker connection: admission control, backend lease,
// dial, and the bidirectional splice. A panic in here is contained so one bad
// session can never crash the broker.
func (b *Broker) handle(ctx context.Context, client net.Conn) {
	defer func() {
		_ = recover() // never let a single session take down the listener
		_ = client.Close()
	}()

	ip, port := splitHostPort(client.RemoteAddr())

	// 1) Admission control.
	// Rejections are thinned (see limiter.logRejection) so a flood the limits
	// turn away does not become a log and database flood.
	reject := func(reason string) {
		if log, suppressed := b.lim.logRejection(ip); log {
			b.cfg.Sink.Emit(Event{
				EventType: EventRejected, Honeypot: b.cfg.Honeypot,
				SrcIP: ip, SrcPort: port, Reason: reason, Suppressed: suppressed,
			})
		}
	}
	ok, reason, release := b.lim.admit(ip)
	if !ok {
		reject(reason)
		return
	}
	defer release()

	// 2) Join the source's cell, or lease one (fixed pool; never
	// attacker-influenced).
	c, err := b.cells.join(sourceKey(ip))
	if err != nil {
		reject(ReasonPoolExhausted)
		return
	}
	backend, generation := c.backend, c.generation
	// Freeing a cell runs its reset, which can take minutes. The attacker's
	// connection is closed first: a failed dial otherwise left an accepted,
	// silent connection open for the whole reset. Its limiter slot stays
	// taken until the reset ends (the deferred release above runs after
	// this), so a source at its cap cannot park more backends in reset than
	// it may hold and drain the pool by breaking cells.
	defer func() {
		_ = client.Close()
		if reason := b.cells.leave(c); reason != "" {
			b.freeCell(c, reason)
		}
	}()
	sessionID, err := newSessionID()
	if err != nil {
		b.cells.fail(c, ReasonBackendDialError, true)
		b.cfg.Sink.Emit(Event{EventType: EventBackendError, Honeypot: b.cfg.Honeypot,
			SrcIP: ip, SrcPort: port, Backend: backend.ID, Generation: generation,
			Reason: ReasonBackendDialError})
		return
	}

	// 3) Dial the backend.
	dialCtx, cancelDial := context.WithTimeout(ctx, b.cfg.DialTimeout)
	upstream, err := b.dial(dialCtx, "tcp", backend.Addr)
	cancelDial()
	if err != nil {
		b.cells.fail(c, ReasonBackendDialError, false)
		b.cfg.Sink.Emit(Event{
			EventType: EventBackendError, Honeypot: b.cfg.Honeypot,
			SrcIP: ip, SrcPort: port, Backend: backend.ID, Generation: generation,
			SessionID: sessionID, Reason: ReasonBackendDialError,
		})
		return
	}
	defer upstream.Close()
	// Before the first byte: the backend's capture of this connection is
	// joined to it on the host by the port the broker dialed from.
	connected := Event{EventType: EventConnect, Honeypot: b.cfg.Honeypot,
		SrcIP: ip, SrcPort: port, Backend: backend.ID, Generation: generation, SessionID: sessionID}
	if local, ok := upstream.LocalAddr().(*net.TCPAddr); ok {
		connected.BackendPort = local.Port
	}
	b.cfg.Sink.Emit(connected)

	// 4) Splice. The session ends with its cell's life (MaxSession from the
	// cell's first connection); idleness within it is bounded by IdleTimeout.
	// Either bound, ctx cancellation, or a peer close tears the session down.
	start := time.Now()
	in, out, reason := b.splice(ctx, client, upstream, c.deadline(b.cfg.MaxSession))

	b.cfg.Sink.Emit(Event{
		EventType: EventSession, Honeypot: b.cfg.Honeypot,
		SrcIP: ip, SrcPort: port, Backend: backend.ID, Generation: generation,
		SessionID: sessionID,
		BytesIn:   in, BytesOut: out,
		DurationMs: time.Since(start).Milliseconds(),
		Reason:     reason,
	})
}

// splice copies bytes in both directions until one side closes, the session
// times out, or ctx is cancelled. It returns bytes client->backend (in),
// backend->client (out), and the teardown reason.
func (b *Broker) splice(ctx context.Context, client, upstream net.Conn, deadline time.Time) (in, out int64, reason string) {
	sessCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// When the session context fires (absolute timeout or broker shutdown),
	// CLOSE both conns to unblock the copy goroutines. Closing (rather than
	// forcing a past deadline) is deliberate: a Read on a closed conn returns
	// net.ErrClosed, which is NOT a timeout, so the peer goroutine does not
	// misreport a forced teardown as an idle timeout. Only a genuine idle
	// deadline surfaces as a timeout error — that is how we attribute the reason.
	go func() {
		<-sessCtx.Done()
		_ = client.Close()
		_ = upstream.Close()
	}()

	var (
		wg           sync.WaitGroup
		idleA, idleB atomic.Bool // a direction hit its OWN idle deadline
		// endAfterBackend ends the session a short while after the backend
		// closed (set by the backend->attacker goroutine, read after Wait).
		endAfterBackend *time.Timer
	)
	// hardClose tears the whole session down (both halves); used for idle/error
	// outcomes. A clean EOF instead propagates a half-close so the peer direction
	// can still drain (real proxies must support TCP half-close).
	hardClose := func() {
		_ = client.Close()
		_ = upstream.Close()
	}
	grace := backendCloseGrace
	if grace > b.cfg.IdleTimeout {
		grace = b.cfg.IdleTimeout
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		// attacker -> backend: read from client (src), write to upstream (dst).
		n, oc := b.copyDir(upstream, client)
		in = n
		switch oc {
		case outcomeEOF:
			halfCloseWrite(upstream) // FIN to backend; let backend->attacker drain
		case outcomeIdle:
			idleA.Store(true)
			hardClose()
		default: // outcomeError
			hardClose()
		}
	}()
	go func() {
		defer wg.Done()
		// backend -> attacker: read from upstream (src), write to client (dst).
		n, oc := b.copyDir(client, upstream)
		out = n
		switch oc {
		case outcomeEOF:
			// FIN to the attacker, who gets a short while to finish. The
			// backend is sshd, which closes its whole socket: an attacker
			// that ignores the FIN otherwise held the session, the backend
			// lease and its limiter slots until its own idle timeout.
			halfCloseWrite(client)
			endAfterBackend = time.AfterFunc(grace, hardClose)
		case outcomeIdle:
			idleB.Store(true)
			hardClose()
		default:
			hardClose()
		}
	}()
	wg.Wait()
	if endAfterBackend != nil {
		endAfterBackend.Stop()
	}

	switch {
	case sessCtx.Err() == context.DeadlineExceeded:
		return in, out, ReasonSessionTimeout
	case ctx.Err() != nil:
		return in, out, ReasonClosed
	case idleA.Load() || idleB.Load():
		return in, out, ReasonIdleTimeout
	default:
		return in, out, ReasonClosed
	}
}

// backendCloseGrace is how long the attacker may keep its half of a session
// open once the backend closed (the session's IdleTimeout when shorter).
var backendCloseGrace = 5 * time.Second

// outcome explains why a copy direction stopped, so splice can decide whether to
// half-close (clean EOF) or hard-close (idle/error) and how to label the session.
type outcome int

const (
	outcomeEOF   outcome = iota // src reached a clean EOF (peer closed its write half)
	outcomeIdle                 // src's own idle deadline elapsed (no data for IdleTimeout)
	outcomeError                // any other read/write error (incl. a forced close)
)

// copyDir copies from src to dst, refreshing src's read deadline before each
// read and dst's write deadline before each write, so a stream that makes no
// progress for IdleTimeout in either step (nothing to read, or a peer that
// stopped reading) is torn down. It returns the number of bytes copied and why
// it stopped.
func (b *Broker) copyDir(dst, src net.Conn) (int64, outcome) {
	buf := make([]byte, b.cfg.BufferSize)
	var total int64
	for {
		_ = src.SetReadDeadline(time.Now().Add(b.cfg.IdleTimeout))
		n, rerr := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(b.cfg.IdleTimeout))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				if ne, ok := werr.(net.Error); ok && ne.Timeout() {
					return total, outcomeIdle
				}
				return total, outcomeError
			}
			total += int64(n)
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, outcomeEOF
			}
			// A timeout error means THIS direction's own idle deadline elapsed
			// (genuine idleness). A forced teardown by the peer goroutine or the
			// session watcher arrives as net.ErrClosed (a Close) — not a timeout —
			// and is reported as outcomeError; the caller then attributes the
			// reason from the session/parent context.
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				return total, outcomeIdle
			}
			return total, outcomeError
		}
	}
}

// halfCloseWrite closes only the write half of c when supported (TCP), so the
// peer sees EOF while c can still be read. Falls back to a no-op for conns that
// do not support half-close (the peer direction's own teardown still applies).
func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// splitHostPort extracts an IP string and port from a net.Addr, tolerating odd
// or missing values (so logging can never panic on a weird RemoteAddr).
func splitHostPort(a net.Addr) (string, int) {
	if a == nil {
		return "", 0
	}
	if tcp, ok := a.(*net.TCPAddr); ok {
		// TCPAddr.IP excludes the IPv6 zone suffix and is kernel-derived. A
		// payload/header never participates in the authoritative source address.
		if tcp == nil || tcp.IP == nil || tcp.Port < 0 || tcp.Port > 65535 {
			return "", 0
		}
		return tcp.IP.String(), tcp.Port
	}
	host, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	port := 0
	if _, serr := fmt.Sscanf(portStr, "%d", &port); serr != nil || port < 0 || port > 65535 {
		port = 0 // tolerate any malformed/out-of-range port without panicking
	}
	return host, port
}
