package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// Recycle errors.
var (
	errNotRecycled = errors.New("proxy: backend was not recycled in time")
	errNotBack     = errors.New("proxy: recycled backend did not come back in time")
	// The backend went away and came back, but the host recycler did not
	// record recreating it: a restart staged from inside, not a reset.
	errNotRecreated = errors.New("proxy: backend restarted but the host did not recreate it")
)

// RecycleOptions tunes RecycleReset.
type RecycleOptions struct {
	Dial       DialFunc      // nil = net.Dialer
	DownWithin time.Duration // how long to wait for the backend to go away
	UpWithin   time.Duration // how long to wait for it to come back
	Poll       time.Duration // probe interval
	// Gate, when set, additionally requires the host recycler's generation
	// counter for the backend to advance (see GenerationGate).
	Gate *GenerationGate
}

// RecycleReset returns a ResetFunc for backends that are reset from OUTSIDE the
// broker: the trusted host-side supervisor recreates the backend container after
// every session (discarding everything the attacker changed), and this hook only
// waits until that has visibly happened - the backend became unreachable, then
// came back and is speaking SSH again - before the pool may reuse it.
//
// The broker therefore needs no privilege at all, and it fails closed: if the
// recreation is not observed (no supervisor running, docker failing), the reset
// returns an error and the pool quarantines the backend instead of handing a
// dirty box to the next attacker.
func RecycleReset(o RecycleOptions) ResetFunc {
	if o.Dial == nil {
		d := &net.Dialer{}
		o.Dial = d.DialContext
	}
	if o.Poll <= 0 {
		o.Poll = 100 * time.Millisecond
	}
	reachable := func(addr string) bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		c, err := o.Dial(ctx, "tcp", addr)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
	speaksSSH := func(addr string) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, err := o.Dial(ctx, "tcp", addr)
		if err != nil {
			return false
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		// The backend may be one an attacker had root on, so read at most
		// the 255 bytes RFC 4253 allows the identification line.
		line, err := bufio.NewReader(io.LimitReader(c, 255)).ReadString('\n')
		return err == nil && strings.HasPrefix(line, "SSH-")
	}
	// With a gate, a counter that already moved proves the recreation even if
	// it finished before we looked (late, or between two quarantine retries);
	// waiting to see the backend go down again would wait for a recreation
	// nobody will do.
	recreated := func(b Backend) bool { return o.Gate != nil && o.Gate.Advanced(b) }
	return func(b Backend) error {
		deadline := time.Now().Add(o.DownWithin)
		for !recreated(b) && reachable(b.Addr) {
			if time.Now().After(deadline) {
				return errNotRecycled
			}
			time.Sleep(o.Poll)
		}
		deadline = time.Now().Add(o.UpWithin)
		for !speaksSSH(b.Addr) {
			if time.Now().After(deadline) {
				return errNotBack
			}
			time.Sleep(o.Poll)
		}
		if o.Gate != nil {
			for !o.Gate.Advanced(b) {
				if time.Now().After(deadline) {
					return errNotRecreated
				}
				time.Sleep(o.Poll)
			}
		}
		return nil
	}
}
