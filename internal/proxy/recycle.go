package proxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// Recycle errors.
var (
	errNotRecycled = errors.New("proxy: backend was not recycled in time")
	errNotBack     = errors.New("proxy: recycled backend did not come back in time")
)

// RecycleOptions tunes RecycleReset.
type RecycleOptions struct {
	Dial       DialFunc      // nil = net.Dialer
	DownWithin time.Duration // how long to wait for the backend to go away
	UpWithin   time.Duration // how long to wait for it to come back
	Poll       time.Duration // probe interval
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
		line, err := bufio.NewReader(c).ReadString('\n')
		return err == nil && strings.HasPrefix(line, "SSH-")
	}
	return func(b Backend) error {
		deadline := time.Now().Add(o.DownWithin)
		for reachable(b.Addr) {
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
		return nil
	}
}
