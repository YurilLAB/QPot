package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

// Serve must return when its listener is closed by someone other than ctx,
// not spin on net.ErrClosed forever.
func TestServeReturnsWhenListenerClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := NewBroker(Config{}, NewPool([]Backend{{ID: "a", Addr: "127.0.0.1:1"}}, nil))
	done := make(chan error, 1)
	go func() { done <- b.Serve(context.Background(), ln) }()
	time.Sleep(50 * time.Millisecond)
	ln.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after its listener was closed")
	}
}

func TestParseBackendsRejectsMalformedPorts(t *testing.T) {
	for _, s := range []string{"h:22x", "h:+22", "h:-1", "h:0", "h:65536", "h:0x16"} {
		if bs, err := ParseBackends(s); err == nil {
			t.Errorf("ParseBackends(%q) accepted invalid port: %+v", s, bs)
		}
	}
	if _, err := ParseBackends("be1=10.0.0.2:22, 10.0.0.3:2222"); err != nil {
		t.Errorf("valid backends rejected: %v", err)
	}
}
