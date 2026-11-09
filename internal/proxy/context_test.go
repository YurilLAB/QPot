package proxy

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestBrokerRecordsTheConnectionBeforeItsFirstByte proves the host can join
// the backend's capture to the visitor: the connect event names the visitor,
// the lease and the port the broker dialed from, and it is on record before
// the backend receives a single byte.
func TestBrokerRecordsTheConnectionBeforeItsFirstByte(t *testing.T) {
	generations := t.TempDir()
	writeGen(t, generations, "be1", 5)
	gate := NewGenerationGate(generations)
	sink := &capSink{}
	accepted := make(chan *net.TCPAddr, 1)
	firstByteSeen := make(chan bool, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		accepted <- c.RemoteAddr().(*net.TCPAddr)
		buf := make([]byte, 1)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		// The connect event must already be there when data arrives.
		_, ok := sink.find(EventConnect)
		firstByteSeen <- ok
		_, _ = c.Write(buf)
	}()
	pool := NewPool([]Backend{{ID: "be1", Addr: ln.Addr().String()}}, nil)
	pool.SetLeaseHook(gate.OnLease)
	addr, stop := startBroker(t, Config{Gate: gate, Sink: sink, Dial: (&net.Dialer{}).DialContext}, pool)
	defer stop()
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if !<-firstByteSeen {
		t.Fatal("the backend received data before the connect event was recorded")
	}
	peer := <-accepted
	local := client.LocalAddr().(*net.TCPAddr)
	_ = client.Close()
	session := sink.wait(t, EventSession, time.Second)
	connect, _ := sink.find(EventConnect)
	if connect.SrcIP != local.IP.String() || connect.SrcPort != local.Port || connect.Backend != "be1" ||
		connect.BackendPort != peer.Port || connect.Generation == nil || *connect.Generation != 5 ||
		!validSessionID(connect.SessionID) || connect.SessionID != session.SessionID {
		t.Fatalf("connect=%+v session=%+v visitor=%s backend saw peer %s", connect, session, local, peer)
	}
}

// A failed dial records no connect event: nothing reached a backend.
func TestBrokerRecordsNoConnectionForAFailedDial(t *testing.T) {
	sink := &capSink{}
	pool := NewPool([]Backend{{ID: "be1", Addr: "127.0.0.1:22"}}, nil)
	addr, stop := startBroker(t, Config{Sink: sink, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, net.ErrClosed
	}}, pool)
	defer stop()
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sink.wait(t, EventBackendError, time.Second)
	if _, ok := sink.find(EventConnect); ok {
		t.Fatal("a connection that never reached its backend was recorded as connected")
	}
}

func TestTCPSourceParserKeepsActualIPWithoutIPv6Zone(t *testing.T) {
	ip, port := splitHostPort(&net.TCPAddr{IP: net.ParseIP("fe80::42"), Port: 42001, Zone: "eth0"})
	if ip != "fe80::42" || port != 42001 {
		t.Fatalf("kernel TCP source parsed as %s:%d", ip, port)
	}
	var missing *net.TCPAddr
	if ip, port := splitHostPort(missing); ip != "" || port != 0 {
		t.Fatalf("typed nil TCP address parsed as %s:%d", ip, port)
	}
}

func TestOpaqueStorageNamesAreStableAndInstanceScoped(t *testing.T) {
	namespace := strings.Repeat("a", 64)
	slot := ContextStorageName(namespace, "ssh-backend-1")
	if len(slot) != 32 || slot == "ssh-backend-1" || slot == ContextStorageName(namespace, "ssh-backend-2") || slot == ContextStorageName(strings.Repeat("b", 64), "ssh-backend-1") {
		t.Fatal("opaque storage name is not stable and instance scoped")
	}
	if slot != ContextStorageName(namespace, "ssh-backend-1") {
		t.Fatal("opaque storage name changed between calls")
	}
	if ContextStorageName("", "ssh-backend-1") != "ssh-backend-1" {
		t.Fatal("the legacy layout keeps service names")
	}
}
