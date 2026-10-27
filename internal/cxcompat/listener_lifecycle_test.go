package cxcompat

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestProtectedCloseClosesQueuedUndeliveredConnections(t *testing.T) {
	listener, err := newProtectedListener(8127, func() ([]netip.Addr, error) { return nil, nil }, func(_, address string) (net.Listener, error) { return newFakeListener(address), nil })
	if err != nil {
		t.Fatal(err)
	}
	connection, peer := net.Pipe()
	defer peer.Close()
	listener.accepted <- acceptResult{conn: connection}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("queued connection not closed: %v", err)
	}
}

func TestProtectedDiscoveryFailureDropsTailnetBindings(t *testing.T) {
	loopback := newFakeListener("127.0.0.1:8129")
	tailnet := newFakeListener("100.90.1.2:8129")
	listener := &protectedListener{
		listeners: map[netip.Addr]net.Listener{netip.MustParseAddr("127.0.0.1"): loopback, netip.MustParseAddr("100.90.1.2"): tailnet},
		addresses: func() ([]netip.Addr, error) { return nil, errors.New("fixture discovery error") },
		done:      make(chan struct{}),
	}
	defer loopback.Close()
	if err := listener.reconcile(); err == nil {
		t.Fatal("discovery error not reported")
	}
	if len(listener.listeners) != 1 || listener.listeners[netip.MustParseAddr("127.0.0.1")] != loopback {
		t.Fatal("discovery error retained unverified network binding")
	}
	select {
	case <-tailnet.done:
	default:
		t.Fatal("tailnet binding remained open")
	}
	select {
	case <-loopback.done:
		t.Fatal("known loopback binding closed")
	default:
	}
}

func TestFailedProtectedBindingIsForgottenForReconciliation(t *testing.T) {
	address := netip.MustParseAddr("127.0.0.1")
	physical := newFakeListener("127.0.0.1:8128")
	if err := physical.Close(); err != nil {
		t.Fatal(err)
	}
	listener := &protectedListener{listeners: map[netip.Addr]net.Listener{address: physical}, done: make(chan struct{}), accepted: make(chan acceptResult, 1)}
	listener.workers.Add(1)
	listener.acceptLoop(address, physical)
	if len(listener.listeners) != 0 {
		t.Fatal("failed physical binding prevents later retry")
	}
}
