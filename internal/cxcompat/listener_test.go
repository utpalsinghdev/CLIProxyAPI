package cxcompat

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

type fakeListener struct {
	addr    net.Addr
	accepts chan net.Conn
	done    chan struct{}
	once    sync.Once
}

func newFakeListener(address string) *fakeListener {
	host, port, _ := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	portNumber, _ := strconv.Atoi(port)
	return &fakeListener{addr: &net.TCPAddr{IP: ip, Port: portNumber}, accepts: make(chan net.Conn), done: make(chan struct{})}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accepts:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *fakeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *fakeListener) Addr() net.Addr { return l.addr }

func TestAllowedListenerAddresses(t *testing.T) {
	input := []netip.Addr{
		loopback6,
		netip.MustParseAddr("100.90.1.2"),
		netip.MustParseAddr("fd7a:115c:a1e0::2"),
		netip.MustParseAddr("192.168.1.8"),
		netip.MustParseAddr("10.0.0.4"),
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("::"),
		netip.MustParseAddr("2001:db8::1"),
	}
	got := allowedListenerAddresses(input)
	want := map[netip.Addr]struct{}{
		loopback4: {}, loopback6: {},
		netip.MustParseAddr("100.90.1.2"):        {},
		netip.MustParseAddr("fd7a:115c:a1e0::2"): {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowedListenerAddresses() = %v; want %v", got, want)
	}
}

func TestListenProtectedRejectsInvalidPorts(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if listener, err := ListenProtected(port); err == nil || listener != nil {
			t.Fatalf("ListenProtected(%d) = (%v, %v); want nil listener and validation error", port, listener, err)
		}
	}
}

func TestReconcileBindsOnlyProtectedAddresses(t *testing.T) {
	addresses := []netip.Addr{
		loopback6,
		netip.MustParseAddr("100.90.1.2"),
		netip.MustParseAddr("192.168.1.8"),
		netip.MustParseAddr("0.0.0.0"),
	}
	var mu sync.Mutex
	var bound []string
	p, err := newProtectedListener(8123, func() ([]netip.Addr, error) { return addresses, nil }, func(network, address string) (net.Listener, error) {
		mu.Lock()
		bound = append(bound, network+" "+address)
		mu.Unlock()
		return newFakeListener(address), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	mu.Lock()
	got := append([]string(nil), bound...)
	mu.Unlock()
	for _, binding := range got {
		if binding == "tcp4 0.0.0.0:8123" || binding == "tcp6 [::]:8123" || binding == "tcp4 192.168.1.8:8123" {
			t.Fatalf("unsafe listener binding: %s", binding)
		}
	}
	if len(got) != 3 {
		t.Fatalf("bound %v; want loopback v4/v6 and one CGNAT address", got)
	}
	if addr := p.Addr().String(); addr != "127.0.0.1:8123" {
		t.Fatalf("Addr() = %q; want loopback address", addr)
	}
}

func TestInitialBindFailureClosesOwnedListeners(t *testing.T) {
	addresses := []netip.Addr{loopback6, netip.MustParseAddr("100.90.1.2")}
	var opened []*fakeListener
	p, err := newProtectedListener(8124, func() ([]netip.Addr, error) { return addresses, nil }, func(_, address string) (net.Listener, error) {
		if address == "100.90.1.2:8124" {
			return nil, errors.New("address unavailable")
		}
		listener := newFakeListener(address)
		opened = append(opened, listener)
		return listener, nil
	})
	if err == nil || p != nil {
		t.Fatalf("newProtectedListener() = (%v, %v); want startup error", p, err)
	}
	if len(opened) != 2 {
		t.Fatalf("opened %d listeners, want both loopback listeners before failed address", len(opened))
	}
	for _, listener := range opened {
		select {
		case <-listener.done:
		default:
			t.Fatal("owned listener left open after partial startup failure")
		}
	}
}

func TestCloseUnblocksAccept(t *testing.T) {
	p, err := newProtectedListener(8125, func() ([]netip.Addr, error) { return nil, nil }, func(_, address string) (net.Listener, error) {
		return newFakeListener(address), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	acceptDone := make(chan error, 1)
	go func() {
		_, err := p.Accept()
		acceptDone <- err
	}()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acceptDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept() error = %v; want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept() remained blocked after Close")
	}
}

func TestReconcileAddsAndRemovesWithoutClosingAcceptedConnections(t *testing.T) {
	address := netip.MustParseAddr("100.90.1.2")
	var addresses []netip.Addr
	var addressesMu sync.Mutex
	listeners := make(map[string]*fakeListener)
	p, err := newProtectedListener(8126, func() ([]netip.Addr, error) {
		addressesMu.Lock()
		defer addressesMu.Unlock()
		return append([]netip.Addr(nil), addresses...), nil
	}, func(_, address string) (net.Listener, error) {
		listener := newFakeListener(address)
		listeners[address] = listener
		return listener, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	addressesMu.Lock()
	addresses = []netip.Addr{address}
	addressesMu.Unlock()
	if err := p.reconcile(); err != nil {
		t.Fatal(err)
	}
	listener := listeners["100.90.1.2:8126"]
	if listener == nil {
		t.Fatal("reconcile did not add Tailscale listener")
	}
	client, peer := net.Pipe()
	defer peer.Close()
	listener.accepts <- client
	accepted, err := p.Accept()
	if err != nil {
		t.Fatal(err)
	}
	addressesMu.Lock()
	addresses = nil
	addressesMu.Unlock()
	if err := p.reconcile(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-listener.done:
	default:
		t.Fatal("removed physical listener remained open")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := accepted.Write([]byte("x"))
		writeDone <- err
	}()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := peer.Read(buffer); err != nil || string(buffer) != "x" {
		t.Fatalf("accepted connection failed after listener removal: read %q, error %v", buffer, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("accepted connection write failed: %v", err)
	}
	_ = accepted.Close()
}

func TestIsProtectedPeerUsesDirectAddress(t *testing.T) {
	cases := []struct {
		remote string
		want   bool
	}{
		{"127.0.0.1:1234", true},
		{"[::1]:1234", true},
		{"100.64.0.1:1234", true},
		{"100.127.255.254:1234", true},
		{"[fd7a:115c:a1e0::1]:1234", true},
		{"[fd12::1]:1234", false},
		{"192.168.1.2:1234", false},
		{"8.8.8.8:1234", false},
		{"not-an-address", false},
	}
	for _, test := range cases {
		if got := IsProtectedPeer(test.remote); got != test.want {
			t.Errorf("IsProtectedPeer(%q) = %t; want %t", test.remote, got, test.want)
		}
	}
}
