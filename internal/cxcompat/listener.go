package cxcompat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const listenerReconcileInterval = 5 * time.Second

var (
	loopback4           = netip.MustParseAddr("127.0.0.1")
	loopback6           = netip.MustParseAddr("::1")
	tailscaleIPv6Prefix = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	protectedIPv4Prefix = netip.MustParsePrefix("100.64.0.0/10")
)

type addressProvider func() ([]netip.Addr, error)
type listenerFactory func(network, address string) (net.Listener, error)

type protectedListener struct {
	port      int
	addresses addressProvider
	listen    listenerFactory
	mu        sync.Mutex
	listeners map[netip.Addr]net.Listener
	accepted  chan acceptResult
	done      chan struct{}
	cancel    context.CancelFunc
	workers   sync.WaitGroup
	closeOnce sync.Once
}

type acceptResult struct {
	conn net.Conn
	err  error
}

// ListenProtected listens on loopback and addresses currently assigned to the local tailscale0 interface.
// Tailscale addresses are reconciled every five seconds; removing a listener does not close accepted connections.
func ListenProtected(port int) (net.Listener, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("protected listener port must be between 1 and 65535")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &protectedListener{
		port: port, addresses: localTailscaleAddresses, listen: listenOnAddress,
		listeners: make(map[netip.Addr]net.Listener), accepted: make(chan acceptResult, 64),
		done: make(chan struct{}), cancel: cancel,
	}
	if err := p.reconcile(); err != nil {
		_ = p.Close()
		return nil, err
	}
	p.workers.Add(1)
	go p.reconcileLoop(ctx)
	return p, nil
}

func newProtectedListener(port int, addresses addressProvider, listen listenerFactory) (*protectedListener, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("protected listener port must be between 1 and 65535")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &protectedListener{
		port: port, addresses: addresses, listen: listen,
		listeners: make(map[netip.Addr]net.Listener), accepted: make(chan acceptResult, 64),
		done: make(chan struct{}), cancel: cancel,
	}
	if err := p.reconcile(); err != nil {
		_ = p.Close()
		return nil, err
	}
	p.workers.Add(1)
	go p.reconcileLoop(ctx)
	return p, nil
}

func (p *protectedListener) reconcileLoop(ctx context.Context) {
	defer p.workers.Done()
	ticker := time.NewTicker(listenerReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.reconcile(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Warn("CX protected listener reconciliation failed; will retry")
			}
		}
	}
}

// reconcile is synchronous so tests and lifecycle callers can apply interface changes deterministically.
func (p *protectedListener) reconcile() error {
	addresses, err := p.addresses()
	if err != nil {
		p.mu.Lock()
		for address, listener := range p.listeners {
			if !address.IsLoopback() {
				delete(p.listeners, address)
				_ = listener.Close()
			}
		}
		p.mu.Unlock()
		return fmt.Errorf("read protected listener addresses: %w", err)
	}
	desired := allowedListenerAddresses(addresses)
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.done:
		return net.ErrClosed
	default:
	}
	for address, listener := range p.listeners {
		if _, keep := desired[address]; !keep {
			delete(p.listeners, address)
			_ = listener.Close()
		}
	}
	ordered := make([]netip.Addr, 0, len(desired))
	for address := range desired {
		ordered = append(ordered, address)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i] == ordered[j] {
			return false
		}
		if ordered[i] == loopback4 {
			return true
		}
		if ordered[j] == loopback4 {
			return false
		}
		if ordered[i] == loopback6 {
			return true
		}
		if ordered[j] == loopback6 {
			return false
		}
		return ordered[i].Less(ordered[j])
	})
	for _, address := range ordered {
		if _, exists := p.listeners[address]; exists {
			continue
		}
		listener, err := p.listen(networkForAddress(address), net.JoinHostPort(address.String(), strconv.Itoa(p.port)))
		if err != nil {
			return fmt.Errorf("listen on protected address %s: %w", address, err)
		}
		p.listeners[address] = listener
		p.workers.Add(1)
		go p.acceptLoop(address, listener)
	}
	return nil
}

func (p *protectedListener) acceptLoop(address netip.Addr, listener net.Listener) {
	defer p.workers.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-p.done:
				return
			default:
			}
			// Forget failed bindings so reconciliation can restore them. Do not
			// remove a newer binding installed after this listener was retired.
			p.mu.Lock()
			if p.listeners[address] == listener {
				delete(p.listeners, address)
			}
			p.mu.Unlock()
			_ = listener.Close()
			return
		}
		select {
		case p.accepted <- acceptResult{conn: conn}:
		case <-p.done:
			_ = conn.Close()
			return
		}
	}
}

func (p *protectedListener) Accept() (net.Conn, error) {
	select {
	case <-p.done:
		return nil, net.ErrClosed
	case result := <-p.accepted:
		return result.conn, result.err
	}
}

func (p *protectedListener) Close() error {
	p.close()
	p.workers.Wait()
	for {
		select {
		case result := <-p.accepted:
			if result.conn != nil {
				_ = result.conn.Close()
			}
		default:
			return nil
		}
	}
}

func (p *protectedListener) close() {
	p.closeOnce.Do(func() {
		close(p.done)
		p.cancel()
		p.mu.Lock()
		for address, listener := range p.listeners {
			delete(p.listeners, address)
			_ = listener.Close()
		}
		p.mu.Unlock()
	})
}

func (p *protectedListener) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if listener, ok := p.listeners[loopback4]; ok {
		return listener.Addr()
	}
	if listener, ok := p.listeners[loopback6]; ok {
		return listener.Addr()
	}
	for _, listener := range p.listeners {
		return listener.Addr()
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p.port}
}

func allowedListenerAddresses(addresses []netip.Addr) map[netip.Addr]struct{} {
	allowed := map[netip.Addr]struct{}{loopback4: {}}
	for _, address := range addresses {
		address = address.Unmap()
		if address == loopback6 || (address.IsValid() && (protectedIPv4Prefix.Contains(address) || (address.Is6() && tailscaleIPv6Prefix.Contains(address)))) {
			allowed[address] = struct{}{}
		}
	}
	return allowed
}

func networkForAddress(address netip.Addr) string {
	if address.Is6() {
		return "tcp6"
	}
	return "tcp4"
}

func listenOnAddress(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

func localTailscaleAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	for _, iface := range interfaces {
		if iface.Name != "tailscale0" && iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		ifaceAddresses, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("read interface addresses: %w", err)
		}
		for _, ifaceAddress := range ifaceAddresses {
			prefix, err := netip.ParsePrefix(ifaceAddress.String())
			if err != nil {
				continue
			}
			address := prefix.Addr().Unmap()
			if address == loopback6 {
				addresses = append(addresses, address)
				continue
			}
			if iface.Name == "tailscale0" && (protectedIPv4Prefix.Contains(address) || (address.Is6() && tailscaleIPv6Prefix.Contains(address))) {
				addresses = append(addresses, address)
			}
		}
	}
	return addresses, nil
}

// IsProtectedPeer checks a direct RemoteAddr value, not forwarded client-address headers.
func IsProtectedPeer(remote string) bool {
	remote = strings.TrimSpace(remote)
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	address, err := netip.ParseAddr(strings.Trim(remote, "[]"))
	if err != nil {
		return false
	}
	address = address.Unmap()
	return address.IsLoopback() || protectedIPv4Prefix.Contains(address) || tailscaleIPv6Prefix.Contains(address)
}
