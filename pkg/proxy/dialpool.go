package proxy

import (
	"net"
	"sync"
	"time"
)

// DialPool keeps a small set of idle, already-handshaken TCP connections per
// backend address so forwarding a request doesn't pay a fresh TCP handshake
// (and, for TLS upstreams, a fresh handshake) on every proxied request.
type DialPool struct {
	mu      sync.Mutex
	idle    map[string][]net.Conn
	maxIdle int
	dialTO  time.Duration
}

func NewDialPool(maxIdlePerBackend int, dialTimeout time.Duration) *DialPool {
	return &DialPool{
		idle:    make(map[string][]net.Conn),
		maxIdle: maxIdlePerBackend,
		dialTO:  dialTimeout,
	}
}

// Get returns an idle connection to addr if one exists, otherwise dials a
// new one.
func (p *DialPool) Get(addr string) (net.Conn, error) {
	p.mu.Lock()
	conns := p.idle[addr]
	if len(conns) > 0 {
		conn := conns[len(conns)-1]
		p.idle[addr] = conns[:len(conns)-1]
		p.mu.Unlock()
		return conn, nil
	}
	p.mu.Unlock()
	return net.DialTimeout("tcp", addr, p.dialTO)
}

// Put returns a still-good connection to the idle pool for reuse, or closes
// it if the pool for that backend is already full.
func (p *DialPool) Put(addr string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.idle[addr]) >= p.maxIdle {
		conn.Close()
		return
	}
	p.idle[addr] = append(p.idle[addr], conn)
}

func (p *DialPool) Discard(conn net.Conn) {
	conn.Close()
}
