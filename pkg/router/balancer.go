// Package router implements path-based routing to upstream pools with a
// round-robin / least-connections balancer and active health checking.
package router

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gbabhi125-svg/ZeroL7/pkg/configwatch"
)

type Backend struct {
	Address string
	Weight  int

	healthy     atomic.Bool
	activeConns atomic.Int64
}

func (b *Backend) Healthy() bool { return b.healthy.Load() }

// Pool is one route's set of backends plus the balancing strategy to pick
// among the currently-healthy ones.
type Pool struct {
	PathPrefix string
	Strategy   string // "round_robin" | "least_conn"

	mu       sync.Mutex
	backends []*Backend
	rrCursor uint64
}

func NewPool(pathPrefix, strategy string, addrs []configwatch.Upstream) *Pool {
	p := &Pool{PathPrefix: pathPrefix, Strategy: strategy}
	for _, a := range addrs {
		b := &Backend{Address: a.Address, Weight: a.Weight}
		b.healthy.Store(true)
		p.backends = append(p.backends, b)
	}
	return p
}

// Pick selects a healthy backend. Returns nil if none are healthy.
func (p *Pool) Pick() *Backend {
	p.mu.Lock()
	defer p.mu.Unlock()

	var healthy []*Backend
	for _, b := range p.backends {
		if b.Healthy() {
			healthy = append(healthy, b)
		}
	}
	if len(healthy) == 0 {
		return nil
	}

	switch p.Strategy {
	case "least_conn":
		best := healthy[0]
		for _, b := range healthy[1:] {
			if b.activeConns.Load() < best.activeConns.Load() {
				best = b
			}
		}
		return best
	default: // round_robin
		idx := atomic.AddUint64(&p.rrCursor, 1)
		return healthy[idx%uint64(len(healthy))]
	}
}

func (b *Backend) Acquire() { b.activeConns.Add(1) }
func (b *Backend) Release() { b.activeConns.Add(-1) }

// Router maps request paths to pools by longest-prefix match.
type Router struct {
	mu    sync.RWMutex
	pools []*Pool
}

func NewRouter(pools []*Pool) *Router {
	return &Router{pools: pools}
}

func (r *Router) Replace(pools []*Pool) {
	r.mu.Lock()
	r.pools = pools
	r.mu.Unlock()
}

func (r *Router) Match(path string) *Pool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var best *Pool
	bestLen := -1
	for _, p := range r.pools {
		if strings.HasPrefix(path, p.PathPrefix) && len(p.PathPrefix) > bestLen {
			best = p
			bestLen = len(p.PathPrefix)
		}
	}
	return best
}

func (r *Router) Pools() []*Pool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Pool, len(r.pools))
	copy(out, r.pools)
	return out
}

// HealthChecker pings every backend across all pools on an interval and
// flips Backend.healthy without touching active connections, so an
// unhealthy backend simply stops receiving new requests while existing
// streams drain naturally.
type HealthChecker struct {
	router   *Router
	path     string
	interval time.Duration
	timeout  time.Duration
	stop     chan struct{}
}

func NewHealthChecker(router *Router, path string, interval, timeout time.Duration) *HealthChecker {
	return &HealthChecker{router: router, path: path, interval: interval, timeout: timeout, stop: make(chan struct{})}
}

func (h *HealthChecker) Start() {
	go func() {
		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()
		h.checkAll()
		for {
			select {
			case <-h.stop:
				return
			case <-ticker.C:
				h.checkAll()
			}
		}
	}()
}

func (h *HealthChecker) Stop() { close(h.stop) }

func (h *HealthChecker) checkAll() {
	for _, pool := range h.router.Pools() {
		for _, b := range pool.backends {
			go h.checkOne(b)
		}
	}
}

func (h *HealthChecker) checkOne(b *Backend) {
	client := http.Client{Timeout: h.timeout}
	url := "http://" + b.Address + h.path
	resp, err := client.Get(url)
	if err != nil {
		b.healthy.Store(false)
		return
	}
	defer resp.Body.Close()
	b.healthy.Store(resp.StatusCode >= 200 && resp.StatusCode < 500)
}

// DialUpstream opens a fresh connection to a backend. A real connection pool
// (keep-alive reuse per backend) lives in pkg/proxy/dialpool.go; this is the
// low-level dial used by it and by health checks.
func DialUpstream(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, timeout)
}
