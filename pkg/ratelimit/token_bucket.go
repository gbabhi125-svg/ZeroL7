// Package ratelimit implements a thread-safe, in-memory per-IP token-bucket
// rate limiter.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	mu       sync.Mutex
	tokens   float64
	lastFill time.Time
}

// Limiter is a per-key (typically client IP) token bucket limiter.
// Each key gets up to `burst` tokens, refilled at `rate` tokens/second.
type Limiter struct {
	rate  float64
	burst float64

	mu      sync.RWMutex
	buckets map[string]*bucket

	stop chan struct{}
}

func New(ratePerSecond float64, burst int) *Limiter {
	l := &Limiter{
		rate:    ratePerSecond,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		stop:    make(chan struct{}),
	}
	go l.janitor()
	return l
}

// Allow reports whether a request from key may proceed, consuming one token
// if so.
func (l *Limiter) Allow(key string) bool {
	return l.AllowN(key, 1)
}

func (l *Limiter) AllowN(key string, n float64) bool {
	b := l.getBucket(key)
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.lastFill = now
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	if b.tokens >= n {
		b.tokens -= n
		return true
	}
	return false
}

func (l *Limiter) getBucket(key string) *bucket {
	l.mu.RLock()
	b, ok := l.buckets[key]
	l.mu.RUnlock()
	if ok {
		return b
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok = l.buckets[key]; ok {
		return b
	}
	b = &bucket{tokens: l.burst, lastFill: time.Now()}
	l.buckets[key] = b
	return b
}

// janitor evicts idle buckets so long-running proxies don't leak memory on
// an unbounded set of client IPs.
func (l *Limiter) janitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-10 * time.Minute)
			l.mu.Lock()
			for key, b := range l.buckets {
				b.mu.Lock()
				idle := b.lastFill.Before(cutoff)
				b.mu.Unlock()
				if idle {
					delete(l.buckets, key)
				}
			}
			l.mu.Unlock()
		}
	}
}

func (l *Limiter) Close() {
	close(l.stop)
}
