package ratelimit

import (
	"testing"
	"time"
)

func TestAllowsBurstThenBlocks(t *testing.T) {
	l := New(1, 3) // 1 token/sec, burst of 3
	defer l.Close()

	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("expected request %d within burst to be allowed", i)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("expected 4th immediate request to be rate limited")
	}
}

func TestRefillsOverTime(t *testing.T) {
	l := New(100, 1) // fast refill for a short test
	defer l.Close()

	if !l.Allow("5.6.7.8") {
		t.Fatal("expected first request to be allowed")
	}
	if l.Allow("5.6.7.8") {
		t.Fatal("expected immediate second request to be blocked")
	}
	time.Sleep(20 * time.Millisecond)
	if !l.Allow("5.6.7.8") {
		t.Fatal("expected request to be allowed after refill window")
	}
}

func TestPerKeyIsolation(t *testing.T) {
	l := New(1, 1)
	defer l.Close()

	if !l.Allow("10.0.0.1") {
		t.Fatal("expected first key's first request to be allowed")
	}
	if !l.Allow("10.0.0.2") {
		t.Fatal("expected second key to have its own independent bucket")
	}
}
