package main

import (
	"sync"
	"time"
)

// RateLimiter decides whether to respond to a given source IP.

const (
	maxRequests   = 10               // max allowed requests inside the window
	windowSize    = 60 * time.Second // sliding window width
	blockDuration = 1 * time.Hour    // how long a blocked IP stays blocked
)

type ipState struct {
	timestamps   []time.Time // recent request times within the window
	blockedUntil time.Time   // zero means not blocked
}

// RateLimiter is goroutine-safe.
type RateLimiter struct {
	mu    sync.Mutex
	state map[string]*ipState
}

func newRateLimiter() *RateLimiter {
	rl := &RateLimiter{state: make(map[string]*ipState)}
	go rl.cleanup()
	return rl
}

// Check records the request and returns:
//
//	allowed is true if the honeypot should respond
//	justBlocked is true if this call was the one that triggered the block
func (rl *RateLimiter) Check(ip string) (allowed bool, justBlocked bool) {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	s, ok := rl.state[ip]
	if !ok {
		s = &ipState{}
		rl.state[ip] = s
	}

	// Already blocked -> drop silently
	if now.Before(s.blockedUntil) {
		return false, false
	}

	// Remove timestamps that have fallen outside the sliding window.
	cutoff := now.Add(-windowSize)
	fresh := s.timestamps[:0]
	for _, t := range s.timestamps {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	s.timestamps = append(fresh, now)

	// Enforce the rate limit.
	if len(s.timestamps) > maxRequests {
		s.blockedUntil = now.Add(blockDuration)
		s.timestamps = nil
		return false, true
	}

	return true, false
}

// cleanup removes entries that are neither blocked nor have recent timestamps
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		rl.mu.Lock()
		for ip, s := range rl.state {
			if now.After(s.blockedUntil) && len(s.timestamps) == 0 {
				delete(rl.state, ip)
			}
		}
		rl.mu.Unlock()
	}
}
