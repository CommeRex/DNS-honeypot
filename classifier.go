package main

import (
	"sync"
	"time"
)

// Important: the classifier runs on EVERY incoming packet, even those that the rate limiter subsequently drops.

const (
	attackThreshold = 100            // consecutive requests to classify as attack
	gapTimeout      = 1 * time.Hour
)

type ipRecord struct {
	count       int       
	lastSeen    time.Time 
	inAttack    bool      
	attackStart time.Time 
}

type Classifier struct {
	mu      sync.Mutex
	records map[string]*ipRecord
}

func newClassifier() *Classifier {
	c := &Classifier{records: make(map[string]*ipRecord)}
	go c.sweeper()
	return c
}

// Observe is called for every incoming DNS packet.
// It updates the per ip counter and emits log events when an
// attack starts. It returns true if this packet caused an attack_start event.
func (c *Classifier) Observe(ip string, domain string, queryType string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	r, ok := c.records[ip]
	if !ok {
		r = &ipRecord{}
		c.records[ip] = r
	}

	// If the gap since the last request exceeds the timeout, treat this as a new session
	if !r.lastSeen.IsZero() && now.Sub(r.lastSeen) > gapTimeout {
		if r.inAttack {
			writeEvent(EventEntry{
				Timestamp:    now.UTC().Format(time.RFC3339Nano),
				EventType:    "attack_end",
				SourceIP:     ip,
				AttackCount:  r.count,
				AttackStart:  r.attackStart.UTC().Format(time.RFC3339Nano),
				AttackEnd:    r.lastSeen.UTC().Format(time.RFC3339Nano),
			})
		}
		r.count = 0
		r.inAttack = false
	}

	r.count++
	r.lastSeen = now

	// Check whether this IP has just crossed the attack threshold.
	if !r.inAttack && r.count >= attackThreshold {
		r.inAttack = true
		r.attackStart = now
		writeEvent(EventEntry{
			Timestamp:   now.UTC().Format(time.RFC3339Nano),
			EventType:   "attack_start",
			SourceIP:    ip,
			AttackCount: r.count,
			Domain:      domain,
			QueryType:   queryType,
		})
	}
}

// sweeper periodically closes stale attack records so they do not sit open forever
func (c *Classifier) sweeper() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for ip, r := range c.records {
			if r.inAttack && now.Sub(r.lastSeen) > gapTimeout {
				writeEvent(EventEntry{
					Timestamp:   now.UTC().Format(time.RFC3339Nano),
					EventType:   "attack_end",
					SourceIP:    ip,
					AttackCount: r.count,
					AttackStart: r.attackStart.UTC().Format(time.RFC3339Nano),
					AttackEnd:   r.lastSeen.UTC().Format(time.RFC3339Nano),
				})
				r.inAttack = false
				r.count = 0
			}
			if !r.inAttack && now.Sub(r.lastSeen) > gapTimeout {
				delete(c.records, ip)
			}
		}
		c.mu.Unlock()
	}
}
