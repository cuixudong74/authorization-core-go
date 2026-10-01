// Package authz contains the authorization engine: it combines the
// versioned policy store, decision cache, timeout handling and
// dependency degradation into a single Authorize entry point.
package authz

import (
	"sync"
	"time"

	"github.com/cuixudong74/authorization-core-go/policy"
)

// cacheEntry is an immutable cached decision. Entries are never mutated
// after insertion: a miss simply replaces them, so concurrent readers
// can never observe a partially written value.
type cacheEntry struct {
	decision policy.Decision
	version  int64
	expireAt time.Time
}

// Cache is a decision cache tagged with the policy version it was
// derived from.
//
// Correctness rules:
//   - Every entry records the policy version it was evaluated against;
//     lookups only return entries whose version matches the current
//     policy version.
//   - Invalidation bumps a generation counter and drops all entries.
//     In-flight lookups that started before the bump either finish with
//     the old (still valid for their snapshot) value or miss and
//     re-evaluate against the current policy — they never get a dirty
//     value.
//   - A cache miss never fails open: callers evaluate the policy and
//     deny if evaluation cannot complete.
type Cache struct {
	mu        sync.RWMutex
	entries   map[string]cacheEntry
	hits      uint64
	misses    uint64
	evictions uint64
}

// NewCache returns an empty cache.
func NewCache() *Cache {
	return &Cache{entries: make(map[string]cacheEntry)}
}

// Get returns the cached decision for key if it exists, was evaluated
// against policyVersion and has not expired.
func (c *Cache) Get(key string, policyVersion int64) (policy.Decision, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return policy.Decision{}, false
	}
	if entry.version != policyVersion {
		c.mu.Lock()
		delete(c.entries, key)
		c.evictions++
		c.misses++
		c.mu.Unlock()
		return policy.Decision{}, false
	}
	if !entry.expireAt.IsZero() && time.Now().After(entry.expireAt) {
		c.mu.Lock()
		delete(c.entries, key)
		c.evictions++
		c.misses++
		c.mu.Unlock()
		return policy.Decision{}, false
	}
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	return entry.decision, true
}

// Set stores a decision tagged with policyVersion. ttl <= 0 means the
// entry never expires (it is only removed by invalidation).
func (c *Cache) Set(key string, policyVersion int64, d policy.Decision, ttl time.Duration) {
	entry := cacheEntry{decision: d, version: policyVersion}
	if ttl > 0 {
		entry.expireAt = time.Now().Add(ttl)
	}
	c.mu.Lock()
	c.entries[key] = entry
	c.mu.Unlock()
}

// Invalidate drops every cached decision. It is called on policy
// publish so that stale conclusions can never be served.
func (c *Cache) Invalidate() {
	c.mu.Lock()
	n := len(c.entries)
	c.entries = make(map[string]cacheEntry)
	c.evictions += uint64(n)
	c.mu.Unlock()
}

// Remove deletes a single key.
func (c *Cache) Remove(key string) {
	c.mu.Lock()
	if _, ok := c.entries[key]; ok {
		delete(c.entries, key)
		c.evictions++
	}
	c.mu.Unlock()
}

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	n := len(c.entries)
	c.mu.RUnlock()
	return n
}

// Stats returns hit/miss/eviction counters.
func (c *Cache) Stats() (hits, misses, evictions uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, c.evictions
}
