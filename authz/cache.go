package authz

import "sync"

// cacheKey 以 (策略版本, 请求指纹) 为键：
// 版本是键的一部分，策略变更后旧版本的结论天然不可达，
// 不会被新请求读到。
type cacheKey struct {
	version uint64
	key     string
}

// cache 是并发安全的决策缓存。
// 所有读写都走同一把互斥锁的临界区，不存在半成品条目，
// 因此不会脏读；缓存未命中时由调用方重新评估，
// 清空/重建期间只会多算、绝不放行越权请求。
type cache struct {
	mu      sync.RWMutex
	entries map[cacheKey]Decision
	max     int
}

func newCache(maxEntries int) *cache {
	if maxEntries <= 0 {
		maxEntries = 1024
	}
	return &cache{entries: make(map[cacheKey]Decision), max: maxEntries}
}

// get 读取缓存。命中时返回的 Decision 会被调用方标记 FromCache。
func (c *cache) get(version uint64, key string) (Decision, bool) {
	c.mu.RLock()
	d, ok := c.entries[cacheKey{version: version, key: key}]
	c.mu.RUnlock()
	return d, ok
}

// put 写入缓存。写入前精准清理旧版本条目（失效），
// 容量超限时整体清空重建——重建期间未命中即重新评估，不放行。
func (c *cache) put(version uint64, key string, d Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		// 重建：只保留当前版本条目，旧版本结论全部失效。
		for k := range c.entries {
			if k.version != version {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.max {
			clear(c.entries)
		}
	}
	c.entries[cacheKey{version: version, key: key}] = d
}

// invalidateVersion 精准失效指定版本的全部缓存结论。
func (c *cache) invalidateVersion(version uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if k.version == version {
			delete(c.entries, k)
		}
	}
}
