package authz

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Engine 是统一授权决策入口，组合策略存储、决策缓存与评估器。
// 并发安全：评估与发布可同时进行，互不影响。
type Engine struct {
	store  *store
	cache  *cache
	eval   *evaluator
	config engineConfig
}

type engineConfig struct {
	evalTimeout time.Duration
	cacheSize   int
}

// Option 配置项。
type Option func(*engineConfig)

// WithEvalTimeout 设置单次评估超时，超时降级为拒绝（ReasonEvalTimeout）。
func WithEvalTimeout(d time.Duration) Option {
	return func(c *engineConfig) { c.evalTimeout = d }
}

// WithCacheSize 设置决策缓存容量上限。
func WithCacheSize(n int) Option {
	return func(c *engineConfig) { c.cacheSize = n }
}

// NewEngine 创建引擎。
func NewEngine(opts ...Option) *Engine {
	cfg := engineConfig{evalTimeout: 100 * time.Millisecond, cacheSize: 1024}
	for _, o := range opts {
		o(&cfg)
	}
	return &Engine{
		store:  newStore(),
		cache:  newCache(cfg.cacheSize),
		eval:   &evaluator{},
		config: cfg,
	}
}

// Publish 校验并原子发布新策略版本，随后精准失效旧版本缓存。
// 发布失败（策略非法）时旧版本继续生效。
func (e *Engine) Publish(p *Policy) (uint64, error) {
	_, oldVersion, hadOld := e.store.current()
	version, err := e.store.publish(p)
	if err != nil {
		return 0, err
	}
	if hadOld {
		// 精准失效旧版本缓存；新版本键天然隔离，双保险。
		e.cache.invalidateVersion(oldVersion)
	}
	return version, nil
}

// Authorize 评估一次请求。
// 单次评估只读取一次策略快照，正在评估的请求不会得到新旧混合的结果；
// 超时、策略缺失一律降级拒绝并给出可区分的原因。
func (e *Engine) Authorize(ctx context.Context, req Request) Decision {
	policy, version, ok := e.store.current()
	if !ok {
		return Decision{Allow: false, Reason: ReasonPolicyMissing}
	}

	key := fingerprint(req)
	if d, hit := e.cache.get(version, key); hit {
		d.FromCache = true
		return d
	}

	type result struct{ d Decision }
	ch := make(chan result, 1)
	go func() {
		ch <- result{d: e.eval.evaluate(policy, req, version)}
	}()

	t := time.NewTimer(e.config.evalTimeout)
	defer t.Stop()
	select {
	case r := <-ch:
		e.cache.put(version, key, r.d)
		return r.d
	case <-ctx.Done():
		return Decision{Allow: false, Reason: ReasonEvalTimeout, Version: version}
	case <-t.C:
		return Decision{Allow: false, Reason: ReasonEvalTimeout, Version: version}
	}
}

// fingerprint 生成请求的确定性缓存键：角色与属性排序后拼接，
// 与 map 遍历顺序无关。
func fingerprint(req Request) string {
	var b strings.Builder
	b.WriteString(req.Subject)
	b.WriteByte('|')
	b.WriteString(req.Action)
	b.WriteByte('|')
	b.WriteString(req.Resource)
	b.WriteByte('|')
	roles := append([]string(nil), req.Roles...)
	sort.Strings(roles)
	for _, r := range roles {
		b.WriteString(r)
		b.WriteByte(',')
	}
	b.WriteByte('|')
	keys := make([]string, 0, len(req.Attributes))
	for k := range req.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		fmt.Fprintf(&b, "%v", req.Attributes[k])
		b.WriteByte(',')
	}
	return b.String()
}
