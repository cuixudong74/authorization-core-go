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
	provider    AttributeProvider
}

// Option 配置项。
type Option func(*engineConfig)

// WithEvalTimeout 设置单次评估超时，超时降级为拒绝（ReasonEvalTimeout）。
// 该预算同时约束外部属性获取：依赖慢或卡住时按降级拒绝处理，
// 不会让请求无限等待。
func WithEvalTimeout(d time.Duration) Option {
	return func(c *engineConfig) { c.evalTimeout = d }
}

// WithCacheSize 设置决策缓存容量上限。
func WithCacheSize(n int) Option {
	return func(c *engineConfig) { c.cacheSize = n }
}

// WithAttributeProvider 设置外部属性提供者。仅当策略声明了
// ExternalAttributes 且请求方未携带对应属性时才会被调用。
// 不设置该选项、或策略不声明外部属性时，行为与之前完全一致。
func WithAttributeProvider(p AttributeProvider) Option {
	return func(c *engineConfig) { c.provider = p }
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
//
// 外部依赖语义（策略声明 ExternalAttributes 且请求方未携带时）：
//   - 评估必需的外部属性在单次评估内只获取一次，整个评估使用同一份
//     获取结果，不会出现半新半旧的混合；
//   - 获取失败或属性仍缺失：直接拒绝（ReasonDependencyUnavailable），
//     该结论优先于任何允许规则，且不会被缓存——依赖恢复后同一请求
//     重新评估即可得到正常结论；
//   - 获取受整体评估超时约束，依赖卡住不会让请求无限等待；
//   - 获取成功时，缓存键包含本次取到的外部属性值，依赖取值变化
//     不会复用旧结论。
func (e *Engine) Authorize(ctx context.Context, req Request) Decision {
	policy, version, ok := e.store.current()
	if !ok {
		return Decision{Allow: false, Reason: ReasonPolicyMissing}
	}

	needed, depRuleID := externalDeps(policy, req)
	if len(needed) == 0 {
		return e.authorizeLocal(ctx, policy, req, version)
	}
	if e.config.provider == nil {
		// 策略需要外部属性但未配置提供者：依赖必然不可用，降级拒绝。
		return Decision{Allow: false, Reason: ReasonDependencyUnavailable, RuleID: depRuleID, Version: version}
	}
	return e.authorizeWithDeps(ctx, policy, req, version, needed, depRuleID)
}

// authorizeLocal 是无外部依赖路径：行为与引入外部依赖之前完全一致。
func (e *Engine) authorizeLocal(ctx context.Context, policy *Policy, req Request, version uint64) Decision {
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

// authorizeWithDeps 需要先取外部属性的路径。获取与评估都在同一个
// 受超时约束的 goroutine 内完成；依赖失败产生的降级拒绝不写入缓存。
func (e *Engine) authorizeWithDeps(ctx context.Context, policy *Policy, req Request, version uint64, needed []string, depRuleID string) Decision {
	depDenied := Decision{
		Allow:   false,
		Reason:  ReasonDependencyUnavailable,
		RuleID:  depRuleID,
		Version: version,
	}

	type result struct {
		d         Decision
		key       string // 缓存键（含取到的外部属性值）
		cacheable bool   // 依赖失败的降级结论不缓存
	}
	ch := make(chan result, 1)
	go func() {
		fetched, err := e.config.provider.FetchAttributes(ctx, req, needed)
		if err != nil {
			ch <- result{d: depDenied}
			return
		}
		for _, a := range needed {
			if _, ok := fetched[a]; !ok {
				ch <- result{d: depDenied} // 依赖返回不完整，视同不可用
				return
			}
		}
		merged := req
		merged.Attributes = mergeAttributes(req.Attributes, fetched, needed)
		key := fingerprint(merged)
		if d, hit := e.cache.get(version, key); hit {
			d.FromCache = true
			ch <- result{d: d}
			return
		}
		ch <- result{d: e.eval.evaluate(policy, merged, version), key: key, cacheable: true}
	}()

	t := time.NewTimer(e.config.evalTimeout)
	defer t.Stop()
	select {
	case r := <-ch:
		if r.cacheable {
			e.cache.put(version, r.key, r.d)
		}
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
