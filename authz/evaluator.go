package authz

import (
	"context"
	"sort"
)

// evaluator 对单个不可变策略做评估。provider 在引擎创建时注入，
// 评估过程本身无内部状态，可并发使用。
type evaluator struct {
	provider AttributeProvider // 外部属性依赖；nil 表示未配置
}

// evaluate 保持既有签名与语义：等价于不带超时约束的 evaluateCtx。
func (e *evaluator) evaluate(p *Policy, req Request, version uint64) Decision {
	return e.evaluateCtx(context.Background(), p, req, version)
}

// evaluateCtx 评估请求。语义：
//   - 规则命中 = 角色匹配（含继承展开与 "*"）且动作匹配且资源匹配且条件满足；
//   - 依赖优先：候选规则引用的外部属性获取失败时，直接降级拒绝
//     （ReasonDependencyUnavailable），优先于任何允许/拒绝规则的结论；
//   - 拒绝优先：任意一条拒绝规则命中即整体拒绝，与规则书写顺序无关；
//   - 无任何允许规则命中时默认拒绝；
//   - 决定性规则与书写顺序无关：多条同效果规则同时命中时，
//     取规则 ID 字典序最小者作为决定性规则。
func (e *evaluator) evaluateCtx(ctx context.Context, p *Policy, req Request, version uint64) Decision {
	effective := expandRoles(req.Roles, p.Roles)

	// 第一遍：筛出角色/动作/资源均匹配的候选规则，
	// 并收集其条件引用的外部属性（只获取评估真正用到的依赖）。
	var candidates []*Rule
	needed := make(map[string]struct{})
	for i := range p.Rules {
		r := &p.Rules[i]
		if !matchAnyRole(r.Roles, effective) {
			continue
		}
		if !matchAnyPattern(r.Actions, req.Action) {
			continue
		}
		if !matchAnyPattern(r.Resources, req.Resource) {
			continue
		}
		candidates = append(candidates, r)
		if r.Condition != nil && isExternalAttr(p, r.Condition.Attr) {
			needed[r.Condition.Attr] = struct{}{}
		}
	}

	attrs := req.Attributes
	if len(needed) > 0 {
		// 依赖缺失：评估无法完成，直接降级拒绝，绝不静默放行。
		fetched, ok := e.fetchDeps(ctx, req, needed)
		if !ok {
			return Decision{Allow: false, Reason: ReasonDependencyUnavailable, Version: version}
		}
		// 合并为本次评估私有的属性快照：请求属性 + 当次获取的外部属性。
		// 单次评估只取一次依赖快照，不会出现半新半旧的混合结果；
		// 快照为局部变量，不会在请求之间泄漏。
		merged := make(map[string]any, len(req.Attributes)+len(fetched))
		for k, v := range req.Attributes {
			merged[k] = v
		}
		for k, v := range fetched {
			merged[k] = v
		}
		attrs = merged
	}

	// 第二遍：在属性快照上评估条件，收集全部命中规则。
	var allowHit, denyHit *Rule
	for _, r := range candidates {
		if !matchCondition(r.Condition, attrs) {
			continue
		}
		if r.Effect == EffectDeny {
			denyHit = pickDecisive(denyHit, r)
		} else {
			allowHit = pickDecisive(allowHit, r)
		}
	}

	switch {
	case denyHit != nil:
		return Decision{Allow: false, Reason: ReasonExplicitDeny, RuleID: denyHit.ID, Version: version}
	case allowHit != nil:
		return Decision{Allow: true, RuleID: allowHit.ID, Version: version}
	default:
		return Decision{Allow: false, Reason: ReasonNoAllowRule, Version: version}
	}
}

// fetchDeps 一次性获取本次评估需要的全部外部属性。
// 任一属性获取失败或缺失都视为依赖不可用（ok=false）。
func (e *evaluator) fetchDeps(ctx context.Context, req Request, needed map[string]struct{}) (map[string]any, bool) {
	if e.provider == nil {
		return nil, false // 策略声明了外部属性但未配置 Provider
	}
	attrs := make([]string, 0, len(needed))
	for a := range needed {
		attrs = append(attrs, a)
	}
	sort.Strings(attrs) // 请求列表确定性排序，便于 Provider 侧观测与排障
	vals, err := e.provider.Fetch(ctx, req, attrs)
	if err != nil {
		return nil, false
	}
	for _, a := range attrs {
		if _, ok := vals[a]; !ok {
			return nil, false
		}
	}
	return vals, true
}

// pickDecisive 在同效果命中规则中选取决定性规则：
// 规则 ID 字典序最小者，与规则在配置中的书写顺序无关。
func pickDecisive(cur, r *Rule) *Rule {
	if cur == nil || r.ID < cur.ID {
		return r
	}
	return cur
}

// isExternalAttr 判断属性是否声明为由外部依赖提供。
func isExternalAttr(p *Policy, attr string) bool {
	for _, a := range p.ExternalAttrs {
		if a == attr {
			return true
		}
	}
	return false
}

// matchAnyRole 任一规则角色命中主体有效角色即匹配；"*" 匹配所有主体。
func matchAnyRole(ruleRoles []string, effective map[string]struct{}) bool {
	for _, r := range ruleRoles {
		if r == "*" {
			return true
		}
		if _, ok := effective[r]; ok {
			return true
		}
	}
	return false
}

// matchAnyPattern 支持精确匹配、"*" 全匹配与 "prefix:*" 前缀匹配。
func matchAnyPattern(patterns []string, value string) bool {
	for _, p := range patterns {
		if p == "*" || p == value {
			return true
		}
		if n := len(p); n > 1 && p[n-1] == '*' && len(value) >= n-1 && value[:n-1] == p[:n-1] {
			return true
		}
	}
	return false
}
