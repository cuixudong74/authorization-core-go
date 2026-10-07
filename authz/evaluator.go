package authz

// evaluator 对单个不可变策略做纯函数式评估，无内部状态，可并发使用。
type evaluator struct{}

// evaluate 评估请求。语义：
//   - 规则命中 = 角色匹配（含继承展开与 "*"）且动作匹配且资源匹配且条件满足；
//   - 拒绝优先：任意一条拒绝规则命中即整体拒绝，与规则书写顺序无关；
//   - 无任何允许规则命中时默认拒绝；
//   - 决定性规则：同一效果多条规则命中时，取规则 ID 字典序最小者，
//     因此结论（含 RuleID）与规则书写顺序无关、可复现。
func (e *evaluator) evaluate(p *Policy, req Request, version uint64) Decision {
	effective := expandRoles(req.Roles, p.Roles)

	var allowHit, denyHit *Rule
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
		if !matchCondition(r.Condition, req.Attributes) {
			continue
		}
		if r.Effect == EffectDeny {
			if denyHit == nil || r.ID < denyHit.ID {
				denyHit = r
			}
		} else if allowHit == nil || r.ID < allowHit.ID {
			allowHit = r
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
