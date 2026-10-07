package authz

import "sort"

// externalDeps 计算本次评估缺失的外部属性：
// 策略声明了 ExternalAttributes，且某条角色/动作/资源均匹配的规则
// 其条件引用了这些属性，而请求方未携带——此时不取到该属性就无法
// 确定这条规则是否命中，属于"评估必需"。
//
// 返回排序去重后的缺失属性列表，以及受影响规则中 ID 字典序最小者
// （用于依赖不可用时的可解释性，取舍确定、与规则书写顺序无关）。
// 该函数是纯函数，结果只取决于策略快照与请求。
func externalDeps(p *Policy, req Request) (missing []string, ruleID string) {
	if len(p.ExternalAttributes) == 0 {
		return nil, ""
	}
	declared := make(map[string]struct{}, len(p.ExternalAttributes))
	for _, a := range p.ExternalAttributes {
		declared[a] = struct{}{}
	}
	effective := expandRoles(req.Roles, p.Roles)
	needed := map[string]struct{}{}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Condition == nil {
			continue
		}
		attr := r.Condition.Attr
		if _, ok := declared[attr]; !ok {
			continue
		}
		if _, ok := req.Attributes[attr]; ok {
			continue // 请求方已提供，无需外部获取
		}
		if !matchAnyRole(r.Roles, effective) {
			continue
		}
		if !matchAnyPattern(r.Actions, req.Action) {
			continue
		}
		if !matchAnyPattern(r.Resources, req.Resource) {
			continue
		}
		needed[attr] = struct{}{}
		if ruleID == "" || r.ID < ruleID {
			ruleID = r.ID
		}
	}
	missing = make([]string, 0, len(needed))
	for a := range needed {
		missing = append(missing, a)
	}
	sort.Strings(missing)
	return missing, ruleID
}

// mergeAttributes 返回请求属性与已获取外部属性合并后的新 map。
// 只合并 needed 中列出的键：外部来源无法覆盖请求方已提供的属性，
// 也无法注入评估未要求的属性。原始请求的 Attributes 不被修改。
func mergeAttributes(reqAttrs map[string]any, fetched map[string]any, needed []string) map[string]any {
	merged := make(map[string]any, len(reqAttrs)+len(needed))
	for k, v := range reqAttrs {
		merged[k] = v
	}
	for _, k := range needed {
		merged[k] = fetched[k]
	}
	return merged
}
