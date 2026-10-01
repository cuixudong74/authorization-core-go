package authz

import "fmt"

// matchCondition 判断属性条件是否满足。
// 条件为 nil 视为恒真；属性缺失或类型不匹配视为不满足（不静默放行）。
func matchCondition(c *Condition, attrs map[string]any) bool {
	if c == nil {
		return true
	}
	v, ok := attrs[c.Attr]
	if !ok {
		return false
	}
	switch c.Op {
	case "eq":
		return fmt.Sprint(v) == fmt.Sprint(c.Value)
	case "ne":
		return fmt.Sprint(v) != fmt.Sprint(c.Value)
	case "in":
		list, ok := c.Value.([]any)
		if !ok {
			return false
		}
		for _, item := range list {
			if fmt.Sprint(v) == fmt.Sprint(item) {
				return true
			}
		}
		return false
	case "glob":
		s, ok := v.(string)
		if !ok {
			return false
		}
		pat, ok := c.Value.(string)
		if !ok {
			return false
		}
		return globMatch(pat, s)
	default:
		return false // 未知操作符：不满足，默认拒绝
	}
}

// globMatch 支持 "*"（任意长度）与 "?"（单字符）的通配匹配。
func globMatch(pattern, s string) bool {
	p, t := 0, 0
	star, mark := -1, 0
	for t < len(s) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[t]) {
			p++
			t++
		} else if p < len(pattern) && pattern[p] == '*' {
			star, mark = p, t
			p++
		} else if star != -1 {
			p = star + 1
			mark++
			t = mark
		} else {
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
