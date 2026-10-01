package policy

import (
	"strconv"
	"strings"
)

// Supported condition operators.
const (
	OpEq       = "eq"
	OpNe       = "ne"
	OpGt       = "gt"
	OpLt       = "lt"
	OpGe       = "ge"
	OpLe       = "le"
	OpIn       = "in"
	OpPrefix   = "prefix"
	OpSuffix   = "suffix"
	OpContains = "contains"
	OpExists   = "exists"
)

// knownOperator reports whether op is a supported condition operator.
func knownOperator(op string) bool {
	switch op {
	case OpEq, OpNe, OpGt, OpLt, OpGe, OpLe, OpIn, OpPrefix, OpSuffix, OpContains, OpExists:
		return true
	}
	return false
}

// matchCondition evaluates a single condition against the attribute set.
// A missing attribute makes the condition false (the rule does not match);
// it is never treated as an error at this layer — required-attribute
// checks are handled by the engine so they can produce a distinct reason.
func matchCondition(c Condition, attrs map[string]string) bool {
	val, ok := attrs[c.Attribute]
	if !ok {
		return false
	}
	switch c.Operator {
	case OpEq:
		return val == c.Value
	case OpNe:
		return val != c.Value
	case OpIn:
		for _, item := range strings.Split(c.Value, ",") {
			if val == item {
				return true
			}
		}
		return false
	case OpPrefix:
		return strings.HasPrefix(val, c.Value)
	case OpSuffix:
		return strings.HasSuffix(val, c.Value)
	case OpContains:
		return strings.Contains(val, c.Value)
	case OpExists:
		return true
	case OpGt, OpLt, OpGe, OpLe:
		return compareNumbers(val, c.Value, c.Operator)
	default:
		return false
	}
}

// compareNumbers compares two values as floating point numbers. If either
// value is not numeric the condition is false.
func compareNumbers(actual, expected, op string) bool {
	a, err1 := strconv.ParseFloat(strings.TrimSpace(actual), 64)
	b, err2 := strconv.ParseFloat(strings.TrimSpace(expected), 64)
	if err1 != nil || err2 != nil {
		return false
	}
	switch op {
	case OpGt:
		return a > b
	case OpLt:
		return a < b
	case OpGe:
		return a >= b
	case OpLe:
		return a <= b
	}
	return false
}

// matchWildcard reports whether value matches pattern. A "*" in pattern
// matches any sequence of characters (including the empty sequence);
// every other character must match literally.
func matchWildcard(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	// Prefix before the first '*' must match literally.
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	// Suffix after the last '*' must match literally.
	last := parts[len(parts)-1]
	if last != "" {
		if !strings.HasSuffix(value, last) {
			return false
		}
		value = value[:len(value)-len(last)]
	}
	// Middle segments must appear in order.
	for _, seg := range parts[1 : len(parts)-1] {
		if seg == "" {
			continue
		}
		idx := strings.Index(value, seg)
		if idx < 0 {
			return false
		}
		value = value[idx+len(seg):]
	}
	return true
}
