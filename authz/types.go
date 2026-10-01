// Package authz 提供统一的授权决策核心：角色继承、属性条件、
// 拒绝优先、版本化策略发布、决策缓存与降级处理。
package authz

// Effect 表示规则效果。
type Effect int

const (
	EffectAllow Effect = iota
	EffectDeny
)

// Condition 是属性条件：对请求上下文中的某个属性做比较。
type Condition struct {
	Attr  string // 属性名，从 Request.Attributes 中取值
	Op    string // 比较操作符：eq / ne / in / glob
	Value any    // 期望值（in 时为 []any）
}

// Rule 是一条授权规则。
type Rule struct {
	ID        string
	Effect    Effect
	Roles     []string // 命中的主体角色（支持 "*" 通配）
	Actions   []string // 动作，支持 "prefix:*" 与 "*"
	Resources []string // 资源，支持 "prefix:*" 与 "*"
	Condition *Condition
}

// Policy 是一份完整策略，包含角色继承关系与规则集。
type Policy struct {
	Roles map[string][]string // 角色 -> 继承的父角色列表
	Rules []Rule
}

// Request 是一次授权询问。
type Request struct {
	Subject    string
	Roles      []string // 主体直接拥有的角色
	Action     string
	Resource   string
	Attributes map[string]any
}

// DenyReason 区分拒绝原因，便于排障与监控。
type DenyReason string

const (
	ReasonNoAllowRule   DenyReason = "no_allow_rule"  // 无任何允许规则命中
	ReasonExplicitDeny  DenyReason = "explicit_deny"  // 命中拒绝规则（拒绝优先）
	ReasonPolicyMissing DenyReason = "policy_missing" // 策略缺失，降级拒绝
	ReasonEvalTimeout   DenyReason = "eval_timeout"   // 评估超时，降级拒绝
	ReasonInvalidPolicy DenyReason = "invalid_policy" // 策略内容非法
)

// Decision 是评估结论。
type Decision struct {
	Allow     bool
	Reason    DenyReason // Allow 为 false 时有效
	RuleID    string     // 决定性规则（拒绝时优先记录拒绝规则）
	Version   uint64     // 评估所用策略版本
	FromCache bool
}
