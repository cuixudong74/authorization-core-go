// Package authz 提供统一的授权决策核心：角色继承、属性条件、
// 拒绝优先、版本化策略发布、决策缓存与降级处理。
package authz

import "context"

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
	// ExternalAttributes 声明必须由引擎从外部依赖获取的属性名：
	// 当请求方未携带这些属性、而某条可能命中的规则的条件引用它们时，
	// 引擎会通过 AttributeProvider 获取；获取失败按降级拒绝处理。
	// 不声明该字段的策略行为与之前完全一致。
	ExternalAttributes []string
}

// AttributeProvider 从外部依赖（如用户中心、资源目录）获取请求方
// 无法提供的评估属性。实现必须并发安全：多个请求的获取可能并发进行；
// 实现应尊重 ctx 取消，避免无限阻塞（引擎另有整体评估超时兜底）。
type AttributeProvider interface {
	// FetchAttributes 获取 attrs 中列出的属性，返回属性名到值的映射。
	// 返回 error 或结果中缺少任一请求的属性，都视为依赖不可用。
	FetchAttributes(ctx context.Context, req Request, attrs []string) (map[string]any, error)
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
	// ReasonDependencyUnavailable 表示评估必需的外部属性获取失败或缺失，
	// 评估未能完成，按降级拒绝处理。该原因优先于任何允许结论：
	// 只要关键依赖没到位，即使存在命中的允许规则也一律拒绝。
	// 该结论不会被缓存，依赖恢复后同一请求重新评估即可得到正常结论。
	ReasonDependencyUnavailable DenyReason = "dependency_unavailable"
)

// Decision 是评估结论。
type Decision struct {
	Allow     bool
	Reason    DenyReason // Allow 为 false 时有效
	RuleID    string     // 决定性规则（拒绝时优先记录拒绝规则）
	Version   uint64     // 评估所用策略版本
	FromCache bool
}
