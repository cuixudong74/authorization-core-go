// Package policy defines the authorization policy model, its evaluation
// semantics and a versioned, concurrency-safe policy store.
package policy

// Effect is the outcome a rule produces when it matches.
type Effect uint8

const (
	// EffectDeny always rejects a request when the rule matches.
	EffectDeny Effect = iota
	// EffectAllow permits a request when the rule matches and no deny
	// rule matches.
	EffectAllow
)

// String returns the stable textual representation of an effect.
func (e Effect) String() string {
	switch e {
	case EffectAllow:
		return "allow"
	case EffectDeny:
		return "deny"
	default:
		return "unknown"
	}
}

// A Rule grants or denies access. Resource and Action are patterns that
// support a single "*" wildcard matching any sequence of characters
// (e.g. "doc:*" matches "doc:123", "*" matches everything).
type Rule struct {
	ID         string
	Effect     Effect
	Roles      []string
	Resource   string
	Action     string
	Conditions []Condition
}

// A Condition constrains when a rule applies. All conditions of a rule
// must hold for the rule to match.
type Condition struct {
	Attribute string
	Operator  string
	Value     string
}

// A Role defines an inheritance relation: the role inherits every
// permission of the roles listed in Inherits (transitively).
type Role struct {
	Name     string
	Inherits []string
}

// A Policy is an immutable, fully published version of an authorization
// policy.
type Policy struct {
	Version int64
	Roles   []Role
	Rules   []Rule
	// RequiredAttributes lists attribute keys every request must provide.
	// A request missing any of them is rejected with
	// ReasonDependencyMissing without evaluating rules.
	RequiredAttributes []string
}

// A Request is the authorization question posed to the engine.
type Request struct {
	// Subject identifies the caller (used for auditing/cache keys).
	Subject string
	// SubjectRoles are the roles directly assigned to the subject.
	// Inherited roles are expanded during evaluation.
	SubjectRoles []string
	Resource     string
	Action       string
	// Attributes carries the key/value attributes used by conditions.
	Attributes map[string]string
}

// Reason explains why a decision was reached.
type Reason string

const (
	// ReasonAllow: at least one allow rule matched and no deny rule matched.
	ReasonAllow Reason = "allow"
	// ReasonDeny: at least one deny rule matched (deny overrides allow).
	ReasonDeny Reason = "explicit_deny"
	// ReasonNoMatch: no rule matched; default deny.
	ReasonNoMatch Reason = "no_matching_rule"
	// ReasonPolicyMissing: no policy (or no requested version) available.
	ReasonPolicyMissing Reason = "policy_missing"
	// ReasonDependencyMissing: a required attribute/dependency is absent.
	ReasonDependencyMissing Reason = "dependency_missing"
	// ReasonTimeout: evaluation exceeded the configured timeout.
	ReasonTimeout Reason = "timeout"
	// ReasonInvalidRequest: the request is malformed.
	ReasonInvalidRequest Reason = "invalid_request"
	// ReasonInvalidPolicy: the policy failed validation (e.g. role cycle).
	ReasonInvalidPolicy Reason = "invalid_policy"
)

// A Decision is the answer to an authorization request.
type Decision struct {
	Allowed bool
	Reason  Reason
	// RuleID identifies the rule that determined the outcome: the matched
	// deny rule for deny decisions, the matched allow rule for allow
	// decisions. Empty for default-deny decisions.
	RuleID string
	// Version is the policy version the decision was evaluated against.
	Version int64
}
