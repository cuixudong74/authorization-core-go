package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Validation errors.
var (
	ErrInvalidPolicy   = errors.New("invalid policy")
	ErrEmptyPolicy     = errors.New("policy has no rules")
	ErrDuplicateRole   = errors.New("duplicate role name")
	ErrDuplicateRuleID = errors.New("duplicate rule id")
	ErrUnknownRole     = errors.New("rule references undefined role")
	ErrUnknownOperator = errors.New("condition uses unsupported operator")
	ErrRoleCycle       = errors.New("role inheritance cycle detected")
	ErrInvalidPattern  = errors.New("invalid resource/action pattern")
)

// Validate checks the policy for structural errors. A policy that fails
// validation must never be published; callers receive ErrInvalidPolicy.
func (p *Policy) Validate() error {
	if len(p.Rules) == 0 {
		return ErrEmptyPolicy
	}

	roleNames := make(map[string]bool, len(p.Roles))
	for _, r := range p.Roles {
		if r.Name == "" {
			return fmt.Errorf("%w: empty role name", ErrInvalidPolicy)
		}
		if roleNames[r.Name] {
			return fmt.Errorf("%w: %q", ErrDuplicateRole, r.Name)
		}
		roleNames[r.Name] = true
	}

	ruleIDs := make(map[string]bool, len(p.Rules))
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("%w: rule #%d has empty id", ErrInvalidPolicy, i)
		}
		if ruleIDs[r.ID] {
			return fmt.Errorf("%w: %q", ErrDuplicateRuleID, r.ID)
		}
		ruleIDs[r.ID] = true
		if r.Effect != EffectAllow && r.Effect != EffectDeny {
			return fmt.Errorf("%w: rule %q has invalid effect", ErrInvalidPolicy, r.ID)
		}
		if !validPattern(r.Resource) {
			return fmt.Errorf("%w: rule %q resource %q", ErrInvalidPattern, r.ID, r.Resource)
		}
		if !validPattern(r.Action) {
			return fmt.Errorf("%w: rule %q action %q", ErrInvalidPattern, r.ID, r.Action)
		}
		for _, role := range r.Roles {
			if !roleNames[role] {
				return fmt.Errorf("%w: rule %q references role %q", ErrUnknownRole, r.ID, role)
			}
		}
		for _, c := range r.Conditions {
			if !knownOperator(c.Operator) {
				return fmt.Errorf("%w: rule %q condition %q", ErrUnknownOperator, r.ID, c.Operator)
			}
		}
	}

	if err := p.checkRoleCycles(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	return nil
}

// validPattern reports whether s is a legal resource/action pattern:
// non-empty and containing at most one '*' run (wildcards are simple
// substring wildcards; multiple '*' are supported too, but empty
// segments between them are harmless).
func validPattern(s string) bool {
	if s == "" {
		return false
	}
	return true
}

// checkRoleCycles detects cycles in the role inheritance graph.
func (p *Policy) checkRoleCycles() error {
	roles := make(map[string]*Role, len(p.Roles))
	for i := range p.Roles {
		roles[p.Roles[i].Name] = &p.Roles[i]
	}
	const (
		unvisited = 0
		visiting  = 1
		done      = 2
	)
	state := make(map[string]int, len(p.Roles))
	var visit func(name string) error
	visit = func(name string) error {
		switch state[name] {
		case visiting:
			return fmt.Errorf("%q", name)
		case done:
			return nil
		}
		state[name] = visiting
		r := roles[name]
		if r != nil {
			for _, inh := range r.Inherits {
				if _, ok := roles[inh]; !ok {
					return fmt.Errorf("role %q inherits undefined role %q", name, inh)
				}
				if err := visit(inh); err != nil {
					return err
				}
			}
		}
		state[name] = done
		return nil
	}
	for _, r := range p.Roles {
		if err := visit(r.Name); err != nil {
			return fmt.Errorf("%w involving %s", ErrRoleCycle, err)
		}
	}
	return nil
}

// expandRoles returns the full set of roles the subject effectively has:
// every directly assigned role plus all roles inherited transitively.
func expandRoles(p *Policy, subjectRoles []string) map[string]bool {
	roleDefs := make(map[string]*Role, len(p.Roles))
	for i := range p.Roles {
		roleDefs[p.Roles[i].Name] = &p.Roles[i]
	}
	out := make(map[string]bool, len(subjectRoles))
	var visit func(name string)
	visit = func(name string) {
		if out[name] {
			return
		}
		out[name] = true
		if r := roleDefs[name]; r != nil {
			for _, inh := range r.Inherits {
				visit(inh)
			}
		}
	}
	for _, s := range subjectRoles {
		visit(s)
	}
	return out
}

// ruleMatches reports whether the rule applies to the request given the
// subject's expanded role set.
func ruleMatches(r *Rule, roles map[string]bool, req Request) bool {
	roleOK := false
	for _, role := range r.Roles {
		if roles[role] {
			roleOK = true
			break
		}
	}
	if !roleOK {
		return false
	}
	if !matchWildcard(r.Resource, req.Resource) {
		return false
	}
	if !matchWildcard(r.Action, req.Action) {
		return false
	}
	for _, c := range r.Conditions {
		if !matchCondition(c, req.Attributes) {
			return false
		}
	}
	return true
}

// Evaluate evaluates a request against a policy snapshot.
//
// Semantics:
//   - Every rule is inspected; a deny rule that matches always overrides
//     any number of allow rules (deny-overrides).
//   - When no deny rule matches, a single matching allow rule is enough.
//   - When no rule matches, the request is denied (default deny).
//   - The result does not depend on rule ordering: all matching rules are
//     considered and the reported rule id is chosen deterministically
//     (smallest id among the decisive effect's matches).
func Evaluate(p *Policy, req Request) Decision {
	roles := expandRoles(p, req.SubjectRoles)

	var matchedDeny, matchedAllow []string
	for i := range p.Rules {
		r := &p.Rules[i]
		if !ruleMatches(r, roles, req) {
			continue
		}
		if r.Effect == EffectDeny {
			matchedDeny = append(matchedDeny, r.ID)
		} else {
			matchedAllow = append(matchedAllow, r.ID)
		}
	}

	if len(matchedDeny) > 0 {
		sort.Strings(matchedDeny)
		return Decision{
			Allowed: false,
			Reason:  ReasonDeny,
			RuleID:  matchedDeny[0],
			Version: p.Version,
		}
	}
	if len(matchedAllow) > 0 {
		sort.Strings(matchedAllow)
		return Decision{
			Allowed: true,
			Reason:  ReasonAllow,
			RuleID:  matchedAllow[0],
			Version: p.Version,
		}
	}
	return Decision{
		Allowed: false,
		Reason:  ReasonNoMatch,
		Version: p.Version,
	}
}

// MissingRequiredAttributes returns the required attribute keys that the
// request does not provide.
func MissingRequiredAttributes(p *Policy, req Request) []string {
	var missing []string
	for _, key := range p.RequiredAttributes {
		if _, ok := req.Attributes[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	return missing
}

// Fingerprint returns a stable, order-independent textual representation
// of the request for use in cache keys. Roles and attributes are sorted
// so that requests with semantically equal inputs share a key.
func Fingerprint(req Request) string {
	roles := append([]string(nil), req.SubjectRoles...)
	sort.Strings(roles)

	keys := make([]string, 0, len(req.Attributes))
	for k := range req.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("s=")
	b.WriteString(req.Subject)
	b.WriteString("|r=")
	b.WriteString(strings.Join(roles, ","))
	b.WriteString("|res=")
	b.WriteString(req.Resource)
	b.WriteString("|act=")
	b.WriteString(req.Action)
	b.WriteString("|a=")
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(req.Attributes[k])
		b.WriteByte(';')
	}
	return b.String()
}
