package policy

import (
	"math/rand"
	"testing"
)

// helper to build a policy concisely.
func testPolicy() *Policy {
	return &Policy{
		Roles: []Role{
			{Name: "guest"},
			{Name: "member", Inherits: []string{"guest"}},
			{Name: "admin", Inherits: []string{"member"}},
		},
		Rules: []Rule{
			{ID: "r-guest-public-read", Effect: EffectAllow, Roles: []string{"guest"}, Resource: "doc:public", Action: "read"},
			{ID: "r-member-read", Effect: EffectAllow, Roles: []string{"member"}, Resource: "doc:*", Action: "read"},
			{ID: "r-admin-all", Effect: EffectAllow, Roles: []string{"admin"}, Resource: "doc:*", Action: "*"},
			{ID: "r-deny-secret", Effect: EffectDeny, Roles: []string{"admin"}, Resource: "doc:secret", Action: "*"},
		},
	}
}

func TestRoleInheritance(t *testing.T) {
	p := testPolicy()
	cases := []struct {
		roles    []string
		resource string
		action   string
		want     bool
	}{
		// guest: only public read
		{[]string{"guest"}, "doc:public", "read", true},
		{[]string{"guest"}, "doc:public", "delete", false},
		{[]string{"guest"}, "doc:report", "read", false},
		// member inherits guest + own wildcard read
		{[]string{"member"}, "doc:public", "read", true},
		{[]string{"member"}, "doc:report", "read", true},
		{[]string{"member"}, "doc:report", "delete", false},
		// admin inherits member/guest + wildcard all, but secret is denied
		{[]string{"admin"}, "doc:report", "read", true},
		{[]string{"admin"}, "doc:report", "delete", true},
		{[]string{"admin"}, "doc:public", "read", true},
		{[]string{"admin"}, "doc:secret", "read", false},
		{[]string{"admin"}, "doc:secret", "delete", false},
		// unknown role: default deny
		{[]string{"nobody"}, "doc:public", "read", false},
	}
	for _, c := range cases {
		d := Evaluate(p, Request{
			SubjectRoles: c.roles,
			Resource:     c.resource,
			Action:       c.action,
		})
		if d.Allowed != c.want {
			t.Errorf("roles=%v %s/%s: got allowed=%v reason=%s rule=%q, want %v",
				c.roles, c.resource, c.action, d.Allowed, d.Reason, d.RuleID, c.want)
		}
	}
}

func TestDenyOverrides(t *testing.T) {
	p := &Policy{
		Roles: []Role{{Name: "admin"}},
		Rules: []Rule{
			{ID: "allow-all", Effect: EffectAllow, Roles: []string{"admin"}, Resource: "*", Action: "*"},
			{ID: "deny-secret", Effect: EffectDeny, Roles: []string{"admin"}, Resource: "doc:secret", Action: "*"},
		},
	}
	// allow rule matches, but deny overrides -> deny
	d := Evaluate(p, Request{SubjectRoles: []string{"admin"}, Resource: "doc:secret", Action: "read"})
	if d.Allowed || d.Reason != ReasonDeny || d.RuleID != "deny-secret" {
		t.Fatalf("expected explicit deny, got %+v", d)
	}
	// non-secret resource still allowed
	d = Evaluate(p, Request{SubjectRoles: []string{"admin"}, Resource: "doc:other", Action: "read"})
	if !d.Allowed || d.Reason != ReasonAllow || d.RuleID != "allow-all" {
		t.Fatalf("expected allow, got %+v", d)
	}
}

func TestAttributeConditions(t *testing.T) {
	p := &Policy{
		Roles: []Role{{Name: "user"}},
		Rules: []Rule{
			{
				ID:       "owner-read",
				Effect:   EffectAllow,
				Roles:    []string{"user"},
				Resource: "doc:*",
				Action:   "read",
				Conditions: []Condition{
					{Attribute: "user.id", Operator: OpEq, Value: "resource.owner"},
				},
			},
			{
				ID:       "level3-write",
				Effect:   EffectAllow,
				Roles:    []string{"user"},
				Resource: "doc:*",
				Action:   "write",
				Conditions: []Condition{
					{Attribute: "user.level", Operator: OpGe, Value: "3"},
				},
			},
		},
	}
	cases := []struct {
		attrs map[string]string
		act   string
		want  bool
	}{
		{map[string]string{"user.id": "resource.owner", "resource.owner": "resource.owner"}, "read", true},
		{map[string]string{"user.id": "someone-else", "resource.owner": "resource.owner"}, "read", false},
		{map[string]string{"user.level": "3"}, "write", true},
		{map[string]string{"user.level": "2"}, "write", false},
		{map[string]string{}, "read", false}, // missing attribute -> condition false
	}
	for _, c := range cases {
		d := Evaluate(p, Request{
			SubjectRoles: []string{"user"},
			Resource:     "doc:1",
			Action:       c.act,
			Attributes:   c.attrs,
		})
		if d.Allowed != c.want {
			t.Errorf("attrs=%v act=%s: got allowed=%v reason=%s, want %v",
				c.attrs, c.act, d.Allowed, d.Reason, c.want)
		}
	}
}

func TestWildcardMatching(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"*", "anything", true},
		{"doc:*", "doc:1", true},
		{"doc:*", "doc:1:2", true},
		{"doc:*", "image:1", false},
		{"doc:?", "doc:1", false}, // '?' is a literal character, not a wildcard
		{"doc:1", "doc:1", true},
		{"doc:1", "doc:2", false},
		{"read", "read", true},
		{"read", "write", false},
	}
	for _, c := range cases {
		if got := matchWildcard(c.pattern, c.value); got != c.want {
			t.Errorf("matchWildcard(%q,%q)=%v want %v", c.pattern, c.value, got, c.want)
		}
	}
}

func TestOrderIndependence(t *testing.T) {
	p := testPolicy()
	req := Request{SubjectRoles: []string{"admin"}, Resource: "doc:secret", Action: "read"}
	base := Evaluate(p, req)
	if base.Reason != ReasonDeny {
		t.Fatalf("sanity: expected deny, got %+v", base)
	}
	// Shuffle rules repeatedly; every result must be identical.
	for i := 0; i < 200; i++ {
		shuffled := *p
		shuffled.Rules = append([]Rule(nil), p.Rules...)
		rand.Shuffle(len(shuffled.Rules), func(a, b int) {
			shuffled.Rules[a], shuffled.Rules[b] = shuffled.Rules[b], shuffled.Rules[a]
		})
		d := Evaluate(&shuffled, req)
		if d.Allowed != base.Allowed || d.Reason != base.Reason || d.RuleID != base.RuleID {
			t.Fatalf("shuffle %d: got %+v, want %+v", i, d, base)
		}
	}
}

func TestDefaultDeny(t *testing.T) {
	p := testPolicy()
	d := Evaluate(p, Request{SubjectRoles: []string{"guest"}, Resource: "doc:secret", Action: "delete"})
	if d.Allowed || d.Reason != ReasonNoMatch || d.RuleID != "" {
		t.Fatalf("expected default deny, got %+v", d)
	}
}

func TestValidationRejectsBadPolicies(t *testing.T) {
	cases := []struct {
		name string
		p    *Policy
	}{
		{"empty rules", &Policy{Roles: []Role{{Name: "r"}}, Rules: nil}},
		{"duplicate role", &Policy{Roles: []Role{{Name: "r"}, {Name: "r"}}, Rules: []Rule{{ID: "1", Roles: []string{"r"}, Resource: "*", Action: "*"}}}},
		{"duplicate rule id", &Policy{Roles: []Role{{Name: "r"}}, Rules: []Rule{{ID: "1", Roles: []string{"r"}, Resource: "*", Action: "*"}, {ID: "1", Roles: []string{"r"}, Resource: "*", Action: "*"}}}},
		{"unknown role", &Policy{Roles: []Role{{Name: "r"}}, Rules: []Rule{{ID: "1", Roles: []string{"ghost"}, Resource: "*", Action: "*"}}}},
		{"bad operator", &Policy{Roles: []Role{{Name: "r"}}, Rules: []Rule{{ID: "1", Roles: []string{"r"}, Resource: "*", Action: "*", Conditions: []Condition{{Attribute: "a", Operator: "bogus"}}}}}},
		{"role cycle", &Policy{Roles: []Role{{Name: "a", Inherits: []string{"b"}}, {Name: "b", Inherits: []string{"a"}}}, Rules: []Rule{{ID: "1", Roles: []string{"a"}, Resource: "*", Action: "*"}}}},
		{"inherits undefined role", &Policy{Roles: []Role{{Name: "a", Inherits: []string{"zzz"}}}, Rules: []Rule{{ID: "1", Roles: []string{"a"}, Resource: "*", Action: "*"}}}},
	}
	for _, c := range cases {
		if err := c.p.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", c.name)
		}
	}
}

func TestValidationAcceptsValidPolicy(t *testing.T) {
	if err := testPolicy().Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
}

func TestMissingRequiredAttributes(t *testing.T) {
	p := &Policy{RequiredAttributes: []string{"user.id", "tenant"}}
	req := Request{Attributes: map[string]string{"user.id": "u1"}}
	missing := MissingRequiredAttributes(p, req)
	if len(missing) != 1 || missing[0] != "tenant" {
		t.Fatalf("expected [tenant], got %v", missing)
	}
}
