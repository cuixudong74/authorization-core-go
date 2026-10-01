package authz

import (
	"math/rand"
	"testing"
)

func TestRoleInheritanceMultiLevel(t *testing.T) {
	p := &Policy{
		Roles: map[string][]string{
			"viewer": {"reader"},
			"reader": {"base"},
			"editor": {"viewer"},
			"admin":  {"editor"},
		},
		Rules: []Rule{
			{ID: "r1", Effect: EffectAllow, Roles: []string{"base"}, Actions: []string{"read"}, Resources: []string{"doc:*"}},
		},
	}
	ev := &evaluator{}
	// admin -> editor -> viewer -> reader -> base，多级继承后应命中 base 的允许规则
	d := ev.evaluate(p, Request{Subject: "u1", Roles: []string{"admin"}, Action: "read", Resource: "doc:1"}, 1)
	if !d.Allow || d.RuleID != "r1" {
		t.Fatalf("expected allow via multi-level inheritance, got %+v", d)
	}
	// 未继承链上的角色不命中
	d = ev.evaluate(p, Request{Subject: "u2", Roles: []string{"guest"}, Action: "read", Resource: "doc:1"}, 1)
	if d.Allow || d.Reason != ReasonNoAllowRule {
		t.Fatalf("expected deny no_allow_rule, got %+v", d)
	}
}

func TestRoleInheritanceCycleSafe(t *testing.T) {
	// 循环继承不得死循环
	roles := expandRoles([]string{"a"}, map[string][]string{"a": {"b"}, "b": {"a"}})
	if len(roles) != 2 {
		t.Fatalf("expected {a,b}, got %v", roles)
	}
}

func TestAttributeConditions(t *testing.T) {
	p := &Policy{
		Rules: []Rule{
			{ID: "dept", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"*"},
				Condition: &Condition{Attr: "dept", Op: "eq", Value: "eng"}},
			{ID: "env", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"deploy"}, Resources: []string{"*"},
				Condition: &Condition{Attr: "env", Op: "in", Value: []any{"staging", "dev"}}},
			{ID: "ip", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"ssh"}, Resources: []string{"*"},
				Condition: &Condition{Attr: "ip", Op: "glob", Value: "10.0.*"}},
		},
	}
	ev := &evaluator{}
	cases := []struct {
		name  string
		req   Request
		allow bool
	}{
		{"eq hit", Request{Roles: []string{"x"}, Action: "read", Resource: "r", Attributes: map[string]any{"dept": "eng"}}, true},
		{"eq miss", Request{Roles: []string{"x"}, Action: "read", Resource: "r", Attributes: map[string]any{"dept": "ops"}}, false},
		{"attr missing", Request{Roles: []string{"x"}, Action: "read", Resource: "r"}, false},
		{"in hit", Request{Roles: []string{"x"}, Action: "deploy", Resource: "r", Attributes: map[string]any{"env": "staging"}}, true},
		{"in miss", Request{Roles: []string{"x"}, Action: "deploy", Resource: "r", Attributes: map[string]any{"env": "prod"}}, false},
		{"glob hit", Request{Roles: []string{"x"}, Action: "ssh", Resource: "r", Attributes: map[string]any{"ip": "10.0.1.5"}}, true},
		{"glob miss", Request{Roles: []string{"x"}, Action: "ssh", Resource: "r", Attributes: map[string]any{"ip": "192.168.1.1"}}, false},
	}
	for _, c := range cases {
		d := ev.evaluate(p, c.req, 1)
		if d.Allow != c.allow {
			t.Errorf("%s: expected allow=%v, got %+v", c.name, c.allow, d)
		}
	}
}

func TestDenyOverrides(t *testing.T) {
	p := &Policy{
		Rules: []Rule{
			{ID: "allow-all", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"*"}, Resources: []string{"*"}},
			{ID: "deny-prod", Effect: EffectDeny, Roles: []string{"*"}, Actions: []string{"delete"}, Resources: []string{"prod:*"}},
		},
	}
	ev := &evaluator{}
	d := ev.evaluate(p, Request{Roles: []string{"u"}, Action: "delete", Resource: "prod:db"}, 1)
	if d.Allow || d.Reason != ReasonExplicitDeny || d.RuleID != "deny-prod" {
		t.Fatalf("expected explicit deny, got %+v", d)
	}
	// 允许规则单独存在时正常放行
	d = ev.evaluate(p, Request{Roles: []string{"u"}, Action: "read", Resource: "prod:db"}, 1)
	if !d.Allow {
		t.Fatalf("expected allow, got %+v", d)
	}
}

func TestRuleOrderIndependence(t *testing.T) {
	base := []Rule{
		{ID: "a1", Effect: EffectAllow, Roles: []string{"dev"}, Actions: []string{"read"}, Resources: []string{"doc:*"}},
		{ID: "d1", Effect: EffectDeny, Roles: []string{"dev"}, Actions: []string{"read"}, Resources: []string{"doc:secret"}},
		{ID: "a2", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:public"}},
	}
	reqs := []Request{
		{Roles: []string{"dev"}, Action: "read", Resource: "doc:1"},
		{Roles: []string{"dev"}, Action: "read", Resource: "doc:secret"},
		{Roles: []string{"guest"}, Action: "read", Resource: "doc:public"},
		{Roles: []string{"guest"}, Action: "read", Resource: "doc:secret"},
	}
	want := make([]Decision, len(reqs))
	ev := &evaluator{}
	for i, r := range reqs {
		want[i] = ev.evaluate(&Policy{Rules: base}, r, 1)
	}
	// 随机打乱规则顺序 100 次，结论必须一致
	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 100; iter++ {
		shuffled := append([]Rule(nil), base...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		p := &Policy{Rules: shuffled}
		for i, r := range reqs {
			got := ev.evaluate(p, r, 1)
			if got.Allow != want[i].Allow || got.Reason != want[i].Reason {
				t.Fatalf("iter %d req %d: order changed conclusion: want %+v got %+v", iter, i, want[i], got)
			}
		}
	}
}

func TestWildcardAndPrefixPatterns(t *testing.T) {
	if !matchAnyPattern([]string{"doc:*"}, "doc:123") {
		t.Fatal("prefix pattern should match")
	}
	if matchAnyPattern([]string{"doc:*"}, "image:123") {
		t.Fatal("prefix pattern should not match other prefix")
	}
	if !matchAnyPattern([]string{"*"}, "anything") {
		t.Fatal("star should match everything")
	}
}
