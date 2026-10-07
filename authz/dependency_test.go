package authz

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// depPolicy 声明外部属性 clearance，允许规则依赖它。
func depPolicy() *Policy {
	return &Policy{
		ExternalAttrs: []string{"clearance"},
		Rules: []Rule{
			{ID: "allow-cleared", Effect: EffectAllow, Roles: []string{"*"},
				Actions: []string{"read"}, Resources: []string{"doc:*"},
				Condition: &Condition{Attr: "clearance", Op: "eq", Value: "top"}},
		},
	}
}

func okProvider() AttributeProvider {
	return AttributeProviderFunc(func(ctx context.Context, req Request, attrs []string) (map[string]any, error) {
		return map[string]any{"clearance": "top"}, nil
	})
}

func failProvider() AttributeProvider {
	return AttributeProviderFunc(func(ctx context.Context, req Request, attrs []string) (map[string]any, error) {
		return nil, errors.New("dependency down")
	})
}

// 依赖获取失败：必须拒绝，且原因可与普通无权限（no_allow_rule）区分。
func TestDependencyFailureDeniesWithDistinctReason(t *testing.T) {
	e := NewEngine(WithAttributeProvider(failProvider()))
	if _, err := e.Publish(depPolicy()); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), Request{Subject: "u", Action: "read", Resource: "doc:1"})
	if d.Allow {
		t.Fatalf("dependency failure must not allow, got %+v", d)
	}
	if d.Reason != ReasonDependencyUnavailable {
		t.Fatalf("expected dependency_unavailable, got %+v", d)
	}
	if d.Reason == ReasonNoAllowRule || d.Reason == ReasonExplicitDeny {
		t.Fatalf("reason must be distinguishable from normal denials, got %+v", d)
	}
}

// 策略声明了外部属性但引擎未配置 Provider：同样按依赖不可用降级拒绝。
func TestDependencyDeclaredButNoProvider(t *testing.T) {
	e := NewEngine()
	if _, err := e.Publish(depPolicy()); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), Request{Subject: "u", Action: "read", Resource: "doc:1"})
	if d.Allow || d.Reason != ReasonDependencyUnavailable {
		t.Fatalf("expected dependency_unavailable deny, got %+v", d)
	}
}

// Provider 返回中缺失所需属性：视为依赖不可用。
func TestDependencyPartialResult(t *testing.T) {
	e := NewEngine(WithAttributeProvider(AttributeProviderFunc(
		func(ctx context.Context, req Request, attrs []string) (map[string]any, error) {
			return map[string]any{}, nil // 一个属性都没返回
		})))
	if _, err := e.Publish(depPolicy()); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), Request{Subject: "u", Action: "read", Resource: "doc:1"})
	if d.Allow || d.Reason != ReasonDependencyUnavailable {
		t.Fatalf("expected dependency_unavailable deny, got %+v", d)
	}
}

// 依赖缺失优先于允许：同时存在无条件允许规则，也不得放行。
func TestDependencyMissingBeatsAllowRule(t *testing.T) {
	p := depPolicy()
	p.Rules = append(p.Rules, Rule{ID: "allow-all", Effect: EffectAllow,
		Roles: []string{"*"}, Actions: []string{"*"}, Resources: []string{"*"}})
	e := NewEngine(WithAttributeProvider(failProvider()))
	if _, err := e.Publish(p); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), Request{Subject: "u", Action: "read", Resource: "doc:1"})
	if d.Allow {
		t.Fatalf("unconditional allow rule must not rescue missing dependency, got %+v", d)
	}
	if d.Reason != ReasonDependencyUnavailable {
		t.Fatalf("expected dependency_unavailable, got %+v", d)
	}
}

// 依赖恢复后同一请求必须得到正常结论；失败结论不得被缓存。
func TestDependencyRecoveryRestoresDecision(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	e := NewEngine(WithAttributeProvider(AttributeProviderFunc(
		func(ctx context.Context, req Request, attrs []string) (map[string]any, error) {
			if down.Load() {
				return nil, errors.New("dependency down")
			}
			return map[string]any{"clearance": "top"}, nil
		})))
	if _, err := e.Publish(depPolicy()); err != nil {
		t.Fatal(err)
	}
	req := Request{Subject: "u", Action: "read", Resource: "doc:1"}

	d1 := e.Authorize(context.Background(), req)
	if d1.Allow || d1.Reason != ReasonDependencyUnavailable {
		t.Fatalf("while down: expected dependency_unavailable, got %+v", d1)
	}
	down.Store(false) // 依赖恢复
	d2 := e.Authorize(context.Background(), req)
	if !d2.Allow || d2.RuleID != "allow-cleared" {
		t.Fatalf("after recovery: expected normal allow, got %+v", d2)
	}
	if d2.FromCache {
		t.Fatalf("degraded failure must not be served from cache, got %+v", d2)
	}
	// 再次抖动为失败：缓存的正常结论属于旧依赖状态，但成功结论可缓存——
	// 关键是失败本身从未被缓存，重新评估永远反映当次依赖状态。
	down.Store(true)
	d3 := e.Authorize(context.Background(), req)
	if d3.Reason == ReasonDependencyUnavailable {
		// 允许：成功结论被缓存或重新评估失败，二者都必须自洽
		if d3.FromCache {
			t.Fatalf("cached entry must not be a degraded failure: %+v", d3)
		}
	}
}

// 并发 + 时好时坏：每次结论必须与当次依赖真实状态一致，
// 不出现半新半旧，也不把别的请求的结论泄漏进来。
func TestDependencyConcurrentFlakyConsistency(t *testing.T) {
	provider := AttributeProviderFunc(func(ctx context.Context, req Request, attrs []string) (map[string]any, error) {
		// 时好时坏：以请求属性 nonce 模拟当次依赖状态（不影响规则匹配）
		if req.Attributes["nonce"].(int)%3 == 0 {
			return nil, errors.New("flaky")
		}
		// 每个主体的当次真实值
		return map[string]any{"clearance": "clearance-" + req.Subject}, nil
	})

	p := &Policy{
		ExternalAttrs: []string{"clearance"},
		Rules: []Rule{
			{ID: "allow-vip", Effect: EffectAllow, Roles: []string{"*"},
				Actions: []string{"read"}, Resources: []string{"doc:*"},
				Condition: &Condition{Attr: "clearance", Op: "eq", Value: "clearance-vip"}},
		},
	}
	e := NewEngine(WithAttributeProvider(provider), WithCacheSize(4096))
	if _, err := e.Publish(p); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan string, 1024)
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(w)))
			for i := 0; i < 200; i++ {
				// 一半请求是 vip（依赖正常时应放行），一半不是
				subj := "vip"
				if rng.Intn(2) == 0 {
					subj = fmt.Sprintf("user%d", w)
				}
				nonce := rng.Intn(3) // nonce%3==0 时当次依赖失败
				req := Request{Subject: subj, Action: "read", Resource: "doc:1",
					Attributes: map[string]any{"nonce": nonce}}
				d := e.Authorize(context.Background(), req)
				wantDepDown := nonce%3 == 0
				wantAllow := subj == "vip" && !wantDepDown
				switch {
				case wantDepDown:
					if d.Allow || d.Reason != ReasonDependencyUnavailable {
						errs <- fmt.Sprintf("dep down but got %+v (subj=%s nonce=%d)", d, subj, nonce)
					}
				case wantAllow:
					if !d.Allow || d.RuleID != "allow-vip" {
						errs <- fmt.Sprintf("expected allow for vip, got %+v", d)
					}
				default:
					if d.Allow {
						errs <- fmt.Sprintf("non-vip must not be allowed (leak?), got %+v (subj=%s)", d, subj)
					}
					if d.Reason != ReasonNoAllowRule {
						errs <- fmt.Sprintf("expected no_allow_rule for non-vip, got %+v", d)
					}
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

// 依赖慢/卡住：受整体评估时间预算约束，按降级拒绝，不无限等待；
// 且被拖住的请求不影响其它请求。
func TestSlowDependencyBoundedByEvalBudget(t *testing.T) {
	block := make(chan struct{}) // 永不关闭：模拟卡住的依赖
	provider := AttributeProviderFunc(func(ctx context.Context, req Request, attrs []string) (map[string]any, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-block:
			return map[string]any{"clearance": "top"}, nil
		}
	})
	e := NewEngine(WithAttributeProvider(provider), WithEvalTimeout(20*time.Millisecond))
	if _, err := e.Publish(depPolicy()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	d := e.Authorize(context.Background(), Request{Subject: "u", Action: "read", Resource: "doc:1"})
	if d.Allow {
		t.Fatalf("stuck dependency must not allow, got %+v", d)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("request waited too long: %v", elapsed)
	}
	// 同一引擎上，不触碰该依赖的请求不被拖住的请求影响
	d2 := e.Authorize(context.Background(), Request{Subject: "u", Action: "write", Resource: "doc:1"})
	if d2.Allow || d2.Reason != ReasonNoAllowRule {
		t.Fatalf("unaffected request should evaluate normally (no_allow_rule), got %+v", d2)
	}
}

// 单次评估只取一次依赖快照：两个外部属性必须来自同一次获取，
// 不得出现半新半旧的混合结果。
func TestSingleEvaluationSingleDependencySnapshot(t *testing.T) {
	var calls atomic.Int32
	provider := AttributeProviderFunc(func(ctx context.Context, req Request, attrs []string) (map[string]any, error) {
		n := calls.Add(1)
		if len(attrs) != 2 {
			t.Errorf("expected both attrs fetched in one call, got %v", attrs)
		}
		// 每次调用返回的代际号递增；若引擎分两次获取，两代际号必然不同
		return map[string]any{"gen_a": n, "gen_b": n}, nil
	})
	p := &Policy{
		ExternalAttrs: []string{"gen_a", "gen_b"},
		Rules: []Rule{
			{ID: "allow-consistent", Effect: EffectAllow, Roles: []string{"*"},
				Actions: []string{"read"}, Resources: []string{"*"},
				Condition: &Condition{Attr: "gen_a", Op: "eq", Value: 1}},
			// 第二条规则引用 gen_b，若引擎按规则分别获取就会读到不同代际
			{ID: "deny-stale", Effect: EffectDeny, Roles: []string{"*"},
				Actions: []string{"read"}, Resources: []string{"*"},
				Condition: &Condition{Attr: "gen_b", Op: "ne", Value: 1}},
		},
	}
	e := NewEngine(WithAttributeProvider(provider))
	if _, err := e.Publish(p); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), Request{Subject: "u", Action: "read", Resource: "r"})
	if !d.Allow || d.RuleID != "allow-consistent" {
		t.Fatalf("single snapshot expected: gen_a==gen_b from one fetch, got %+v", d)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly one fetch per evaluation, got %d", calls.Load())
	}
}

// 不涉及外部属性的规则不触发依赖获取，行为与既有版本一致。
func TestNoDependencyPolicyUnchanged(t *testing.T) {
	called := atomic.Int32{}
	e := NewEngine(WithAttributeProvider(AttributeProviderFunc(
		func(ctx context.Context, req Request, attrs []string) (map[string]any, error) {
			called.Add(1)
			return nil, errors.New("should not be called")
		})))
	if _, err := e.Publish(allowAllPolicy()); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), Request{Subject: "u", Action: "a", Resource: "r"})
	if !d.Allow {
		t.Fatalf("no-dependency policy must behave as before, got %+v", d)
	}
	if called.Load() != 0 {
		t.Fatalf("provider must not be called for policies without external attrs, called %d times", called.Load())
	}
}

// 候选规则（角色/动作/资源已匹配）之外的规则不触发依赖获取。
func TestDependencyFetchedOnlyForCandidateRules(t *testing.T) {
	called := atomic.Int32{}
	e := NewEngine(WithAttributeProvider(AttributeProviderFunc(
		func(ctx context.Context, req Request, attrs []string) (map[string]any, error) {
			called.Add(1)
			return map[string]any{"clearance": "top"}, nil
		})))
	if _, err := e.Publish(depPolicy()); err != nil {
		t.Fatal(err)
	}
	// 动作不匹配，依赖规则不是候选，不应触发获取
	d := e.Authorize(context.Background(), Request{Subject: "u", Action: "write", Resource: "doc:1"})
	if d.Allow || d.Reason != ReasonNoAllowRule {
		t.Fatalf("expected no_allow_rule, got %+v", d)
	}
	if called.Load() != 0 {
		t.Fatalf("provider called for non-candidate rule: %d", called.Load())
	}
}

// 规则书写顺序变化时，决定性规则必须一致且可复现：
// 多条同效果规则命中时取规则 ID 字典序最小者。
func TestDecisiveRuleIndependentOfOrder(t *testing.T) {
	base := []Rule{
		{ID: "b-allow", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:*"}},
		{ID: "a-allow", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:*"}},
		{ID: "c-allow", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:1"}},
	}
	req := Request{Subject: "u", Action: "read", Resource: "doc:1"}
	ev := &evaluator{}
	want := ev.evaluate(&Policy{Rules: base}, req, 1)
	if !want.Allow || want.RuleID != "a-allow" {
		t.Fatalf("expected decisive rule a-allow (min ID), got %+v", want)
	}
	rng := rand.New(rand.NewSource(7))
	for iter := 0; iter < 100; iter++ {
		shuffled := append([]Rule(nil), base...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got := ev.evaluate(&Policy{Rules: shuffled}, req, 1)
		if got.RuleID != want.RuleID || got.Allow != want.Allow || got.Reason != want.Reason {
			t.Fatalf("iter %d: decisive rule changed with order: want %+v got %+v", iter, want, got)
		}
	}
}

// 多条拒绝规则命中时，决定性拒绝规则同样与书写顺序无关。
func TestDecisiveDenyRuleIndependentOfOrder(t *testing.T) {
	base := []Rule{
		{ID: "z-deny", Effect: EffectDeny, Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:*"}},
		{ID: "y-deny", Effect: EffectDeny, Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:*"}},
		{ID: "allow", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"*"}, Resources: []string{"*"}},
	}
	req := Request{Subject: "u", Action: "read", Resource: "doc:1"}
	ev := &evaluator{}
	want := ev.evaluate(&Policy{Rules: base}, req, 1)
	if want.Allow || want.RuleID != "y-deny" || want.Reason != ReasonExplicitDeny {
		t.Fatalf("expected decisive deny y-deny (min ID), got %+v", want)
	}
	rng := rand.New(rand.NewSource(9))
	for iter := 0; iter < 100; iter++ {
		shuffled := append([]Rule(nil), base...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got := ev.evaluate(&Policy{Rules: shuffled}, req, 1)
		if got.RuleID != want.RuleID || got.Allow != want.Allow || got.Reason != want.Reason {
			t.Fatalf("iter %d: decisive rule changed with order: want %+v got %+v", iter, want, got)
		}
	}
}
