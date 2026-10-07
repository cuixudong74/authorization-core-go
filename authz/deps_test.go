package authz

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// stubProvider 是可编程的测试用外部属性提供者，并发安全。
type stubProvider struct {
	mu     sync.Mutex
	values map[string]any
	err    error
	calls  int
}

func (s *stubProvider) FetchAttributes(_ context.Context, _ Request, attrs []string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	out := make(map[string]any, len(attrs))
	for _, a := range attrs {
		if v, ok := s.values[a]; ok {
			out[a] = v
		}
	}
	return out, nil
}

func (s *stubProvider) set(values map[string]any, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values, s.err = values, err
}

func (s *stubProvider) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// depPolicy 声明外部属性 clearance：允许规则依赖它，另有一条无条件允许规则。
func depPolicy() *Policy {
	return &Policy{
		ExternalAttributes: []string{"clearance"},
		Rules: []Rule{
			{ID: "allow-clearance", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:*"},
				Condition: &Condition{Attr: "clearance", Op: "eq", Value: "top"}},
			{ID: "allow-all", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"*"}, Resources: []string{"*"}},
		},
	}
}

func depRequest() Request {
	return Request{Subject: "u", Roles: []string{"r"}, Action: "read", Resource: "doc:1"}
}

// 依赖获取失败：必须拒绝，且原因可与 no_allow_rule 等现有原因区分。
func TestDependencyFailureDeniesWithDistinctReason(t *testing.T) {
	p := &stubProvider{err: errors.New("backend down")}
	e := NewEngine(WithAttributeProvider(p))
	if _, err := e.Publish(depPolicy()); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), depRequest())
	if d.Allow {
		t.Fatalf("dependency failure must not allow, got %+v", d)
	}
	if d.Reason != ReasonDependencyUnavailable {
		t.Fatalf("expected dependency_unavailable, got %+v", d)
	}
	// 与"评估完成但无允许规则命中"明确区分
	if d.Reason == ReasonNoAllowRule || d.Reason == ReasonExplicitDeny {
		t.Fatalf("reason must be distinguishable from evaluation outcomes, got %+v", d)
	}
	// 可解释性：指出被依赖卡住的规则
	if d.RuleID != "allow-clearance" {
		t.Fatalf("expected blocked rule id, got %+v", d)
	}
}

// 依赖缺失时即使存在能匹配的无条件允许规则，也绝不允许放行。
func TestDependencyFailureOverridesAllowRule(t *testing.T) {
	p := &stubProvider{err: errors.New("backend down")}
	e := NewEngine(WithAttributeProvider(p))
	if _, err := e.Publish(depPolicy()); err != nil {
		t.Fatal(err)
	}
	// allow-all 规则无条件命中，但依赖不可用必须优先于允许
	d := e.Authorize(context.Background(), depRequest())
	if d.Allow || d.Reason != ReasonDependencyUnavailable {
		t.Fatalf("dependency failure must override allow rule, got %+v", d)
	}
}

// 依赖返回不完整（缺少必需属性）同样视为不可用。
func TestDependencyIncompleteResultDenies(t *testing.T) {
	p := &stubProvider{values: map[string]any{}} // 不返回 clearance
	e := NewEngine(WithAttributeProvider(p))
	if _, err := e.Publish(depPolicy()); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), depRequest())
	if d.Allow || d.Reason != ReasonDependencyUnavailable {
		t.Fatalf("incomplete dependency result must deny, got %+v", d)
	}
}

// 依赖恢复后，同一请求重新评估必须得到正常结论；失败结论不得被缓存。
func TestDependencyRecoveryRestoresDecision(t *testing.T) {
	p := &stubProvider{err: errors.New("backend down")}
	e := NewEngine(WithAttributeProvider(p))
	if _, err := e.Publish(depPolicy()); err != nil {
		t.Fatal(err)
	}
	req := depRequest()
	d1 := e.Authorize(context.Background(), req)
	if d1.Allow || d1.Reason != ReasonDependencyUnavailable {
		t.Fatalf("expected degraded deny, got %+v", d1)
	}
	// 依赖恢复：同一请求必须重新评估并得到原本的结论，
	// 且不是来自缓存（失败结论不允许被记住）。
	// 两条允许规则都命中时，决定性规则按 ID 字典序取 allow-all。
	p.set(map[string]any{"clearance": "top"}, nil)
	d2 := e.Authorize(context.Background(), req)
	if !d2.Allow || d2.RuleID != "allow-all" || d2.FromCache {
		t.Fatalf("recovered dependency must yield fresh allow, got %+v", d2)
	}
	// 成功结论可以缓存
	d3 := e.Authorize(context.Background(), req)
	if !d3.Allow || !d3.FromCache {
		t.Fatalf("successful decision should be cacheable, got %+v", d3)
	}
}

// 依赖取值变化时，不得复用旧取值下的缓存结论。
func TestDependencyValueChangeNotStale(t *testing.T) {
	p := &stubProvider{values: map[string]any{"clearance": "top"}}
	e := NewEngine(WithAttributeProvider(p))
	// 去掉无条件允许规则，结论完全由外部属性决定
	pol := depPolicy()
	pol.Rules = pol.Rules[:1]
	if _, err := e.Publish(pol); err != nil {
		t.Fatal(err)
	}
	req := depRequest()
	if d := e.Authorize(context.Background(), req); !d.Allow {
		t.Fatalf("expected allow with clearance=top, got %+v", d)
	}
	p.set(map[string]any{"clearance": "low"}, nil)
	d := e.Authorize(context.Background(), req)
	if d.Allow || d.Reason != ReasonNoAllowRule {
		t.Fatalf("changed dependency value must not reuse stale allow, got %+v", d)
	}
}

// 并发 + 时好时坏：每个请求的结论必须与它当次取到的依赖状态一致，
// 不得把别的请求的属性值泄漏进来，也不得单次评估内重复获取。
func TestDependencyConcurrentFlakyConsistency(t *testing.T) {
	// 策略：clearance == "good" 才允许（无兜底允许规则）
	pol := &Policy{
		ExternalAttributes: []string{"clearance"},
		Rules: []Rule{
			{ID: "allow-good", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:*"},
				Condition: &Condition{Attr: "clearance", Op: "eq", Value: "good"}},
		},
	}
	// 每个主体有确定的依赖状态：偶数 good、奇数 bad、7 的倍数出错。
	// 若发生跨请求泄漏或半新半旧混合，结论就会与主体编号矛盾。
	p := &subjectProvider{}
	e := NewEngine(WithAttributeProvider(p))
	if _, err := e.Publish(pol); err != nil {
		t.Fatal(err)
	}

	const workers = 16
	const perWorker = 200
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				n := w*perWorker + i
				req := Request{
					Subject:  fmt.Sprintf("sub-%d", n),
					Roles:    []string{"r"},
					Action:   "read",
					Resource: "doc:1",
				}
				d := e.Authorize(context.Background(), req)
				switch {
				case n%7 == 0:
					if d.Allow || d.Reason != ReasonDependencyUnavailable {
						t.Errorf("sub-%d: expected dependency_unavailable, got %+v", n, d)
					}
				case n%2 == 0:
					if !d.Allow || d.RuleID != "allow-good" {
						t.Errorf("sub-%d: expected allow, got %+v", n, d)
					}
				default:
					if d.Allow || d.Reason != ReasonNoAllowRule {
						t.Errorf("sub-%d: expected no_allow_rule, got %+v", n, d)
					}
				}
			}
		}(w)
	}
	wg.Wait()
	// 每个请求指纹唯一，单次评估只应获取一次依赖
	if got := p.callCount(); got != workers*perWorker {
		t.Fatalf("expected exactly %d fetches (one per evaluation), got %d", workers*perWorker, got)
	}
}

// subjectProvider 按主体编号确定性地返回值或错误，模拟时好时坏的依赖。
type subjectProvider struct {
	mu    sync.Mutex
	calls int
}

func (s *subjectProvider) FetchAttributes(_ context.Context, req Request, attrs []string) (map[string]any, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	var n int
	if _, err := fmt.Sscanf(req.Subject, "sub-%d", &n); err != nil {
		return nil, err
	}
	if n%7 == 0 {
		return nil, errors.New("flaky backend")
	}
	v := "bad"
	if n%2 == 0 {
		v = "good"
	}
	out := make(map[string]any, len(attrs))
	for _, a := range attrs {
		out[a] = v
	}
	return out, nil
}

func (s *subjectProvider) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// 依赖卡住：受整体评估超时约束，按降级拒绝，且不影响其它请求。
func TestDependencySlowFallsBackWithoutBlockingOthers(t *testing.T) {
	blocking := &blockingProvider{started: make(chan struct{})}
	e := NewEngine(WithAttributeProvider(blocking), WithEvalTimeout(20*time.Millisecond))
	if _, err := e.Publish(depPolicy()); err != nil {
		t.Fatal(err)
	}

	stuck := make(chan Decision, 1)
	go func() { stuck <- e.Authorize(context.Background(), depRequest()) }()
	<-blocking.started // 确认依赖调用已经卡住

	// 卡住期间，不需要外部属性的请求必须正常完成
	local := e.Authorize(context.Background(), Request{Subject: "u2", Action: "read", Resource: "other:1"})
	if !local.Allow || local.RuleID != "allow-all" {
		t.Fatalf("stuck dependency must not affect other requests, got %+v", local)
	}

	select {
	case d := <-stuck:
		if d.Allow || d.Reason != ReasonEvalTimeout {
			t.Fatalf("stuck dependency must degrade to eval_timeout deny, got %+v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request waited unboundedly on stuck dependency")
	}
}

type blockingProvider struct{ started chan struct{} }

func (b *blockingProvider) FetchAttributes(ctx context.Context, _ Request, _ []string) (map[string]any, error) {
	select {
	case <-b.started:
	default:
		close(b.started)
	}
	<-ctx.Done() // 卡住直到调用方上下文取消
	return nil, ctx.Err()
}

// 请求方已携带该属性时，不触发外部获取。
func TestRequestProvidedAttrSkipsProvider(t *testing.T) {
	p := &stubProvider{err: errors.New("must not be called")}
	e := NewEngine(WithAttributeProvider(p))
	pol := depPolicy()
	pol.Rules = pol.Rules[:1] // 只保留依赖 clearance 的规则
	if _, err := e.Publish(pol); err != nil {
		t.Fatal(err)
	}
	req := depRequest()
	req.Attributes = map[string]any{"clearance": "top"}
	d := e.Authorize(context.Background(), req)
	if !d.Allow || d.RuleID != "allow-clearance" {
		t.Fatalf("request-provided attr should be used directly, got %+v", d)
	}
	if p.callCount() != 0 {
		t.Fatalf("provider must not be called when request carries the attr, got %d calls", p.callCount())
	}
}

// 未配置 provider 但策略需要外部属性：按依赖不可用降级拒绝，绝不放行。
func TestMissingProviderDenies(t *testing.T) {
	e := NewEngine() // 不配置 provider
	pol := depPolicy()
	pol.Rules = pol.Rules[:1]
	if _, err := e.Publish(pol); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), depRequest())
	if d.Allow || d.Reason != ReasonDependencyUnavailable {
		t.Fatalf("missing provider must degrade to dependency_unavailable, got %+v", d)
	}
}

// 不声明外部属性的策略：即使配置了 provider 也绝不调用，行为不变。
func TestNoExternalAttrsKeepsExistingBehavior(t *testing.T) {
	p := &stubProvider{err: errors.New("must not be called")}
	e := NewEngine(WithAttributeProvider(p))
	if _, err := e.Publish(allowAllPolicy()); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), Request{Action: "a", Resource: "r"})
	if !d.Allow {
		t.Fatalf("plain policy must allow, got %+v", d)
	}
	if p.callCount() != 0 {
		t.Fatalf("provider must not be called for policies without external attributes")
	}
}

// 规则顺序变化时，决定性规则（RuleID）必须一致且可复现：
// 多条同效果规则命中时取规则 ID 字典序最小者。
func TestDecisiveRuleIndependentOfOrder(t *testing.T) {
	base := []Rule{
		{ID: "b-allow", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:*"}},
		{ID: "a-allow", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:*"}},
		{ID: "z-deny", Effect: EffectDeny, Roles: []string{"*"}, Actions: []string{"delete"}, Resources: []string{"doc:*"}},
		{ID: "y-deny", Effect: EffectDeny, Roles: []string{"*"}, Actions: []string{"delete"}, Resources: []string{"doc:*"}},
	}
	ev := &evaluator{}
	rng := rand.New(rand.NewSource(7))
	for iter := 0; iter < 100; iter++ {
		shuffled := append([]Rule(nil), base...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		p := &Policy{Rules: shuffled}
		d := ev.evaluate(p, Request{Roles: []string{"x"}, Action: "read", Resource: "doc:1"}, 1)
		if !d.Allow || d.RuleID != "a-allow" {
			t.Fatalf("iter %d: decisive allow rule must be a-allow regardless of order, got %+v", iter, d)
		}
		d = ev.evaluate(p, Request{Roles: []string{"x"}, Action: "delete", Resource: "doc:1"}, 1)
		if d.Allow || d.RuleID != "y-deny" || d.Reason != ReasonExplicitDeny {
			t.Fatalf("iter %d: decisive deny rule must be y-deny regardless of order, got %+v", iter, d)
		}
	}
}

// 非法的外部属性声明（空名、重复）整体拒绝发布，旧版本继续生效。
func TestExternalAttributesValidation(t *testing.T) {
	e := NewEngine()
	v1, err := e.Publish(allowAllPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Publish(&Policy{ExternalAttributes: []string{""}}); err == nil {
		t.Fatal("expected validation error for empty external attribute name")
	}
	if _, err := e.Publish(&Policy{ExternalAttributes: []string{"a", "a"}}); err == nil {
		t.Fatal("expected validation error for duplicate external attribute")
	}
	d := e.Authorize(context.Background(), Request{Action: "a", Resource: "r"})
	if !d.Allow || d.Version != v1 {
		t.Fatalf("invalid publish must not affect old version, got %+v", d)
	}
}
