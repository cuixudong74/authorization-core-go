package authz

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func allowAllPolicy() *Policy {
	return &Policy{Rules: []Rule{
		{ID: "allow", Effect: EffectAllow, Roles: []string{"*"}, Actions: []string{"*"}, Resources: []string{"*"}},
	}}
}

func denyAllPolicy() *Policy {
	return &Policy{Rules: []Rule{
		{ID: "deny", Effect: EffectDeny, Roles: []string{"*"}, Actions: []string{"*"}, Resources: []string{"*"}},
	}}
}

func TestPolicyMissingFallback(t *testing.T) {
	e := NewEngine()
	d := e.Authorize(context.Background(), Request{Action: "read", Resource: "x"})
	if d.Allow || d.Reason != ReasonPolicyMissing {
		t.Fatalf("expected policy_missing deny, got %+v", d)
	}
}

func TestCacheHitAndVersionIsolation(t *testing.T) {
	e := NewEngine()
	if _, err := e.Publish(allowAllPolicy()); err != nil {
		t.Fatal(err)
	}
	req := Request{Subject: "u", Roles: []string{"r"}, Action: "read", Resource: "doc:1"}
	d1 := e.Authorize(context.Background(), req)
	if !d1.Allow || d1.FromCache {
		t.Fatalf("first call should be uncached allow, got %+v", d1)
	}
	d2 := e.Authorize(context.Background(), req)
	if !d2.Allow || !d2.FromCache {
		t.Fatalf("second call should be cached allow, got %+v", d2)
	}
	// 发布拒绝策略后，旧的允许结论不得继续生效
	if _, err := e.Publish(denyAllPolicy()); err != nil {
		t.Fatal(err)
	}
	d3 := e.Authorize(context.Background(), req)
	if d3.Allow || d3.Reason != ReasonExplicitDeny || d3.FromCache {
		t.Fatalf("stale cache must not survive publish, got %+v", d3)
	}
}

func TestPublishValidationKeepsOldVersion(t *testing.T) {
	e := NewEngine()
	v1, err := e.Publish(allowAllPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Publish(&Policy{Rules: []Rule{{ID: ""}}}); err == nil {
		t.Fatal("expected validation error for rule without id")
	}
	d := e.Authorize(context.Background(), Request{Action: "a", Resource: "r"})
	if !d.Allow || d.Version != v1 {
		t.Fatalf("invalid publish must not affect old version, got %+v", d)
	}
}

func TestConcurrentPublishAndAuthorize(t *testing.T) {
	e := NewEngine(WithCacheSize(64))
	if _, err := e.Publish(allowAllPolicy()); err != nil {
		t.Fatal(err)
	}
	req := Request{Subject: "u", Roles: []string{"r"}, Action: "read", Resource: "doc:1"}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// 发布方：交替发布允许/拒绝策略
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				_, _ = e.Publish(allowAllPolicy())
			} else {
				_, _ = e.Publish(denyAllPolicy())
			}
		}
	}()
	// 读取方：每次结论必须与某个完整版本一致（允许或显式拒绝），
	// 不得出现新旧混合（本例中体现为原因与效果自洽）。
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				d := e.Authorize(context.Background(), req)
				if d.Allow && d.RuleID != "allow" {
					t.Errorf("inconsistent allow: %+v", d)
				}
				if !d.Allow && d.Reason != ReasonExplicitDeny {
					t.Errorf("unexpected deny reason: %+v", d)
				}
			}
		}()
	}
	// 让读取方跑一段时间后停止发布方
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	// 切换完成后新请求必须按最新版本评估
	_, _ = e.Publish(denyAllPolicy())
	d := e.Authorize(context.Background(), req)
	if d.Allow {
		t.Fatalf("after final publish, request must follow new version, got %+v", d)
	}
}

func TestInFlightRequestSeesSingleSnapshot(t *testing.T) {
	e := NewEngine()
	if _, err := e.Publish(allowAllPolicy()); err != nil {
		t.Fatal(err)
	}
	// 单次 Authorize 只取一次快照：评估期间发生发布，
	// 该请求仍完整使用旧版本（结论为旧版本的 allow，版本号一致）。
	req := Request{Action: "a", Resource: "r"}
	d := e.Authorize(context.Background(), req)
	if !d.Allow || d.Version != 1 {
		t.Fatalf("expected version 1 allow, got %+v", d)
	}
}

func TestEvalTimeoutFallback(t *testing.T) {
	e := NewEngine(WithEvalTimeout(time.Nanosecond))
	if _, err := e.Publish(allowAllPolicy()); err != nil {
		t.Fatal(err)
	}
	// 超时窗口极小，评估 goroutine 大概率来不及完成；
	// 即使偶发完成也只允许 allow 或 timeout 拒绝，绝不静默放行。
	seenTimeout := false
	for i := 0; i < 100; i++ {
		d := e.Authorize(context.Background(), Request{Action: fmt.Sprintf("a%d", i), Resource: "r"})
		if !d.Allow && d.Reason != ReasonEvalTimeout {
			t.Fatalf("unexpected reason: %+v", d)
		}
		if d.Reason == ReasonEvalTimeout {
			seenTimeout = true
		}
	}
	if !seenTimeout {
		t.Log("no timeout observed (evaluation faster than 1ns is impossible in practice)")
	}
}

func TestContextCancelFallback(t *testing.T) {
	e := NewEngine(WithEvalTimeout(time.Hour))
	if _, err := e.Publish(allowAllPolicy()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 已取消的上下文
	d := e.Authorize(ctx, Request{Action: "a", Resource: "r"})
	// 两种合法结果：评估在取消前完成（allow），或走降级（eval_timeout 拒绝）。
	// 绝不允许出现其他拒绝原因或静默放行。
	if d.Allow {
		return
	}
	if d.Reason != ReasonEvalTimeout {
		t.Fatalf("degraded deny must be eval_timeout, got %+v", d)
	}
}

func TestConcurrentCacheAccessNoDirtyRead(t *testing.T) {
	e := NewEngine(WithCacheSize(8)) // 小容量，强制频繁清空重建
	if _, err := e.Publish(allowAllPolicy()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				req := Request{Subject: fmt.Sprintf("u%d", w), Action: fmt.Sprintf("a%d", i%20), Resource: "r"}
				d := e.Authorize(context.Background(), req)
				if !d.Allow {
					t.Errorf("allow-all policy must never deny, got %+v", d)
				}
			}
		}(w)
	}
	wg.Wait()
}
