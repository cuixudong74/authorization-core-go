package authz

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cuixudong74/authorization-core-go/policy"
)

func allowPolicy(version int64) *policy.Policy {
	return &policy.Policy{
		Version: version,
		Roles:   []policy.Role{{Name: "admin"}},
		Rules: []policy.Rule{
			{ID: "allow-admin", Effect: policy.EffectAllow, Roles: []string{"admin"}, Resource: "doc:*", Action: "*"},
		},
	}
}

func denyPolicy(version int64) *policy.Policy {
	return &policy.Policy{
		Version: version,
		Roles:   []policy.Role{{Name: "admin"}},
		Rules: []policy.Rule{
			{ID: "deny-all", Effect: policy.EffectDeny, Roles: []string{"admin"}, Resource: "*", Action: "*"},
		},
	}
}

func req() policy.Request {
	return policy.Request{Subject: "u1", SubjectRoles: []string{"admin"}, Resource: "doc:1", Action: "read"}
}

// --- degradation -----------------------------------------------------------

func TestPolicyMissing(t *testing.T) {
	e := NewEngine(policy.NewStore(), NewCache(), Config{CacheEnabled: true}, nil)
	d := e.Authorize(context.Background(), req())
	if d.Allowed || d.Reason != policy.ReasonPolicyMissing {
		t.Fatalf("expected policy_missing deny, got %+v", d)
	}
}

func TestInvalidRequest(t *testing.T) {
	e := NewEngine(policy.NewStore(), NewCache(), Config{}, nil)
	if _, err := e.Publish(allowPolicy(1)); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), policy.Request{Subject: "u1"}) // no resource/action
	if d.Allowed || d.Reason != policy.ReasonInvalidRequest {
		t.Fatalf("expected invalid_request deny, got %+v", d)
	}
}

type failingProvider struct{}

func (failingProvider) Attributes(context.Context, policy.Request) (map[string]string, error) {
	return nil, errors.New("attribute store down")
}

func TestDependencyMissingOnProviderError(t *testing.T) {
	e := NewEngine(policy.NewStore(), NewCache(), Config{}, failingProvider{})
	if _, err := e.Publish(allowPolicy(1)); err != nil {
		t.Fatal(err)
	}
	d := e.Authorize(context.Background(), req())
	if d.Allowed || d.Reason != policy.ReasonDependencyMissing {
		t.Fatalf("expected dependency_missing deny, got %+v", d)
	}
}

func TestDependencyMissingOnRequiredAttribute(t *testing.T) {
	store := policy.NewStore()
	p := allowPolicy(1)
	p.RequiredAttributes = []string{"tenant"}
	e := NewEngine(store, NewCache(), Config{}, nil)
	if _, err := e.Publish(p); err != nil {
		t.Fatal(err)
	}
	r := req()
	r.Attributes = map[string]string{} // tenant missing
	d := e.Authorize(context.Background(), r)
	if d.Allowed || d.Reason != policy.ReasonDependencyMissing {
		t.Fatalf("expected dependency_missing deny, got %+v", d)
	}
	// present -> allowed
	r.Attributes = map[string]string{"tenant": "t1"}
	d = e.Authorize(context.Background(), r)
	if !d.Allowed || d.Reason != policy.ReasonAllow {
		t.Fatalf("expected allow, got %+v", d)
	}
}

type blockingProvider struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingProvider) Attributes(context.Context, policy.Request) (map[string]string, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return map[string]string{}, nil
}

func TestTimeout(t *testing.T) {
	store := policy.NewStore()
	e := NewEngine(store, NewCache(), Config{EvalTimeout: 50 * time.Millisecond}, nil)
	if _, err := e.Publish(allowPolicy(1)); err != nil {
		t.Fatal(err)
	}
	bp := &blockingProvider{entered: make(chan struct{}), release: make(chan struct{})}
	e.provider = bp
	d := e.Authorize(context.Background(), req())
	if d.Allowed || d.Reason != policy.ReasonTimeout {
		t.Fatalf("expected timeout deny, got %+v", d)
	}
}

// --- cache -----------------------------------------------------------------

func TestCacheHitAndInvalidateOnPublish(t *testing.T) {
	store := policy.NewStore()
	cache := NewCache()
	e := NewEngine(store, cache, Config{CacheEnabled: true}, nil)
	if _, err := e.Publish(allowPolicy(1)); err != nil {
		t.Fatal(err)
	}
	r := req()
	d1 := e.Authorize(context.Background(), r)
	if !d1.Allowed {
		t.Fatalf("expected allow v1, got %+v", d1)
	}
	hits, misses, _ := cache.Stats()
	if hits != 0 || misses != 1 {
		t.Fatalf("after first eval: hits=%d misses=%d", hits, misses)
	}
	// second eval: cache hit
	d2 := e.Authorize(context.Background(), r)
	if !d2.Allowed || d2.Version != 1 {
		t.Fatalf("expected cached allow v1, got %+v", d2)
	}
	hits, _, _ = cache.Stats()
	if hits != 1 {
		t.Fatalf("expected 1 cache hit, got %d", hits)
	}
	// publish v2 (deny): cache must be invalidated, stale allow must not survive
	if _, err := e.Publish(denyPolicy(2)); err != nil {
		t.Fatal(err)
	}
	if cache.Len() != 0 {
		t.Fatalf("cache not invalidated after publish, len=%d", cache.Len())
	}
	d3 := e.Authorize(context.Background(), r)
	if d3.Allowed || d3.Reason != policy.ReasonDeny || d3.Version != 2 {
		t.Fatalf("expected deny v2 after publish, got %+v", d3)
	}
}

func TestCacheDoesNotServeOldVersion(t *testing.T) {
	store := policy.NewStore()
	cache := NewCache()
	e := NewEngine(store, cache, Config{CacheEnabled: true}, nil)
	if _, err := e.Publish(allowPolicy(1)); err != nil {
		t.Fatal(err)
	}
	r := req()
	e.Authorize(context.Background(), r)
	// hand-craft a stale entry tagged v1 and a fresh policy v2 in store
	cache.Set(cacheKey(1, r), 1, policy.Decision{Allowed: true, Reason: policy.ReasonAllow, Version: 1}, time.Hour)
	if _, err := e.Publish(denyPolicy(2)); err != nil {
		t.Fatal(err)
	}
	// stale entry was wiped by invalidate; but even if it remained, the
	// version check must reject it:
	if d, ok := cache.Get(cacheKey(1, r), 2); ok {
		t.Fatalf("stale entry served: %+v", d)
	}
	_ = e.Authorize(context.Background(), r)
}

// --- concurrency -----------------------------------------------------------

// TestConcurrentPublishAndEvaluate hammers the engine while policies are
// published. Invariant: every decision must equal a fresh evaluation
// against the exact policy version it reports — no mixed versions, no
// stale allows.
func TestConcurrentPublishAndEvaluate(t *testing.T) {
	store := policy.NewStore()
	cache := NewCache()
	e := NewEngine(store, cache, Config{CacheEnabled: true, EvalTimeout: time.Second}, nil)
	if _, err := e.Publish(allowPolicy(1)); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// publishers
	for p := 0; p < 4; p++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			n := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				ver := int64(2 + id*100 + n)
				var pol *policy.Policy
				if (id+n)%2 == 0 {
					pol = allowPolicy(ver)
				} else {
					pol = denyPolicy(ver)
				}
				if _, err := e.Publish(pol); err != nil {
					t.Errorf("publish failed: %v", err)
					return
				}
				n++
			}
		}(p)
	}

	// evaluators
	for c := 0; c < 8; c++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			r := req()
			r.Subject = fmt.Sprintf("u%d", id)
			for {
				select {
				case <-stop:
					return
				default:
				}
				d := e.Authorize(context.Background(), r)
				if d.Reason == policy.ReasonTimeout {
					continue
				}
				snap := store.Version(d.Version)
				if snap == nil {
					t.Errorf("decision references missing version %d", d.Version)
					continue
				}
				want := policy.Evaluate(snap, r)
				if d.Allowed != want.Allowed || d.Reason != want.Reason {
					t.Errorf("version %d: got %+v, want %+v", d.Version, d, want)
				}
			}
		}(c)
	}

	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestInFlightRequestsKeepSnapshot: a request that started before a
// publish must evaluate against the old version; new requests after the
// publish use the new version.
func TestInFlightRequestsKeepSnapshot(t *testing.T) {
	store := policy.NewStore()
	e := NewEngine(store, NewCache(), Config{CacheEnabled: true, EvalTimeout: time.Second}, nil)
	if _, err := e.Publish(allowPolicy(1)); err != nil {
		t.Fatal(err)
	}
	bp := &blockingProvider{entered: make(chan struct{}), release: make(chan struct{})}
	e.provider = bp

	r := req()
	done := make(chan policy.Decision, 1)
	go func() { done <- e.Authorize(context.Background(), r) }()

	<-bp.entered // snapshot v1 captured, evaluation blocked in provider

	if _, err := e.Publish(denyPolicy(2)); err != nil {
		t.Fatal(err)
	}
	close(bp.release)

	d := <-done
	if !d.Allowed || d.Version != 1 {
		t.Fatalf("in-flight request must use v1 snapshot, got %+v", d)
	}
	// new request after publish uses v2
	d2 := e.Authorize(context.Background(), r)
	if d2.Allowed || d2.Version != 2 {
		t.Fatalf("new request must use v2, got %+v", d2)
	}
}

// TestCacheClearDuringEvaluation: invalidating the cache while
// evaluations are in flight must never produce a wrong allow.
func TestCacheClearDuringEvaluation(t *testing.T) {
	store := policy.NewStore()
	cache := NewCache()
	e := NewEngine(store, cache, Config{CacheEnabled: true, EvalTimeout: time.Second}, nil)
	if _, err := e.Publish(allowPolicy(1)); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			r := req()
			r.Subject = fmt.Sprintf("u%d", id)
			for {
				select {
				case <-stop:
					return
				default:
				}
				d := e.Authorize(context.Background(), r)
				snap := store.Version(d.Version)
				if snap == nil {
					t.Errorf("missing version %d", d.Version)
					continue
				}
				want := policy.Evaluate(snap, r)
				if d.Allowed != want.Allowed {
					t.Errorf("version %d: got allow=%v want %v", d.Version, d.Allowed, want.Allowed)
				}
			}
		}(i)
	}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					cache.Invalidate()
					time.Sleep(time.Microsecond)
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}
