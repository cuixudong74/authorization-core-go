package authz

import (
	"context"
	"time"

	"github.com/cuixudong74/authorization-core-go/policy"
)

// Default configuration values.
const (
	DefaultEvalTimeout = 2 * time.Second
)

// AttributeProvider supplies attributes for a request. When the engine
// is configured with a provider, a provider failure is treated as a
// missing dependency and the request is denied (never silently allowed).
type AttributeProvider interface {
	Attributes(ctx context.Context, req policy.Request) (map[string]string, error)
}

// Config configures the authorization engine.
type Config struct {
	// EvalTimeout bounds how long an evaluation may take. Zero means
	// DefaultEvalTimeout.
	EvalTimeout time.Duration
	// CacheTTL bounds how long a cached decision stays valid. Zero means
	// entries only become invalid on policy publish.
	CacheTTL time.Duration
	// CacheEnabled toggles the decision cache.
	CacheEnabled bool
}

// Engine is the single authorization entry point.
type Engine struct {
	store    *policy.Store
	cache    *Cache
	provider AttributeProvider
	cfg      Config
}

// NewEngine wires the engine. cache may be nil to disable caching;
// provider may be nil to rely solely on request-supplied attributes.
func NewEngine(store *policy.Store, cache *Cache, cfg Config, provider AttributeProvider) *Engine {
	if cfg.EvalTimeout <= 0 {
		cfg.EvalTimeout = DefaultEvalTimeout
	}
	return &Engine{store: store, cache: cache, cfg: cfg, provider: provider}
}

// Publish validates and installs a new policy version and invalidates
// every cached decision so stale conclusions cannot survive.
func (e *Engine) Publish(p *policy.Policy) (int64, error) {
	v, err := e.store.Publish(p)
	if err != nil {
		return 0, err
	}
	if e.cache != nil {
		e.cache.Invalidate()
	}
	return v, nil
}

// deny builds a deny decision for the given reason, tagged with the
// policy version when available.
func deny(reason policy.Reason, version int64) policy.Decision {
	return policy.Decision{Allowed: false, Reason: reason, Version: version}
}

// Authorize decides a single request.
//
// Failure semantics (all failures default to deny with a distinct
// reason):
//   - malformed request        -> ReasonInvalidRequest
//   - no policy published       -> ReasonPolicyMissing
//   - attribute provider error  -> ReasonDependencyMissing
//   - required attribute absent -> ReasonDependencyMissing
//   - evaluation timeout        -> ReasonTimeout
func (e *Engine) Authorize(parent context.Context, req policy.Request) policy.Decision {
	if req.Subject == "" || req.Resource == "" || req.Action == "" {
		return deny(policy.ReasonInvalidRequest, 0)
	}

	// Snapshot the policy before doing any work: requests in flight keep
	// evaluating this version even while a publish installs a new one.
	pol := e.store.Current()
	if pol == nil {
		return deny(policy.ReasonPolicyMissing, 0)
	}

	ctx, cancel := context.WithTimeout(parent, e.cfg.EvalTimeout)
	defer cancel()

	type result struct {
		d policy.Decision
	}
	done := make(chan result, 1)
	go func() {
		attrs := req.Attributes
		if e.provider != nil {
			provided, err := e.provider.Attributes(ctx, req)
			if err != nil {
				done <- result{deny(policy.ReasonDependencyMissing, pol.Version)}
				return
			}
			merged := make(map[string]string, len(attrs)+len(provided))
			for k, v := range provided {
				merged[k] = v
			}
			for k, v := range attrs { // request attributes win
				merged[k] = v
			}
			attrs = merged
		}
		req.Attributes = attrs

		if missing := policy.MissingRequiredAttributes(pol, req); len(missing) > 0 {
			done <- result{deny(policy.ReasonDependencyMissing, pol.Version)}
			return
		}

		if e.cache != nil && e.cfg.CacheEnabled {
			key := cacheKey(pol.Version, req)
			if d, ok := e.cache.Get(key, pol.Version); ok {
				done <- result{d}
				return
			}
			d := policy.Evaluate(pol, req)
			e.cache.Set(key, pol.Version, d, e.cfg.CacheTTL)
			done <- result{d}
			return
		}

		done <- result{policy.Evaluate(pol, req)}
	}()

	select {
	case <-ctx.Done():
		return deny(policy.ReasonTimeout, pol.Version)
	case r := <-done:
		return r.d
	}
}

// cacheKey prefixes the request fingerprint with the policy version so
// that entries from older versions can never match.
func cacheKey(version int64, req policy.Request) string {
	return "v" + itoa(version) + "|" + policy.Fingerprint(req)
}

// itoa is a tiny allocation-free int-to-string helper.
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
