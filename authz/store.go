package authz

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// snapshot 是一次完整发布的不可变快照。
type snapshot struct {
	policy  *Policy
	version uint64
}

// store 保存已提交的策略版本。
// 发布时先在锁内构造完整快照，再一次原子指针替换对外可见，
// 因此读取方任一时刻只能看到某个已提交的完整版本，
// 绝不暴露发布过程中的半成品。
type store struct {
	mu  sync.Mutex // 仅串行化发布
	cur atomic.Pointer[snapshot]
}

func newStore() *store { return &store{} }

// publish 校验并原子发布一个完整版本，返回新版本号（单调递增）。
func (s *store) publish(p *Policy) (uint64, error) {
	if p == nil {
		return 0, errors.New("authz: nil policy")
	}
	if err := validatePolicy(p); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var v uint64
	if cur := s.cur.Load(); cur != nil {
		v = cur.version
	}
	v++
	s.cur.Store(&snapshot{policy: p, version: v})
	return v, nil
}

// current 返回当前已发布版本；从未发布过时 ok=false。
func (s *store) current() (p *Policy, version uint64, ok bool) {
	snap := s.cur.Load()
	if snap == nil {
		return nil, 0, false
	}
	return snap.policy, snap.version, true
}

// validatePolicy 发布前校验，非法策略整体拒绝发布，不影响旧版本。
func validatePolicy(p *Policy) error {
	seen := make(map[string]struct{}, len(p.ExternalAttributes))
	for _, a := range p.ExternalAttributes {
		if a == "" {
			return errors.New("authz: external attribute name must not be empty")
		}
		if _, dup := seen[a]; dup {
			return fmt.Errorf("authz: duplicate external attribute %q", a)
		}
		seen[a] = struct{}{}
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("authz: rule %d missing id", i)
		}
		if r.Effect != EffectAllow && r.Effect != EffectDeny {
			return fmt.Errorf("authz: rule %q has invalid effect", r.ID)
		}
		if c := r.Condition; c != nil {
			switch c.Op {
			case "eq", "ne", "in", "glob":
			default:
				return fmt.Errorf("authz: rule %q has unknown condition op %q", r.ID, c.Op)
			}
		}
	}
	return nil
}
