package policy

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// Store is a versioned, concurrency-safe policy store.
//
// Publishing builds an immutable Policy snapshot and installs it with a
// single atomic pointer swap. Readers therefore always observe one
// complete, committed version: a publish in progress is never visible.
// Requests that started before a publish keep evaluating against the
// snapshot they captured (no mixed old/new results); new requests see
// the new version.
type Store struct {
	pubMu       sync.Mutex // serializes publishes
	current     atomic.Pointer[Policy]
	versions    map[int64]*Policy
	nextVersion int64
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{versions: make(map[int64]*Policy), nextVersion: 1}
}

// Current returns the latest committed policy snapshot, or nil if no
// policy has been published yet. The returned pointer is immutable and
// safe to use concurrently.
func (s *Store) Current() *Policy {
	return s.current.Load()
}

// Version returns the policy snapshot with the given version, or nil if
// that version does not exist.
func (s *Store) Version(v int64) *Policy {
	s.pubMu.Lock()
	p := s.versions[v]
	s.pubMu.Unlock()
	return p
}

// LatestVersion returns the version number of the current policy, or 0
// if no policy has been published.
func (s *Store) LatestVersion() int64 {
	if p := s.Current(); p != nil {
		return p.Version
	}
	return 0
}

// Publish validates the policy, assigns the next monotonic version and
// atomically installs it. On error the store is unchanged (the policy
// is not installed).
func (s *Store) Publish(p *Policy) (int64, error) {
	if p == nil {
		return 0, fmt.Errorf("%w: nil policy", ErrInvalidPolicy)
	}
	if err := p.Validate(); err != nil {
		return 0, err
	}

	s.pubMu.Lock()
	defer s.pubMu.Unlock()

	v := s.nextVersion
	s.nextVersion++
	p.Version = v
	s.versions[v] = p
	s.current.Store(p)
	return v, nil
}

// PublishPolicy is a convenience helper that validates and publishes a
// policy built by the caller. It returns ErrInvalidPolicy wrapped with
// the validation error when the policy is rejected.
func (s *Store) PublishPolicy(roles []Role, rules []Rule, required ...string) (int64, error) {
	p := &Policy{Roles: roles, Rules: rules, RequiredAttributes: required}
	v, err := s.Publish(p)
	if err != nil {
		return 0, errors.Join(ErrInvalidPolicy, err)
	}
	return v, nil
}
