package oast

import (
	"context"
	"sync"
	"time"
)

// memStore is the in-memory Store used by tests and by deployments that want
// OAST without persistence. It is not for production persistence (payloads and
// interactions vanish on restart), but it exercises the exact same code paths
// the PostgreSQL store does.
type memStore struct {
	mu           sync.Mutex
	payloads     map[string]*Payload
	interactions []*Interaction
	bindings     map[int64][]string
	seq          int64
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() Store {
	return &memStore{payloads: map[string]*Payload{}, bindings: map[int64][]string{}}
}

func (s *memStore) nextID() int64 {
	s.seq++
	return s.seq
}

func (s *memStore) InsertPayload(_ context.Context, p *Payload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *p
	s.payloads[clone.CorrelationID] = &clone
	return nil
}

func (s *memStore) GetPayload(_ context.Context, id string) (*Payload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.payloads {
		if p.ID == id {
			clone := *p
			return &clone, nil
		}
	}
	return nil, nil
}

func (s *memStore) GetPayloadByCorrelation(_ context.Context, correlationID string) (*Payload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.payloads[correlationID]
	if !ok {
		return nil, nil
	}
	clone := *p
	return &clone, nil
}

func (s *memStore) ListPayloads(_ context.Context, taskID int64, limit int) ([]*Payload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Payload, 0, len(s.payloads))
	for _, p := range s.payloads {
		if taskID > 0 && p.TaskID != taskID {
			continue
		}
		clone := *p
		out = append(out, &clone)
	}
	// Newest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *memStore) InsertInteraction(_ context.Context, in *Interaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.interactions {
		if existing.ID == in.ID {
			return nil // idempotent by evidence-derived id
		}
	}
	clone := *in
	s.interactions = append(s.interactions, &clone)
	if p, ok := s.payloads[in.Correlation]; ok {
		p.InteractionCount++
	}
	return nil
}

func (s *memStore) ListInteractions(_ context.Context, taskID int64, payloadID string, since time.Time, limit int) ([]*Interaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// correlation id -> payload, for the task filter.
	corrOf := func(pid string) string {
		for _, p := range s.payloads {
			if p.ID == pid {
				return p.CorrelationID
			}
		}
		return ""
	}
	out := make([]*Interaction, 0, len(s.interactions))
	for _, in := range s.interactions {
		if payloadID != "" && in.PayloadID != payloadID {
			continue
		}
		if taskID > 0 {
			p := s.payloads[in.Correlation]
			if p == nil || p.TaskID != taskID {
				continue
			}
		}
		if !since.IsZero() && !in.Timestamp.After(since) {
			continue
		}
		clone := *in
		out = append(out, &clone)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	_ = corrOf
	return out, nil
}

func (s *memStore) DeleteExpired(_ context.Context, now time.Time) (int64, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var dead []string
	for corr, p := range s.payloads {
		if p.Expired(now) {
			dead = append(dead, corr)
		}
	}
	var removedInts int64
	for _, corr := range dead {
		delete(s.payloads, corr)
		kept := s.interactions[:0]
		for _, in := range s.interactions {
			if in.Correlation != corr {
				kept = append(kept, in)
			} else {
				removedInts++
			}
		}
		s.interactions = kept
	}
	return int64(len(dead)), removedInts, nil
}

func (s *memStore) BindFindingPayloads(_ context.Context, findingID int64, payloadIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range payloadIDs {
		if id == "" {
			continue
		}
		if !contains(s.bindings[findingID], id) {
			s.bindings[findingID] = append(s.bindings[findingID], id)
		}
	}
	return nil
}

func (s *memStore) ListFindingPayloads(_ context.Context, findingID int64) ([]*Payload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := s.bindings[findingID]
	out := make([]*Payload, 0, len(want))
	for _, id := range want {
		for _, p := range s.payloads {
			if p.ID == id {
				clone := *p
				out = append(out, &clone)
				break
			}
		}
	}
	return out, nil
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
