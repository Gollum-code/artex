package oast

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Payload is one minted collaborator address: a subdomain of the base domain
// (for DNS callbacks) and an HTTP URL (for HTTP callbacks). CorrelationID is the
// unique part that ties a callback back to this payload.
//
// Both surfaces share one correlation id on purpose. A blind SSRF triggered by
// an attacker-supplied URL often reaches the payload as a DNS lookup first and
// as an HTTP request later; giving the two surfaces separate ids would split a
// single logical interaction across two payloads and force the agent to guess
// they belong together.
type Payload struct {
	ID            string    `json:"id"`             // internal payload id (also the storage key)
	CorrelationID string    `json:"correlation_id"` // unique host label under BaseDomain
	BaseDomain    string    `json:"base_domain"`    // operator-owned base domain, e.g. oast.example.com
	Subdomain     string    `json:"subdomain"`      // correlationid.base_domain
	URL           string    `json:"url"`            // HTTP callback URL
	Label         string    `json:"label"`          // free-form tag from the agent, e.g. "ssrf-order-42"
	TaskID        int64     `json:"task_id"`
	ExplorationID int64     `json:"exploration_id"`
	IntentID      int64     `json:"intent_id"`
	Worker        string    `json:"worker"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	// InteractionCount is bumped by the recorder so a payload listing can report
	// "still live / already hit" without a second query per payload.
	InteractionCount int `json:"interaction_count"`
}

// Expired reports whether the payload has passed its TTL.
func (p *Payload) Expired(now time.Time) bool { return !now.Before(p.ExpiresAt) }

// Hits returns how many interactions this payload has received.
func (p *Payload) Hits() int { return p.InteractionCount }

// correlationIDLength is the fixed length of a correlation id. A fixed length
// (rather than variable) is what lets the listener scan an arbitrary string for
// a 32-character window without a delimiter.
const correlationIDLength = 32

// correlationAlphabet is base32 built from the lowercase alphanumerics minus the
// ambiguous ones (0 1 l o), so an id stays readable when it appears in a target's
// log line, a screenshot, or a pasted payload. Exactly 32 symbols, which is what
// lets 5 bits map to one character with no skew.
const correlationAlphabet = "23456789abcdefghijkmnpqrstuvwxyz"

// newCorrelationID returns a fresh correlation id: 160 bits of CSPRNG output
// encoded over correlationAlphabet, exactly correlationIDLength characters.
func newCorrelationID() (string, error) {
	var buf [20]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("oast: correlation id entropy: %w", err)
	}
	// 20 bytes = 160 bits = 32 groups of 5 bits. Each group indexes the alphabet.
	out := make([]byte, 0, correlationIDLength)
	bitPos := 0
	totalBits := len(buf) * 8
	for i := 0; i < correlationIDLength; i++ {
		var v uint
		for b := 0; b < 5; b++ {
			if bitPos >= totalBits {
				break
			}
			byteIdx := bitPos / 8
			bitIdx := uint(7 - bitPos%8)
			v = (v << 1) | uint((buf[byteIdx]>>bitIdx)&1)
			bitPos++
		}
		out = append(out, correlationAlphabet[v])
	}
	return string(out), nil
}

// payloadSeq mints correlation ids that have never been handed out.
type payloadSeq struct {
	mu  sync.Mutex
	n   uint64
	gen func() (string, error)
}

func newPayloadSeq() *payloadSeq { return &payloadSeq{gen: newCorrelationID} }

// next returns a correlation id for which taken reports false. Collisions are
// retried; eight consecutive collisions mean the generator is broken, not
// unlucky, so it errors rather than risk a duplicate.
func (s *payloadSeq) next(taken func(string) bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for attempt := 0; attempt < 8; attempt++ {
		id, err := s.gen()
		if err != nil {
			return "", err
		}
		if taken == nil || !taken(id) {
			return id, nil
		}
	}
	return "", fmt.Errorf("oast: correlation id generator keeps colliding")
}

// nextSeq returns a monotonic counter value, used to make payload ids unique and
// k-sortable.
func (s *payloadSeq) nextSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return s.n
}

// payloadID builds the internal payload id. It embeds the correlation id so a
// listener that only sees a hostname can recover the payload without a lookup
// table keyed by substring, and a sequence suffix to keep ids unique and
// k-sortable in the store.
func payloadID(correlationID string, seq uint64) string {
	return fmt.Sprintf("oast_%s_%016x", correlationID, seq)
}

// normalizeDomain lowercases and strips a trailing dot.
func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}
