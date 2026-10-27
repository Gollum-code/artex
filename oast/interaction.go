package oast

import (
	"net/http"
	"strings"
	"time"
)

// Interaction is one received callback. Protocol and the raw exchange are the
// evidence: an agent cites them, a human reviews them, and a finding's proof
// chain references the interaction id. Nothing here is inferred or summarized.
type Interaction struct {
	ID          string    `json:"id"`
	PayloadID   string    `json:"payload_id"`
	Protocol    string    `json:"protocol"` // dns | http | https
	Kind        string    `json:"kind"`     // a | aaaa | txt | http
	Correlation string    `json:"correlation_id"`
	FullHost    string    `json:"full_host"` // the hostname the query/request was for
	QueryName   string    `json:"query_name,omitempty"`
	QueryType   string    `json:"query_type,omitempty"`
	Method      string    `json:"method,omitempty"`
	Path        string    `json:"path,omitempty"`
	URL         string    `json:"url,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	RemoteAddr  string    `json:"remote_addr"`
	RawRequest  string    `json:"raw_request,omitempty"`
	RawResponse string    `json:"raw_response,omitempty"`
	Body        string    `json:"body,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// InteractionView is the trimmed shape returned to agents: enough to prove the
// callback happened and describe it, without the raw dumps. Use Interaction() for
// the full evidence.
type InteractionView struct {
	ID          string    `json:"id"`
	Protocol    string    `json:"protocol"`
	Kind        string    `json:"kind"`
	Correlation string    `json:"correlation_id"`
	FullHost    string    `json:"full_host"`
	Method      string    `json:"method,omitempty"`
	Path        string    `json:"path,omitempty"`
	URL         string    `json:"url,omitempty"`
	RemoteAddr  string    `json:"remote_addr"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

func (i *Interaction) view() InteractionView {
	return InteractionView{
		ID: i.ID, Protocol: i.Protocol, Kind: i.Kind, Correlation: i.Correlation,
		FullHost: i.FullHost, Method: i.Method, Path: i.Path, URL: i.URL,
		RemoteAddr: i.RemoteAddr, UserAgent: i.UserAgent, Timestamp: i.Timestamp,
	}
}

// hostFromURL extracts the host portion of an absolute URL, tolerating a
// userinfo prefix and a port suffix. Returns "" when the input has no host.
func hostFromURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	// Strip brackets from an IPv6 literal, then any port.
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if i := strings.LastIndexByte(s, ':'); i >= 0 && !strings.Contains(s, "]") {
		// Only strip when what follows looks like a port (all digits).
		rest := s[i+1:]
		allDigits := rest != ""
		for _, c := range rest {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			s = s[:i]
		}
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// httpUserAgent reads the client User-Agent, which is the single most useful
// discriminator when a blind probe fires from a server-side HTTP library.
func httpUserAgent(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Header.Get("User-Agent")
}
