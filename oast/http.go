package oast

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
)

// maxEvidenceBytes caps how much of a callback request body is kept as evidence.
// A blind SSRF often returns a large target page (10s of MB); keeping it whole
// would blow up the database and the agent's context for no analytical gain,
// while the first 64 KiB is more than enough to prove control of the response.
const maxEvidenceBytes = 64 << 10

// callbackBanner is the response every HTTP callback receives. It is
// deliberately generic: the request having arrived is the signal, and telling a
// scanner what it found would make the collaborator itself a fingerprinting
// oracle.
const callbackBanner = `<!doctype html><html><head><meta charset="utf-8"><title>OK</title></head><body><h1>OK</h1></body></html>`

// serveHTTP is the handler for the HTTP listener. It records every request that
// carries a live correlation id, in the host, the path, the query, a header, or
// the body, then answers with a neutral 200 so the caller (the target) believes
// the request was handled normally.
func (e *Engine) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body := readEvidenceBody(r)
	corr := e.findCorrelationInRequest(r, body)
	if corr != "" {
		raw := dumpRequest(r, body)
		proto := "http"
		if r.TLS != nil {
			proto = "https"
		}
		e.recordCallback(r.Context(), corr, Interaction{
			Protocol:   proto,
			Kind:       "http",
			FullHost:   hostFromURL(r.Host),
			Method:     r.Method,
			Path:       r.URL.Path,
			URL:        absoluteRequestURL(r),
			UserAgent:  httpUserAgent(r),
			RemoteAddr: remoteHost(r),
			RawRequest: raw,
			Body:       body,
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(callbackBanner))
}

// findCorrelationInRequest looks for a live correlation id anywhere a blind
// probe might place it. Ordering is cheapest-and-most-likely first, but every
// source is checked: a DNS-only gadget resolves the host, a plain SSRF keeps it
// in the host, an API that fetches a user-controlled "callback" keeps it in the
// query or body, and a proxy-style SSRF often carries it in X-Forwarded-Host.
func (e *Engine) findCorrelationInRequest(r *http.Request, body string) string {
	// 1. Host labels: the canonical shape (abc123.oast.example.com).
	if corr := e.findCorrelationInText(hostFromURL(r.Host)); corr != "" {
		return corr
	}
	// 2. Path and query: the shape used when only an HTTP base is configured.
	if corr := e.findCorrelationInText(r.URL.Path); corr != "" {
		return corr
	}
	if corr := e.findCorrelationInText(r.URL.RawQuery); corr != "" {
		return corr
	}
	// 3. Forwarding headers a proxy-based SSRF frequently preserves.
	for _, h := range []string{"X-Forwarded-Host", "X-Original-URL", "Referer", "Origin"} {
		if v := r.Header.Get(h); v != "" {
			if corr := e.findCorrelationInText(v); corr != "" {
				return corr
			}
		}
	}
	// 4. Body last: it is the largest and the least common location.
	if body != "" {
		if corr := e.findCorrelationInText(body); corr != "" {
			return corr
		}
	}
	return ""
}

// findCorrelationInText scans text for a maximal run of payload-alphabet
// characters, then checks every 32-character window inside it against the live
// payload registry. Runs shorter than the id length cannot match and are
// skipped, so the scan is linear in the text length.
func (e *Engine) findCorrelationInText(text string) string {
	if text == "" {
		return ""
	}
	const idLen = 32
	lower := strings.ToLower(text)
	runStart := -1
	check := func(start, end int) string {
		if end-start < idLen {
			return ""
		}
		for i := start; i+idLen <= end; i++ {
			candidate := lower[i : i+idLen]
			if !isCorrelationAlphabet(candidate) {
				continue
			}
			e.mu.RLock()
			p := e.payloads[candidate]
			e.mu.RUnlock()
			if p != nil {
				return candidate
			}
		}
		return ""
	}
	for i := 0; i < len(lower); i++ {
		if isAlphabetByte(lower[i]) {
			if runStart < 0 {
				runStart = i
			}
			continue
		}
		if runStart >= 0 {
			if corr := check(runStart, i); corr != "" {
				return corr
			}
			runStart = -1
		}
	}
	if runStart >= 0 {
		if corr := check(runStart, len(lower)); corr != "" {
			return corr
		}
	}
	return ""
}

// isAlphabetByte reports whether b can appear in a correlation id.
func isAlphabetByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// isCorrelationAlphabet reports whether s consists only of correlation-alphabet
// characters (a cheap pre-filter before the map lookup).
func isCorrelationAlphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isAlphabetByte(s[i]) {
			return false
		}
	}
	return true
}

// readEvidenceBody reads up to maxEvidenceBytes of the request body, restoring
// the body so a caller that wants to serve it still can (it does not, but the
// contract is friendlier than consuming the stream).
func readEvidenceBody(r *http.Request) string {
	if r == nil || r.Body == nil {
		return ""
	}
	limited := io.LimitReader(r.Body, maxEvidenceBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil || len(data) == 0 {
		return ""
	}
	truncated := len(data) > maxEvidenceBytes
	if truncated {
		data = data[:maxEvidenceBytes]
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	if truncated {
		return string(data) + "\n\n...[截断：原始请求体超过 64 KiB]"
	}
	if isProbablyBinary(data) {
		return "[二进制内容，hex 前 4096 字节]\n" + hex.EncodeToString(data[:min(len(data), 4096)])
	}
	return string(data)
}

// isProbablyBinary is a cheap NUL/control-byte heuristic.
func isProbablyBinary(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

// dumpRequest renders the request head plus body for the evidence record.
func dumpRequest(r *http.Request, body string) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteString(" ")
	b.WriteString(r.RequestURI)
	b.WriteString(" ")
	b.WriteString(r.Proto)
	b.WriteString("\r\nHost: ")
	b.WriteString(r.Host)
	b.WriteString("\r\n")
	for k, vs := range r.Header {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

// absoluteRequestURL reconstructs the URL a client requested, for display.
func absoluteRequestURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// remoteHost strips the port from a RemoteAddr.
func remoteHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	addr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
