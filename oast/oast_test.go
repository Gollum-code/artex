package oast

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newTestEngine(t *testing.T) (*Engine, Store) {
	t.Helper()
	store := NewMemStore()
	e := New(store)
	err := e.Configure(Config{
		Enabled:    true,
		Domain:     "oast.test",
		AnswerIP:   "127.0.0.1",
		HTTPListen: "", // tests drive handlers directly
		DNSListen:  "",
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return e, store
}

func TestCorrelationIDFormat(t *testing.T) {
	for i := 0; i < 200; i++ {
		id, err := newCorrelationID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != correlationIDLength {
			t.Fatalf("len=%d want %d", len(id), correlationIDLength)
		}
		for _, c := range id {
			if !strings.ContainsRune(correlationAlphabet, c) {
				t.Fatalf("id %q contains out-of-alphabet %q", id, c)
			}
		}
	}
	// Two minted ids must differ.
	a, _ := newCorrelationID()
	b, _ := newCorrelationID()
	if a == b {
		t.Fatal("two ids collided")
	}
}

func TestMintPayloadShape(t *testing.T) {
	e, _ := newTestEngine(t)
	p, err := e.Mint(context.Background(), MintRequest{TaskID: 7, IntentID: 9, Worker: "w1", Label: "ssrf"})
	if err != nil {
		t.Fatal(err)
	}
	if p.TaskID != 7 || p.IntentID != 9 || p.Label != "ssrf" {
		t.Fatalf("attribution lost: %+v", p)
	}
	wantSub := p.CorrelationID + ".oast.test"
	if p.Subdomain != wantSub {
		t.Fatalf("subdomain=%q want %q", p.Subdomain, wantSub)
	}
	if !strings.HasPrefix(p.URL, "http://"+wantSub) {
		t.Fatalf("url=%q", p.URL)
	}
	if p.ID == "" || !strings.HasPrefix(p.ID, "oast_") {
		t.Fatalf("id=%q", p.ID)
	}
}

func TestHTTPCallbackByHostAndDedup(t *testing.T) {
	e, _ := newTestEngine(t)
	p, _ := e.Mint(context.Background(), MintRequest{TaskID: 1})

	// A target that resolves the payload and fetches it with the payload host.
	req := reqWithHost(p.Subdomain, "/robots.txt?x=1")
	req.Header.Set("User-Agent", "curl/8.0")
	rec := httptest.NewRecorder()
	e.serveHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	// Duplicate delivery of the same evidence must not create a second row.
	e.serveHTTP(httptest.NewRecorder(), req)

	got, err := e.Poll(context.Background(), 1, "", time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("interactions=%d want 1", len(got))
	}
	in := got[0]
	if in.Protocol != "http" || in.Method != http.MethodGet || in.RemoteAddr != "198.51.100.9" {
		t.Fatalf("bad interaction: %+v", in)
	}
	if !strings.Contains(in.RawRequest, "curl/8.0") {
		t.Fatalf("raw request missing UA: %q", in.RawRequest)
	}
	payloads, _ := e.List(context.Background(), 1, 10)
	if len(payloads) != 1 || payloads[0].Hits() != 1 {
		t.Fatalf("hit count not bumped: %+v", payloads)
	}
}

func TestHTTPCorrelationInPathAndBody(t *testing.T) {
	e, _ := newTestEngine(t)

	// Path form (public_base_url deployments where the host is fixed).
	p1, _ := e.Mint(context.Background(), MintRequest{TaskID: 2})
	rec := httptest.NewRecorder()
	e.serveHTTP(rec, reqWithHost("10.0.0.5:8080", "/api/fetch/"+p1.CorrelationID))
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}

	// Body form (an SSRF that posts the URL in a JSON field).
	p2, _ := e.Mint(context.Background(), MintRequest{TaskID: 2})
	body := `{"webhook":"http://` + p2.Subdomain + `/cb"}`
	req := httptest.NewRequest(http.MethodPost, "http://10.0.0.5:8080/api/hook", strings.NewReader(body))
	req.Host = "10.0.0.5:8080"
	req.Header.Set("Content-Type", "application/json")
	e.serveHTTP(httptest.NewRecorder(), req)

	got, _ := e.Poll(context.Background(), 2, "", time.Time{}, 10)
	if len(got) != 2 {
		t.Fatalf("interactions=%d want 2", len(got))
	}
}

func TestDNSCallback(t *testing.T) {
	e, _ := newTestEngine(t)
	p, _ := e.Mint(context.Background(), MintRequest{TaskID: 3})

	// Drive the real DNS handler with a query for the payload's A record.
	ds := &dnsServer{
		baseDomain: "oast.test",
		answerIPv4: e.answerIP(),
		onCallback: func(correlation, proto, host, qtype, raw string) {
			e.recordCallback(context.Background(), correlation, Interaction{
				Protocol: proto, Kind: strings.ToLower(qtype), FullHost: host, QueryName: host, QueryType: qtype,
			})
		},
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(p.Subdomain), dns.TypeA)
	w := &recordingWriter{}
	ds.serve(w, m)

	if w.msg == nil {
		t.Fatal("no DNS reply")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answers=%d want 1 A record", len(w.msg.Answer))
	}
	if a, ok := w.msg.Answer[0].(*dns.A); !ok || a.A.String() != "127.0.0.1" {
		t.Fatalf("bad A answer: %+v", w.msg.Answer[0])
	}
	got, _ := e.Poll(context.Background(), 3, "", time.Time{}, 10)
	if len(got) != 1 || got[0].Protocol != "dns" || got[0].Kind != "a" {
		t.Fatalf("bad DNS interaction: %+v", got)
	}
}

func TestUnknownHostNotRecorded(t *testing.T) {
	e, _ := newTestEngine(t)
	// A scanner hitting the listener with a random host must not create evidence.
	rec := httptest.NewRecorder()
	e.serveHTTP(rec, reqWithHost("random-host.oast.test", "/"))
	got, _ := e.Poll(context.Background(), 0, "", time.Time{}, 10)
	if len(got) != 0 {
		t.Fatalf("unknown host recorded: %+v", got)
	}
	if rec.Code != 200 {
		// Still returns 200 so the listener is not a fingerprinting oracle.
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestPayloadExpiry(t *testing.T) {
	mem := NewMemStore()
	e := New(mem)
	current := time.Now()
	e.now = func() time.Time { return current }
	if err := e.Configure(Config{Enabled: true, Domain: "oast.test", AnswerIP: "127.0.0.1", TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	p, _ := e.Mint(context.Background(), MintRequest{TaskID: 4})

	// Before expiry the payload resolves.
	if e.lookup(context.Background(), p.CorrelationID) == nil {
		t.Fatal("payload should resolve before expiry")
	}
	// A callback after expiry is dropped.
	current = current.Add(2 * time.Minute)
	rec := httptest.NewRecorder()
	e.serveHTTP(rec, reqWithHost(p.Subdomain, "/"))
	if got, _ := e.Poll(context.Background(), 4, "", time.Time{}, 10); len(got) != 0 {
		t.Fatalf("expired payload recorded: %+v", got)
	}
	// And it is filtered from List.
	if ps, _ := e.List(context.Background(), 4, 10); len(ps) != 0 {
		t.Fatalf("expired payload listed: %+v", ps)
	}
	// The janitor removes it.
	if n, m, err := mem.DeleteExpired(context.Background(), current); err != nil || n != 1 || m != 0 {
		t.Fatalf("DeleteExpired = %d,%d,%v", n, m, err)
	}
}

func TestConfigureValidation(t *testing.T) {
	cases := []Config{
		{Enabled: true, Domain: "http://oast.test"},
		{Enabled: true, Domain: "nodot"},
		{Enabled: true, Domain: "oast.test", AnswerIP: "not-an-ip"},
		{Enabled: true},
	}
	for i, c := range cases {
		if err := c.Validate(); err == nil {
			t.Fatalf("case %d should be invalid: %+v", i, c)
		}
	}
	ok := Config{Enabled: true, Domain: "oast.test", AnswerIP: "127.0.0.1"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestFindCorrelationInText(t *testing.T) {
	e, _ := newTestEngine(t)
	p, _ := e.Mint(context.Background(), MintRequest{TaskID: 5})
	// A log line where the id is embedded with punctuation.
	line := "GET /proxy?url=http%3A%2F%2F" + strings.ToUpper(p.CorrelationID) + ".oast.test%2F&x=1"
	if got := e.findCorrelationInText(line); got != p.CorrelationID {
		t.Fatalf("got %q want %q", got, p.CorrelationID)
	}
	if got := e.findCorrelationInText("nothing to see here 1234567890abc"); got != "" {
		t.Fatalf("false positive: %q", got)
	}
}

// --- helpers ---

func reqWithHost(host, path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	r.Host = host
	r.RemoteAddr = "198.51.100.9:1234"
	return r
}

// recordingWriter captures the reply message so a test can assert on it.
type recordingWriter struct {
	msg *dns.Msg
}

func (w *recordingWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *recordingWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}
func (w *recordingWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *recordingWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *recordingWriter) Close() error                { return nil }
func (w *recordingWriter) TsigStatus() error           { return nil }
func (w *recordingWriter) TsigTimersOnly(bool)         {}
func (w *recordingWriter) Hijack()                     {}

var _ io.Reader = strings.NewReader("")
