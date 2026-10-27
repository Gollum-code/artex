package oast

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Store is the persistence contract the engine needs. The db package implements
// it against PostgreSQL; tests implement it in memory. Keeping it here (rather
// than importing db) lets the engine be exercised without a database.
type Store interface {
	InsertPayload(ctx context.Context, p *Payload) error
	GetPayload(ctx context.Context, id string) (*Payload, error)
	GetPayloadByCorrelation(ctx context.Context, correlationID string) (*Payload, error)
	ListPayloads(ctx context.Context, taskID int64, limit int) ([]*Payload, error)
	InsertInteraction(ctx context.Context, in *Interaction) error
	ListInteractions(ctx context.Context, taskID int64, payloadID string, since time.Time, limit int) ([]*Interaction, error)
	DeleteExpired(ctx context.Context, now time.Time) (int64, int64, error)
	BindFindingPayloads(ctx context.Context, findingID int64, payloadIDs []string) error
	ListFindingPayloads(ctx context.Context, findingID int64) ([]*Payload, error)
}

// Config is the engine's runtime configuration. It is re-read by the server on
// every settings change, so a listener can be brought up or down without a
// process restart.
type Config struct {
	// Enabled gates the whole subsystem: when false no listener runs and tools
	// report the feature as off.
	Enabled bool
	// Domain is the base domain the operator controls, e.g. "oast.example.com".
	// The operator points a wildcard A record (and, for DNS callbacks, the zone's
	// NS record) at this host. Empty disables DNS payloads but HTTP path payloads
	// can still work if PublicBaseURL is set.
	Domain string
	// AnswerIP is the address returned for A queries. A target must be able to
	// reach it for DNS-then-HTTP chains to work.
	AnswerIP string
	// HTTPListen is the address the HTTP listener binds, e.g. ":8080". Empty
	// disables HTTP callbacks.
	HTTPListen string
	// DNSListen is the address the DNS listener binds, e.g. ":53". Empty disables
	// DNS callbacks. Binding :53 needs root or CAP_NET_BIND_SERVICE.
	DNSListen string
	// PublicBaseURL, when set, is the scheme+host used in generated HTTP payload
	// URLs instead of deriving them from Domain/HTTPListen. Use it behind a
	// reverse proxy or when the public port differs from the listen port.
	PublicBaseURL string
	// TTL is how long a payload stays valid. Zero means 72h.
	TTL time.Duration
}

// DefaultTTL is the payload lifetime when Config.TTL is unset.
const DefaultTTL = 72 * time.Hour

// Validate normalizes and checks a config. It returns a non-nil error only for
// values that cannot be honoured (which the settings handler maps to HTTP 400).
func (c *Config) Validate() error {
	c.Domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(c.Domain, ".")))
	c.AnswerIP = strings.TrimSpace(c.AnswerIP)
	c.HTTPListen = strings.TrimSpace(c.HTTPListen)
	c.DNSListen = strings.TrimSpace(c.DNSListen)
	c.PublicBaseURL = strings.TrimRight(strings.TrimSpace(c.PublicBaseURL), "/")
	if c.TTL <= 0 {
		c.TTL = DefaultTTL
	}
	if !c.Enabled {
		return nil
	}
	if c.Domain == "" && c.PublicBaseURL == "" {
		return errors.New("启用 OAST 需要至少配置一个域（domain）或公网基础地址（public_base_url）")
	}
	if c.Domain != "" {
		if strings.Contains(c.Domain, "://") || strings.ContainsAny(c.Domain, " /") {
			return errors.New("domain 只能是裸域名，例如 oast.example.com")
		}
		if !strings.Contains(c.Domain, ".") {
			return errors.New("domain 需要是一个完整域名，例如 oast.example.com")
		}
	}
	if c.AnswerIP != "" && net.ParseIP(c.AnswerIP) == nil {
		return errors.New("answer_ip 不是合法 IP")
	}
	if c.PublicBaseURL != "" {
		if !strings.HasPrefix(c.PublicBaseURL, "http://") && !strings.HasPrefix(c.PublicBaseURL, "https://") {
			return errors.New("public_base_url 需要以 http:// 或 https:// 开头")
		}
	}
	return nil
}

// MintRequest asks the engine for a new payload.
type MintRequest struct {
	TaskID        int64
	ExplorationID int64
	IntentID      int64
	Worker        string
	Label         string
}

// Engine owns the listeners, the payload registry, and the poll bookkeeping.
// One Engine is shared process-wide; it is safe for concurrent use.
type Engine struct {
	store Store

	mu       sync.RWMutex
	cfg      Config
	payloads map[string]*Payload // correlation id -> payload, the hot lookup path
	running  bool

	seq *payloadSeq

	httpSrv *http.Server
	dnsSrv  *dnsServer

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// now is injectable so TTL behaviour is testable without sleeping.
	now func() time.Time
}

// New builds an engine over store. It does not start listeners; call Configure.
func New(store Store) *Engine {
	return &Engine{
		store:    store,
		payloads: map[string]*Payload{},
		seq:      newPayloadSeq(),
		stopCh:   make(chan struct{}),
		now:      time.Now,
	}
}

// Config returns a copy of the active config.
func (e *Engine) Config() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// Enabled reports whether listeners are up and payloads can be minted.
func (e *Engine) Enabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Enabled
}

// Configure validates cfg, then starts, stops, or restarts listeners so the
// running state matches it. It is idempotent: calling it with an unchanged
// config is cheap when listeners are already up.
func (e *Engine) Configure(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	e.mu.Lock()
	prev := e.cfg
	e.cfg = cfg
	// A disabled engine keeps its payload map (cached, harmless) but no listeners.
	if !cfg.Enabled {
		e.mu.Unlock()
		e.stopListeners()
		return nil
	}
	needRestart := !e.running ||
		prev.HTTPListen != cfg.HTTPListen ||
		prev.DNSListen != cfg.DNSListen
	e.mu.Unlock()

	if !needRestart {
		return nil
	}
	e.stopListeners()
	return e.startListeners()
}

// Start launches the TTL janitor. Listeners are started by Configure.
func (e *Engine) Start(ctx context.Context) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.janitor(ctx)
	}()
}

// Close stops listeners and the janitor.
func (e *Engine) Close() error {
	e.stopOnce.Do(func() { close(e.stopCh) })
	err := e.stopListeners()
	e.wg.Wait()
	return err
}

func (e *Engine) startListeners() error {
	e.mu.Lock()
	cfg := e.cfg
	e.mu.Unlock()

	// HTTP
	if cfg.HTTPListen != "" {
		srv := &http.Server{Addr: cfg.HTTPListen, Handler: http.HandlerFunc(e.serveHTTP)}
		ln, err := net.Listen("tcp", cfg.HTTPListen)
		if err != nil {
			return fmt.Errorf("oast: HTTP 监听 %s 失败: %w", cfg.HTTPListen, err)
		}
		e.mu.Lock()
		e.httpSrv = srv
		e.mu.Unlock()
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[oast] HTTP 监听退出: %v", err)
			}
		}()
		log.Printf("[oast] HTTP 回连监听 %s（域 %s）", cfg.HTTPListen, cfg.Domain)
	}

	// DNS
	if cfg.DNSListen != "" {
		ds := newDNSServer(cfg.DNSListen, cfg.Domain, e.answerIP(), func(correlation string, proto string, host string, qtype string, raw string) {
			e.recordCallback(context.Background(), correlation, Interaction{
				Protocol: proto, Kind: strings.ToLower(qtype), FullHost: host,
				QueryName: host, QueryType: qtype, RawRequest: raw,
			})
		})
		if ds == nil {
			return errors.New("oast: DNS 监听未配置")
		}
		e.mu.Lock()
		e.dnsSrv = ds
		e.mu.Unlock()
		ds.Start()
		log.Printf("[oast] DNS 回连监听 %s（域 %s，应答 A=%s）", cfg.DNSListen, cfg.Domain, cfg.AnswerIP)
	}

	e.mu.Lock()
	e.running = true
	e.mu.Unlock()
	return nil
}

func (e *Engine) stopListeners() error {
	e.mu.Lock()
	httpSrv, dnsSrv := e.httpSrv, e.dnsSrv
	e.httpSrv, e.dnsSrv = nil, nil
	e.running = false
	e.mu.Unlock()

	var firstErr error
	if httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := httpSrv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		cancel()
	}
	if dnsSrv != nil {
		if err := dnsSrv.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// answerIP returns the configured A-record answer, or the loopback address when
// unset (which is the right answer for a same-host target and a harmless one
// otherwise).
func (e *Engine) answerIP() net.IP {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if ip := net.ParseIP(e.cfg.AnswerIP); ip != nil {
		return ip
	}
	return net.ParseIP("127.0.0.1")
}

// Mint allocates a new payload. The returned payload is persisted before it is
// returned, so a callback that arrives in the same instant as the caller plants
// the URL still resolves.
func (e *Engine) Mint(ctx context.Context, req MintRequest) (*Payload, error) {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	if !cfg.Enabled {
		return nil, errors.New("OAST 未启用")
	}
	if cfg.Domain == "" && cfg.PublicBaseURL == "" {
		return nil, errors.New("OAST 未配置域或公网基础地址")
	}

	corr, err := e.seq.next(func(id string) bool {
		e.mu.RLock()
		_, ok := e.payloads[id]
		e.mu.RUnlock()
		return ok
	})
	if err != nil {
		return nil, err
	}

	now := e.now()
	p := &Payload{
		ID:            payloadID(corr, e.seq.nextSeq()),
		CorrelationID: corr,
		BaseDomain:    cfg.Domain,
		Label:         strings.TrimSpace(req.Label),
		TaskID:        req.TaskID,
		ExplorationID: req.ExplorationID,
		IntentID:      req.IntentID,
		Worker:        req.Worker,
		CreatedAt:     now,
		ExpiresAt:     now.Add(cfg.TTL),
	}
	if cfg.Domain != "" {
		p.Subdomain = corr + "." + cfg.Domain
	}
	p.URL = e.payloadURL(cfg, corr)

	if err := e.store.InsertPayload(ctx, p); err != nil {
		return nil, fmt.Errorf("oast: 保存 payload: %w", err)
	}
	e.mu.Lock()
	e.payloads[corr] = p
	e.mu.Unlock()
	return p, nil
}

// payloadURL builds the HTTP callback URL for a correlation id. Three shapes,
// in priority order:
//
//  1. PublicBaseURL set -> <base>/<correlation> (reverse proxy / non-standard port)
//  2. Domain + HTTPListen -> http://<correlation>.<domain>[:port]/
//  3. Domain only -> http://<correlation>.<domain>/
//
// When none yields a usable URL the payload still has its DNS name, and the
// caller surfaces that.
func (e *Engine) payloadURL(cfg Config, corr string) string {
	if cfg.PublicBaseURL != "" {
		return cfg.PublicBaseURL + "/" + corr
	}
	if cfg.Domain == "" {
		return ""
	}
	host := corr + "." + cfg.Domain
	if port := listenPort(cfg.HTTPListen); port != "" && port != "80" && port != "443" {
		return "http://" + host + ":" + port + "/"
	}
	return "http://" + host + "/"
}

// listenPort extracts the port from a listen address like ":8080" or
// "0.0.0.0:8080". It returns "" when the address carries no usable port.
func listenPort(addr string) string {
	if addr == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

// lookup resolves a correlation id to a payload, checking the in-process cache
// first and the store second (so a payload minted before a restart still
// resolves, provided its row is still live).
func (e *Engine) lookup(ctx context.Context, corr string) *Payload {
	if corr == "" {
		return nil
	}
	e.mu.RLock()
	p := e.payloads[corr]
	e.mu.RUnlock()
	if p != nil {
		return p
	}
	p, err := e.store.GetPayloadByCorrelation(ctx, corr)
	if err != nil || p == nil {
		return nil
	}
	if p.Expired(e.now()) {
		return nil
	}
	e.mu.Lock()
	e.payloads[corr] = p
	e.mu.Unlock()
	return p
}

// recordCallback stores an interaction, incrementing the payload's hit counter.
// It is called from listener goroutines; store errors are logged, not returned,
// because a failed write must never break the listener (the target is waiting
// for a response and the DNS/HTTP response is already going out).
func (e *Engine) recordCallback(ctx context.Context, corr string, in Interaction) {
	p := e.lookup(ctx, corr)
	if p == nil {
		// Unknown or expired token: this is background noise (scanners, stale
		// payloads) and must not be persisted as evidence.
		return
	}
	if p.Expired(e.now()) {
		return
	}

	in.Correlation = corr
	in.PayloadID = p.ID
	in.FullHost = strings.ToLower(strings.TrimSuffix(in.FullHost, "."))
	if in.Timestamp.IsZero() {
		in.Timestamp = e.now()
	}
	// The id is deterministic on the evidence, so a duplicate delivery (DNS retry,
	// HTTP keep-alive replay) cannot create two rows for one callback.
	if in.ID == "" {
		in.ID = interactionID(in)
	}
	if err := e.store.InsertInteraction(ctx, &in); err != nil {
		log.Printf("[oast] 记录回连失败 (%s): %v", corr, err)
		return
	}
	e.mu.Lock()
	p.InteractionCount++
	e.mu.Unlock()
}

// interactionID derives a stable id from the interaction's identifying fields.
func interactionID(in Interaction) string {
	parts := []string{in.PayloadID, in.Protocol, in.Kind, in.FullHost, in.QueryName, in.QueryType, in.Method, in.URL, in.RemoteAddr, in.Timestamp.UTC().Format(time.RFC3339Nano)}
	return "oastint_" + shortHash(strings.Join(parts, "|"))
}

// Poll returns interactions for a task (or one payload within it) newer than
// since. A zero since returns everything still retained, most recent first.
func (e *Engine) Poll(ctx context.Context, taskID int64, payloadID string, since time.Time, limit int) ([]*Interaction, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return e.store.ListInteractions(ctx, taskID, payloadID, since, limit)
}

// List returns the task's live payloads with their hit counts.
func (e *Engine) List(ctx context.Context, taskID int64, limit int) ([]*Payload, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out, err := e.store.ListPayloads(ctx, taskID, limit)
	if err != nil {
		return nil, err
	}
	now := e.now()
	filtered := out[:0]
	for _, p := range out {
		if p.Expired(now) {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered, nil
}

// BindFinding attaches payloads to a finding so a report can cite the OOB
// evidence that confirmed it.
func (e *Engine) BindFinding(ctx context.Context, findingID int64, payloadIDs []string) error {
	if findingID <= 0 || len(payloadIDs) == 0 {
		return nil
	}
	return e.store.BindFindingPayloads(ctx, findingID, payloadIDs)
}

// janitor periodically deletes expired payloads and their interactions.
func (e *Engine) janitor(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case <-t.C:
			if n, m, err := e.store.DeleteExpired(ctx, e.now()); err != nil {
				log.Printf("[oast] 清理过期数据失败: %v", err)
			} else if n > 0 || m > 0 {
				log.Printf("[oast] 清理过期 payload %d 个、回连 %d 条", n, m)
			}
		}
	}
}
