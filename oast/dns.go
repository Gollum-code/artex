package oast

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// dnsServer is a minimal authoritative-for-one-zone DNS server. It answers only
// queries whose name ends in the configured base domain, and only for the record
// types that matter to an OAST callback (A, AAAA, TXT).
//
// Why not a full DNS stack: the only traffic this server should ever see is a
// target resolving a payload subdomain (or a TXT lookup of it, which is what a
// blind XXE/SQLi gadget does when it is asked to resolve the token). Serving
// anything else would either be wrong or a liability.
type dnsServer struct {
	addr string

	server *dns.Server
	udp    *dns.Server
	tcp    *dns.Server

	baseDomain string
	answerIPv4 net.IP

	// onCallback is invoked for every recognized query. It is called on the
	// serving goroutine, so implementations must not block.
	onCallback func(correlation, protocol, host, qtype, raw string)

	closeOnce sync.Once
}

// newDNSServer builds (but does not start) the server. A nil server is a valid
// "DNS disabled" result.
func newDNSServer(addr, baseDomain string, answerIPv4 net.IP, onCallback func(correlation, protocol, host, qtype, raw string)) *dnsServer {
	if addr == "" || onCallback == nil {
		return nil
	}
	return &dnsServer{
		addr:       addr,
		baseDomain: strings.ToLower(strings.TrimSuffix(baseDomain, ".")),
		answerIPv4: answerIPv4,
		onCallback: onCallback,
	}
}

// Start binds the listeners and serves. UDP is primary; TCP is added because
// some resolvers fall back to it and because it costs one socket.
func (s *dnsServer) Start() {
	if s == nil {
		return
	}
	pc, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		log.Printf("[oast] DNS UDP 监听失败 %s: %v", s.addr, err)
	} else {
		s.udp = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.serve)}
		go func() { _ = s.udp.ActivateAndServe() }()
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		// TCP failing is not fatal: every resolver retries over UDP.
		log.Printf("[oast] DNS TCP 监听失败 %s: %v", s.addr, err)
		return
	}
	s.tcp = &dns.Server{Listener: ln, Handler: dns.HandlerFunc(s.serve)}
	go func() { _ = s.tcp.ActivateAndServe() }()
}

// Close stops both listeners. Safe on a nil receiver.
func (s *dnsServer) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	s.closeOnce.Do(func() {
		if s.udp != nil {
			if err := s.udp.Shutdown(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if s.tcp != nil {
			if err := s.tcp.Shutdown(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})
	return firstErr
}

// serve answers one DNS query. Unknown names get a NOERROR empty answer (not
// NXDOMAIN): a scanner probing for the zone learns nothing, while a legitimate
// resolver that retried with different casing still resolves.
func (s *dnsServer) serve(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil || len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	host := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	qtype := dns.TypeToString[q.Qtype]
	if qtype == "" {
		qtype = "TYPE" + strconv.Itoa(int(q.Qtype))
	}

	if corr := s.correlationFor(host); corr != "" {
		s.onCallback(corr, "dns", host, qtype, "")
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	switch q.Qtype {
	case dns.TypeA:
		if ip := s.answerIPv4.To4(); ip != nil {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   ip,
			})
		}
	case dns.TypeAAAA:
		// Deliberately no AAAA answer: the lookup is still recorded as a hit,
		// which is what matters, and returning :: would make a follow-up HTTP
		// request hang on an unreachable address.
	case dns.TypeTXT:
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: []string{"oast"},
		})
	}
	_ = w.WriteMsg(m)
}

// correlationFor returns the correlation id of a hostname that ends in the base
// domain. The id is the leftmost label, so "abc.oast.example.com" -> "abc".
func (s *dnsServer) correlationFor(host string) string {
	if s == nil {
		return ""
	}
	base := normalizeDomain(s.baseDomain)
	if base == "" || host == base {
		return ""
	}
	suffix := "." + base
	if !strings.HasSuffix(host, suffix) {
		return ""
	}
	left := strings.TrimSuffix(host, suffix)
	// The correlation id is the FIRST label of the remainder; deeper labels
	// (e.g. a target that prefixes its own context) are ignored.
	if i := strings.IndexByte(left, '.'); i >= 0 {
		left = left[:i]
	}
	return left
}

// shortHash is a compact, stable, collision-resistant tag used to build ids.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
