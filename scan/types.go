// Package scan bridges external recon and vulnerability scanners into ARTEX.
//
// # Why it exists
//
// An autonomous agent can already run `nuclei` or `ffuf` through Bash, but the
// output is prose it has to re-read and hand-translate into insert_assets and
// report_finding calls. That loses structure (status codes, matched templates,
// extracted values), duplicates findings across rescans, and spends model tokens
// on parsing instead of reasoning. This package runs the scanner, parses its
// machine-readable output into a neutral model, and hands the result to the asset
// and finding stores in one step.
//
// # Design
//
// Parsing is pure: a scanner's stdout (or JSON file) goes in, a Result comes out,
// with no database or process dependency, so every format is unit-tested against
// captured samples. Execution is a thin wrapper over os/exec with a timeout and a
// bounded output buffer. Ingestion maps Result onto the existing AssetStore
// upserts and a fingerprinted finding write, so a rescan cannot duplicate a
// finding and a scan never invents an asset shape the rest of ARTEX cannot read.
package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Scanner format identifiers. A profile names the parser used for its output.
const (
	FormatNuclei    = "nuclei"
	FormatHttpx     = "httpx"
	FormatSubfinder = "subfinder"
	FormatFfuf      = "ffuf"
	FormatKatana    = "katana"
	FormatJSONL     = "jsonl"
	FormatNone      = "none"
)

// Asset kinds mirror assets.type so ingestion needs no translation table.
const (
	AssetSubdomain = "subdomain"
	AssetIP        = "ip"
	AssetService   = "service"
	AssetEndpoint  = "endpoint"
)

// Asset is one observational record from a scanner, already normalized to the
// shape the asset store expects. Zero fields are simply not written.
type Asset struct {
	Kind string

	// subdomain / ip
	Domain      string
	IP          string
	RecordType  string
	RecordValue []string
	BoundDomain string

	// service / endpoint
	URL           string
	Method        string
	Port          int
	ServiceName   string
	StatusCode    int
	ContentLength int64
	PageTitle     string
	Technologies  []string
	FaviconMMH3   string

	Source string // scanner name that produced this record
}

// Finding is one vulnerability report from a scanner.
type Finding struct {
	VulnClass string // template id / rule id — the stable machine key
	Name      string
	Severity  string // critical|high|medium|low
	Summary   string
	Evidence  string

	Host       string
	MatchedAt  string
	ExternalID string // matcher-name / parameter / signal, when the scanner has one
	Source     string // scanner name

	Tags       []string
	CWE        []string
	CVSSScore  float64
	CVSSVector string
	References []string
}

// Result is everything one scanner invocation produced.
type Result struct {
	Scanner  string
	Target   string
	Assets   []Asset
	Findings []Finding
	Warnings []string
	Records  int // input records seen, including ones that produced nothing
}

// FingerprintKey is the dedup identity of a finding produced by a scanner. It is
// deliberately independent of severity and free text: the same template firing on
// the same endpoint is the same finding, no matter how the summary is worded.
//
// The result is a hex digest rather than a joined string because it is stored in a
// PostgreSQL text column, which rejects NUL bytes — a natural separator for an
// unambiguous join.
func (f Finding) FingerprintKey() string {
	host := f.Host
	if f.MatchedAt != "" {
		host = f.MatchedAt
	}
	return hashKey(strings.Join([]string{f.Source, f.VulnClass, f.ExternalID, host}, "\x00"))
}

// hashKey returns the SHA-256 hex digest of s.
func hashKey(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (r *Result) warn(msg string) {
	if len(r.Warnings) >= 25 {
		return
	}
	r.Warnings = append(r.Warnings, msg)
}

// addAsset appends a in-memory dedup key only when it is new. The store upserts
// are still idempotent; this just keeps the result payload small.
func (r *Result) addAsset(seen map[string]bool, a Asset) {
	k := a.dedupKey()
	if k == "" || seen[k] {
		return
	}
	seen[k] = true
	r.Assets = append(r.Assets, a)
}

func (a Asset) dedupKey() string {
	switch a.Kind {
	case AssetSubdomain:
		return "sub:" + lower(a.Domain)
	case AssetIP:
		return "ip:" + a.IP
	case AssetService:
		return "svc:" + lower(a.URL)
	case AssetEndpoint:
		return "ep:" + upper(a.Method) + " " + lower(a.URL)
	}
	return ""
}
