package scan

import (
	"encoding/json"
	"strconv"
	"strings"
)

// nucleiRecord is the JSON shape nuclei emits with -jsonl (or the JSON entries of
// -json). Only the fields ARTEX uses are declared; everything else is dropped.
type nucleiRecord struct {
	TemplateID   string   `json:"template-id"`
	TemplatePath string   `json:"template-path"`
	TemplateURL  string   `json:"template-url"`
	Type         string   `json:"type"`
	Host         string   `json:"host"`
	MatchedAt    string   `json:"matched-at"`
	MatcherName  string   `json:"matcher-name"`
	IP           string   `json:"ip"`
	Extracted    []string `json:"extracted-results"`
	Request      string   `json:"request"`
	Response     string   `json:"response"`
	Timestamp    int64    `json:"timestamp"`

	Info struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Author         string   `json:"author"`
		Tags           string   `json:"tags"`
		Description    string   `json:"description"`
		Reference      []string `json:"reference"`
		Remediation    string   `json:"remediation"`
		Classification struct {
			CVEID       []string `json:"cve-id"`
			CWEID       []string `json:"cwe-id"`
			CVSSMetrics string   `json:"cvss-metrics"`
			CVSSScore   float64  `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
}

// ParseNuclei converts nuclei JSONL output (one JSON object per line) into the
// neutral Result. Lines that are not JSON objects, and objects without a
// template-id, are skipped with a warning rather than failing the whole run.
func ParseNuclei(scanner, target string, out []byte) *Result {
	r := &Result{Scanner: scanner, Target: target}
	if scanner == "" {
		r.Scanner = FormatNuclei
	}
	seen := map[string]bool{}
	findSeen := map[string]bool{}
	skippedInfo := 0

	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec nucleiRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			r.warn("跳过无法解析的第 " + itoa(i+1) + " 行")
			continue
		}
		r.Records++
		if rec.TemplateID == "" {
			continue
		}
		id := CleanID(rec.TemplateID)
		host := firstNonEmpty(rec.MatchedAt, rec.Host)

		// A template firing on a host is itself evidence the host is alive, so it
		// becomes a service asset. The origin is the service identity; a non-root
		// path additionally becomes an endpoint, so a payload-laden matched-at does
		// not masquerade as a new service.
		if host != "" {
			if origin := originOf(host); origin != "" {
				r.addAsset(seen, Asset{Kind: AssetService, URL: origin, IP: rec.IP, Source: r.Scanner})
			}
			if isEndpointURL(host) {
				r.addAsset(seen, Asset{Kind: AssetEndpoint, URL: host, Method: "GET", IP: rec.IP, Source: r.Scanner})
			}
		}

		f := Finding{
			VulnClass:  id,
			Name:       firstNonEmpty(rec.Info.Name, id),
			Severity:   NormalizeSeverity(rec.Info.Severity),
			Summary:    Clip(firstNonEmpty(rec.Info.Description, rec.Info.Name), 2000),
			Evidence:   nucleiEvidence(rec),
			Host:       rec.Host,
			MatchedAt:  host,
			ExternalID: CleanID(firstNonEmpty(rec.MatcherName, rec.Type)),
			Source:     r.Scanner,
			Tags:       splitCSV(rec.Info.Tags),
			CWE:        rec.Info.Classification.CWEID,
			CVSSScore:  rec.Info.Classification.CVSSScore,
			CVSSVector: rec.Info.Classification.CVSSMetrics,
			References: rec.Info.Reference,
		}
		// Info/unknown templates are fingerprinting, not vulnerabilities: their
		// host already became an asset above. Recording them as "low" would flood
		// the findings table with tech-detection noise.
		switch strings.ToLower(strings.TrimSpace(rec.Info.Severity)) {
		case "info", "informational", "unknown":
			skippedInfo++
			continue
		}
		if f.Name == "" {
			f.Name = id
		}
		k := f.FingerprintKey()
		if findSeen[k] {
			continue
		}
		findSeen[k] = true
		r.Findings = append(r.Findings, f)
	}
	if skippedInfo > 0 {
		r.warn(itoa(skippedInfo) + " 条 info/unknown 模板命中作为指纹资产入库，未登记为漏洞")
	}
	return r
}

func nucleiEvidence(rec nucleiRecord) string {
	var b strings.Builder
	// Classification first: CVSS/CVE/CWE are what a reader needs to triage, and
	// findings has no dedicated columns for them yet.
	if rec.Info.Classification.CVSSScore > 0 || rec.Info.Classification.CVSSMetrics != "" || len(rec.Info.Classification.CVEID) > 0 {
		b.WriteString("=== classification ===\n")
		if len(rec.Info.Classification.CVEID) > 0 {
			b.WriteString("CVE: " + strings.Join(rec.Info.Classification.CVEID, ", ") + "\n")
		}
		if len(rec.Info.Classification.CWEID) > 0 {
			b.WriteString("CWE: " + strings.Join(rec.Info.Classification.CWEID, ", ") + "\n")
		}
		if rec.Info.Classification.CVSSScore > 0 {
			b.WriteString("CVSS: " + formatScore(rec.Info.Classification.CVSSScore))
			if rec.Info.Classification.CVSSMetrics != "" {
				b.WriteString(" (" + rec.Info.Classification.CVSSMetrics + ")")
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if rec.Request != "" {
		b.WriteString("=== request ===\n")
		b.WriteString(Clip(rec.Request, 4000))
		b.WriteString("\n\n")
	}
	if rec.Response != "" {
		b.WriteString("=== response ===\n")
		b.WriteString(Clip(rec.Response, 6000))
		b.WriteString("\n\n")
	}
	if len(rec.Extracted) > 0 {
		b.WriteString("=== extracted ===\n")
		for _, e := range rec.Extracted {
			b.WriteString(Clip(e, 500))
			b.WriteString("\n")
		}
	}
	return b.String()
}

// formatScore renders a CVSS score without a trailing ".0" for whole numbers.
func formatScore(v float64) string {
	if v == float64(int64(v)) {
		return itoa(int(v))
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
