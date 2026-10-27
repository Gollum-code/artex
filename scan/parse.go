package scan

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Parse dispatches to the parser named by format. Unknown formats fall back to
// generic JSONL extraction so an operator-added tool is never a hard error.
func Parse(format, scanner, target string, out []byte) *Result {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case FormatNuclei:
		return ParseNuclei(scanner, target, out)
	case FormatHttpx:
		return ParseHttpx(scanner, target, out)
	case FormatSubfinder:
		return ParseSubfinder(scanner, target, out)
	case FormatFfuf:
		return ParseFfuf(scanner, target, out)
	case FormatKatana:
		return ParseKatana(scanner, target, out)
	case FormatNone, "":
		return &Result{Scanner: scanner, Target: target}
	default:
		return ParseGenericJSONL(scanner, target, out)
	}
}

// httpxRecord is the JSON shape httpx emits with -json (one per line).
type httpxRecord struct {
	Timestamp     string   `json:"timestamp"`
	Port          string   `json:"port"`
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	Title         string   `json:"title"`
	Scheme        string   `json:"scheme"`
	Webserver     string   `json:"webserver"`
	ContentType   string   `json:"content_type"`
	Method        string   `json:"method"`
	Host          string   `json:"host"`
	Path          string   `json:"path"`
	A             []string `json:"a"`
	Tech          []string `json:"tech"`
	Words         int      `json:"words"`
	Lines         int      `json:"lines"`
	StatusCode    int      `json:"status_code"`
	ContentLength int      `json:"content_length"`
	Failed        bool     `json:"failed"`
	Favicon       struct {
		MMH3 int64 `json:"mmh3"`
	} `json:"favicon"`
}

// ParseHttpx turns httpx -json (JSONL) output into service assets.
func ParseHttpx(scanner, target string, out []byte) *Result {
	r := &Result{Scanner: scanner, Target: target}
	if scanner == "" {
		r.Scanner = FormatHttpx
	}
	seen := map[string]bool{}

	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec httpxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			r.warn("跳过无法解析的第 " + itoa(i+1) + " 行")
			continue
		}
		r.Records++
		url := strings.TrimSpace(rec.URL)
		if url == "" {
			continue
		}
		a := Asset{
			Kind:          AssetService,
			URL:           url,
			Method:        rec.Method,
			StatusCode:    rec.StatusCode,
			ContentLength: int64(rec.ContentLength),
			PageTitle:     rec.Title,
			Technologies:  rec.Tech,
			Source:        r.Scanner,
		}
		if a.Method == "" {
			a.Method = "GET"
		}
		if p, err := strconv.Atoi(rec.Port); err == nil {
			a.Port = p
		}
		if rec.Favicon.MMH3 != 0 {
			a.FaviconMMH3 = strconv.FormatInt(rec.Favicon.MMH3, 10)
		}
		if len(rec.A) > 0 {
			a.IP = rec.A[0]
		} else if ip := strings.TrimSpace(rec.Host); ip != "" && isIP(ip) {
			a.IP = ip
		}
		r.addAsset(seen, a)
	}
	return r
}

// subfinderRecord is the JSON shape subfinder emits with -json.
type subfinderRecord struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
	IP     string `json:"ip"`
}

// ParseSubfinder turns subfinder -json output into subdomain assets. When a
// record carries an IP, the host is attached to it as a bound domain so the
// address and the name stay linked.
func ParseSubfinder(scanner, target string, out []byte) *Result {
	r := &Result{Scanner: scanner, Target: target}
	if scanner == "" {
		r.Scanner = FormatSubfinder
	}
	seen := map[string]bool{}
	ipDomains := map[string][]string{}

	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec subfinderRecord
		host := ""
		if strings.HasPrefix(line, "{") {
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				r.warn("跳过无法解析的第 " + itoa(i+1) + " 行")
				continue
			}
			host = rec.Host
		} else {
			// Plain-text fallback: some builds and pipelines print one host per line.
			host = line
		}
		r.Records++
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host == "" || strings.ContainsAny(host, " /") {
			continue
		}
		r.addAsset(seen, Asset{Kind: AssetSubdomain, Domain: host, Source: r.Scanner})
		if ip := strings.TrimSpace(rec.IP); ip != "" && isIP(ip) {
			ipDomains[ip] = append(ipDomains[ip], host)
		}
	}
	for ip, domains := range ipDomains {
		r.addAsset(seen, Asset{Kind: AssetIP, IP: ip, BoundDomain: domains[0], Source: r.Scanner})
	}
	return r
}

// ffufDoc is the document ffuf writes with -of json.
type ffufDoc struct {
	Commandline string       `json:"commandline"`
	Results     []ffufRecord `json:"results"`
}

type ffufRecord struct {
	Input       map[string]string `json:"input"`
	Position    int               `json:"position"`
	Status      int               `json:"status"`
	Length      int64             `json:"length"`
	Words       int               `json:"words"`
	Lines       int               `json:"lines"`
	ContentType string            `json:"content-type"`
	Redirect    string            `json:"redirectlocation"`
	Duration    int64             `json:"duration"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
}

// ParseFfuf turns an ffuf JSON document into endpoint assets. Content discovery
// yields paths, so each matched URL becomes an endpoint (GET) rather than a new
// service; the status code tells the agent whether it is interesting.
func ParseFfuf(scanner, target string, out []byte) *Result {
	r := &Result{Scanner: scanner, Target: target}
	if scanner == "" {
		r.Scanner = FormatFfuf
	}
	seen := map[string]bool{}

	var doc ffufDoc
	if err := json.Unmarshal(out, &doc); err == nil && len(doc.Results) > 0 {
		for _, rec := range doc.Results {
			r.Records++
			r.addAsset(seen, ffufAsset(r.Scanner, rec))
		}
		return r
	}
	// Some builds emit one result object per line.
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec ffufRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			r.warn("跳过无法解析的第 " + itoa(i+1) + " 行")
			continue
		}
		r.Records++
		r.addAsset(seen, ffufAsset(r.Scanner, rec))
	}
	return r
}

func ffufAsset(scanner string, rec ffufRecord) Asset {
	a := Asset{
		Kind:          AssetEndpoint,
		URL:           strings.TrimSpace(rec.URL),
		Method:        "GET",
		StatusCode:    rec.Status,
		ContentLength: rec.Length,
		Source:        scanner,
	}
	if ip := strings.TrimSpace(rec.Host); ip != "" && isIP(ip) {
		a.IP = ip
	}
	return a
}

// katanaRecord is the JSONL shape katana emits with -jsonl.
type katanaRecord struct {
	Timestamp string `json:"timestamp"`
	Request   struct {
		Method   string `json:"method"`
		Endpoint string `json:"endpoint"`
		Source   string `json:"source"`
		Tag      string `json:"tag"`
	} `json:"request"`
	Response struct {
		StatusCode   int      `json:"status_code"`
		Technologies []string `json:"technologies"`
	} `json:"response"`
}

// ParseKatana turns katana -jsonl output into endpoint assets.
func ParseKatana(scanner, target string, out []byte) *Result {
	r := &Result{Scanner: scanner, Target: target}
	if scanner == "" {
		r.Scanner = FormatKatana
	}
	seen := map[string]bool{}

	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec katanaRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			r.warn("跳过无法解析的第 " + itoa(i+1) + " 行")
			continue
		}
		r.Records++
		url := strings.TrimSpace(rec.Request.Endpoint)
		if url == "" {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(rec.Request.Method))
		if method == "" {
			method = "GET"
		}
		r.addAsset(seen, Asset{
			Kind:         AssetEndpoint,
			URL:          url,
			Method:       method,
			StatusCode:   rec.Response.StatusCode,
			Technologies: rec.Response.Technologies,
			Source:       r.Scanner,
		})
	}
	return r
}

// ParseGenericJSONL is the fallback for a scanner whose output is JSON objects
// with host/url fields but no dedicated parser. It harvests hosts as subdomains
// and URLs as services so an operator-added tool still contributes assets.
func ParseGenericJSONL(scanner, target string, out []byte) *Result {
	r := &Result{Scanner: scanner, Target: target}
	seen := map[string]bool{}
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			Host string `json:"host"`
			URL  string `json:"url"`
			IP   string `json:"ip"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			r.warn("跳过无法解析的第 " + itoa(i+1) + " 行")
			continue
		}
		r.Records++
		if rec.URL != "" {
			r.addAsset(seen, Asset{Kind: AssetService, URL: rec.URL, IP: rec.IP, Source: r.Scanner})
		} else if rec.Host != "" {
			r.addAsset(seen, Asset{Kind: AssetSubdomain, Domain: rec.Host, Source: r.Scanner})
		}
	}
	return r
}

func isIP(s string) bool {
	if s == "" {
		return false
	}
	// Fast shape check; asset store validates properly on write.
	hasDot := false
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c == '.':
			hasDot = true
		case c == ':':
			// IPv6
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			// IPv6 hex
		default:
			return false
		}
	}
	return hasDot || strings.Contains(s, ":")
}
