package scan

import "testing"

// Samples are trimmed real-world shapes: one JSON object per line for the JSONL
// scanners, a single document for ffuf. Keeping them literal documents the exact
// field names each vendor emits, which is what the parsers must match.

const nucleiSample = `{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","description":"JNDI lookup injection","tags":"cve,rce,log4j","reference":["https://nvd.nist.gov/x"],"classification":{"cwe-id":["CWE-502"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cvss-score":10.0}},"type":"http","host":"https://app.example.com","matched-at":"https://app.example.com/api?q=${jndi:ldap://x}","matcher-name":"jndi","extracted-results":["ldap://x"],"request":"GET /api HTTP/1.1","response":"HTTP/1.1 200 OK"}
{"template-id":"tech-detect","info":{"name":"Nginx Detection","severity":"info","description":"detected nginx","tags":"tech"},"type":"http","host":"https://app.example.com","matched-at":"https://app.example.com/"}`

func TestParseNuclei(t *testing.T) {
	r := ParseNuclei("", "app.example.com", []byte(nucleiSample))
	if r.Records != 2 {
		t.Fatalf("records = %d, want 2", r.Records)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (info template must not become a finding)", len(r.Findings))
	}
	f := r.Findings[0]
	if f.VulnClass != "CVE-2021-44228" {
		t.Errorf("vulnclass = %q", f.VulnClass)
	}
	if f.Severity != "critical" {
		t.Errorf("severity = %q", f.Severity)
	}
	if f.ExternalID != "jndi" {
		t.Errorf("external id = %q, want matcher-name", f.ExternalID)
	}
	if f.CVSSScore != 10 {
		t.Errorf("cvss = %v", f.CVSSScore)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-502" {
		t.Errorf("cwe = %v", f.CWE)
	}
	if len(f.Tags) != 3 {
		t.Errorf("tags = %v", f.Tags)
	}
	if f.Evidence == "" {
		t.Error("evidence should carry request/response/extracted")
	}
	// Both records are the same host: one service for the origin, plus one endpoint
	// for the non-root matched path.
	if len(r.Assets) != 2 {
		t.Fatalf("assets = %d, want 2: %+v", len(r.Assets), r.Assets)
	}
	var svc, ep bool
	for _, a := range r.Assets {
		switch a.Kind {
		case AssetService:
			svc = a.URL == "https://app.example.com"
		case AssetEndpoint:
			ep = a.URL == "https://app.example.com/api?q=${jndi:ldap://x}"
		}
	}
	if !svc || !ep {
		t.Errorf("asset split wrong: svc=%v ep=%v (%+v)", svc, ep, r.Assets)
	}
}

func TestParseNucleiDedupesSameFinding(t *testing.T) {
	line := `{"template-id":"t1","info":{"name":"n","severity":"high"},"host":"https://a","matched-at":"https://a/x","matcher-name":"m"}`
	r := ParseNuclei("", "a", []byte(line+"\n"+line))
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(r.Findings))
	}
}

func TestParseHttpx(t *testing.T) {
	sample := `{"url":"https://app.example.com","input":"app.example.com","status_code":200,"content_length":1234,"title":"App","tech":["Nginx","Vue"],"host":"10.0.0.5","port":"443","favicon":{"mmh3":-123456}}`
	r := ParseHttpx("", "app.example.com", []byte(sample))
	if len(r.Assets) != 1 {
		t.Fatalf("assets = %d", len(r.Assets))
	}
	a := r.Assets[0]
	if a.Kind != AssetService || a.StatusCode != 200 || a.PageTitle != "App" {
		t.Errorf("asset = %+v", a)
	}
	if a.ContentLength != 1234 || a.Port != 443 || a.IP != "10.0.0.5" {
		t.Errorf("asset details = %+v", a)
	}
	if len(a.Technologies) != 2 {
		t.Errorf("tech = %v", a.Technologies)
	}
	if a.FaviconMMH3 != "-123456" {
		t.Errorf("favicon = %q", a.FaviconMMH3)
	}
}

func TestParseHttpxSkipsGarbage(t *testing.T) {
	r := ParseHttpx("", "x", []byte("not json\n{\"url\":\"https://ok\"}\n"))
	if len(r.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(r.Assets))
	}
	if len(r.Warnings) == 0 {
		t.Error("expected a warning for the unparseable line")
	}
}

func TestParseSubfinderJSONAndPlain(t *testing.T) {
	sample := `{"host":"a.example.com","input":"example.com","source":"crtsh","ip":"1.2.3.4"}
b.example.com
`
	r := ParseSubfinder("", "example.com", []byte(sample))
	if r.Records != 2 {
		t.Fatalf("records = %d", r.Records)
	}
	if len(r.Assets) != 3 { // a.example.com, b.example.com, ip 1.2.3.4
		t.Fatalf("assets = %d, want 3: %+v", len(r.Assets), r.Assets)
	}
	var ip *Asset
	for i := range r.Assets {
		if r.Assets[i].Kind == AssetIP {
			ip = &r.Assets[i]
		}
	}
	if ip == nil || ip.IP != "1.2.3.4" || ip.BoundDomain != "a.example.com" {
		t.Errorf("ip asset = %+v", ip)
	}
}

func TestParseFfuf(t *testing.T) {
	sample := `{"commandline":"ffuf -u https://app.example.com/FUZZ -w w.txt","results":[{"input":{"FUZZ":"admin"},"status":200,"length":42,"url":"https://app.example.com/admin","host":"10.0.0.5"},{"input":{"FUZZ":"api"},"status":401,"length":10,"url":"https://app.example.com/api"}]}`
	r := ParseFfuf("", "https://app.example.com/FUZZ", []byte(sample))
	if r.Records != 2 || len(r.Assets) != 2 {
		t.Fatalf("records=%d assets=%d", r.Records, len(r.Assets))
	}
	if r.Assets[0].Kind != AssetEndpoint || r.Assets[0].Method != "GET" {
		t.Errorf("asset = %+v", r.Assets[0])
	}
	if r.Assets[0].StatusCode != 200 || r.Assets[1].StatusCode != 401 {
		t.Errorf("status codes = %d/%d", r.Assets[0].StatusCode, r.Assets[1].StatusCode)
	}
	if r.Assets[0].IP != "10.0.0.5" {
		t.Errorf("ip = %q", r.Assets[0].IP)
	}
}

func TestParseKatana(t *testing.T) {
	sample := `{"request":{"method":"POST","endpoint":"https://app.example.com/login"},"response":{"status_code":200,"technologies":["Vue"]}}`
	r := ParseKatana("", "https://app.example.com", []byte(sample))
	if len(r.Assets) != 1 {
		t.Fatalf("assets = %d", len(r.Assets))
	}
	a := r.Assets[0]
	if a.Method != "POST" || a.StatusCode != 200 || len(a.Technologies) != 1 {
		t.Errorf("asset = %+v", a)
	}
}

func TestBuildArgsExpandsPlaceholders(t *testing.T) {
	p := Profile{Args: []string{"-u", "{{target}}", "-w", "{{wordlist}}", "-o", "{{outfile}}"}}
	args, err := BuildArgs(p, "https://a/?q=1; rm -rf /", map[string]string{"wordlist": "w.txt"}, "/tmp/out.json")
	if err != nil {
		t.Fatal(err)
	}
	// The target stays one argv element: no shell, so metacharacters are inert.
	if args[1] != "https://a/?q=1; rm -rf /" {
		t.Errorf("target arg = %q", args[1])
	}
	if args[3] != "w.txt" || args[5] != "/tmp/out.json" {
		t.Errorf("args = %v", args)
	}
}

func TestBuildArgsMissingVar(t *testing.T) {
	p := Profile{Args: []string{"-w", "{{wordlist}}"}}
	if _, err := BuildArgs(p, "x", nil, ""); err == nil {
		t.Fatal("expected an error for a missing {{wordlist}}")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "critical", "high": "high", "moderate": "medium",
		"info": "low", "warning": "medium", "weird": "",
	}
	for in, want := range cases {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}
