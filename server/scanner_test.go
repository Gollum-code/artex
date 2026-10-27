package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/artex/scan"
)

// fakeScannerInterpreter finds a Python that can stand in for a real scanner: the
// bridge only cares that a binary exists and prints JSON on stdout. Candidates are
// executed once because Windows ships a `python3` alias stub that LookPath resolves
// but which exits 9009 (CommandNotFoundException) when run.
func fakeScannerInterpreter(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python", "python3"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if _, err := exec.Command(p, "-c", "print(1)").Output(); err == nil {
			return p
		}
	}
	t.Skip("no working python; scanner bridge e2e needs a binary that prints JSON")
	return ""
}

// TestScannerBridgeRunAndDedup exercises the whole path end to end: a configured
// profile runs, its JSON is parsed into assets + findings, the finding is
// fingerprinted, and a second identical run reports a duplicate instead of
// inserting a second row.
func TestScannerBridgeRunAndDedup(t *testing.T) {
	interp := fakeScannerInterpreter(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	domain := fmt.Sprintf("e2e-scan-%d.example.com", time.Now().UnixNano())
	payload := fmt.Sprintf(
		`{"template-id":"e2e-vuln","info":{"name":"E2E Finding","severity":"high","description":"bridge test"},"type":"http","host":"https://%s","matched-at":"https://%s/x","matcher-name":"m1"}`,
		domain, domain)
	script := "print(" + strconvQuote(payload) + ")"

	p := &db.ScannerProfile{
		Name:           "e2e-fake-" + domain,
		Binary:         interp,
		Args:           []string{"-c", script},
		Format:         scan.FormatNuclei,
		TimeoutSeconds: 30,
		Enabled:        true,
	}
	id, err := m.pg.SaveScannerProfile(p)
	if err != nil {
		t.Fatalf("save profile: %v", err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM scanner_runs WHERE profile_id=$1`, id)
		_, _ = m.pg.Exec(`DELETE FROM scanner_profiles WHERE id=$1`, id)
		_, _ = m.pg.Exec(`DELETE FROM findings WHERE source=$1`, p.Name)
		_, _ = m.pg.Exec(`DELETE FROM assets WHERE domain=$1 OR url LIKE $2`, domain, "%"+domain+"%")
	})

	s := &Server{m: m}
	ctx := context.Background()

	first, err := s.runScanner(ctx, id, domain, nil, 0, "test")
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if first.AssetsAdded != 2 { // origin service + /x endpoint
		t.Errorf("assets added = %d, want 2 (%+v)", first.AssetsAdded, first)
	}
	if first.FindingsNew != 1 || first.FindingsDup != 0 {
		t.Errorf("findings new/dup = %d/%d, want 1/0; warnings=%v err=%q", first.FindingsNew, first.FindingsDup, first.Warnings, first.Error)
	}

	second, err := s.runScanner(ctx, id, domain, nil, 0, "test")
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second.FindingsNew != 0 || second.FindingsDup != 1 {
		t.Errorf("rescan findings new/dup = %d/%d, want 0/1", second.FindingsNew, second.FindingsDup)
	}

	// Each run writes its own audit row; check BOTH rows (newest first).
	runs, err := m.pg.ListScannerRuns(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var seenRuns int
	for _, r := range runs {
		if r.ProfileID != nil && *r.ProfileID == id {
			seenRuns++
			switch seenRuns {
			case 1: // newest = the rescan
				if r.FindingsNew != 0 || r.FindingsDup != 1 {
					t.Errorf("rescan findings new/dup = %d/%d, want 0/1", r.FindingsNew, r.FindingsDup)
				}
			case 2: // the first run
				if r.FindingsNew != 1 || r.FindingsDup != 0 {
					t.Errorf("first run findings new/dup = %d/%d, want 1/0", r.FindingsNew, r.FindingsDup)
				}
			}
		}
	}
	if seenRuns != 2 {
		t.Errorf("scanner_runs has %d rows for the test profile, want 2", seenRuns)
	}
}

// TestScannerFindingEntersTaskGraph is the regression test for the gap where a
// scan inside a task wrote only the findings table: the planner, coverage view and
// task report all read exploration nodes, so a scan finding was invisible.
func TestScannerFindingEntersTaskGraph(t *testing.T) {
	interp := fakeScannerInterpreter(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	task, err := m.CreateTaskWithOptions("scan graph", "find one issue", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	domain := fmt.Sprintf("e2e-graph-%d.example.com", time.Now().UnixNano())
	payload := fmt.Sprintf(
		`{"template-id":"e2e-graph-vuln","info":{"name":"Graph Finding","severity":"critical","description":"reaches the graph","classification":{"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cvss-score":9.8}},"type":"http","host":"https://%s","matched-at":"https://%s/p","matcher-name":"m1"}`,
		domain, domain)
	p := &db.ScannerProfile{
		Name:           "e2e-graph-" + domain,
		Binary:         interp,
		Args:           []string{"-c", "print(" + strconvQuote(payload) + ")"},
		Format:         scan.FormatNuclei,
		TimeoutSeconds: 30,
		Enabled:        true,
	}
	id, err := m.pg.SaveScannerProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM scanner_runs WHERE profile_id=$1`, id)
		_, _ = m.pg.Exec(`DELETE FROM scanner_profiles WHERE id=$1`, id)
	})

	s := &Server{m: m}
	res, err := s.runScanner(context.Background(), id, domain, nil, taskID, "test")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.FindingsNew != 1 {
		t.Fatalf("findings_new = %d (warnings=%v)", res.FindingsNew, res.Warnings)
	}

	// 1. The finding exists as an exploration node (what the report reads).
	nodes, err := task.Store.ListByKind(db.KindFinding, 50)
	if err != nil {
		t.Fatal(err)
	}
	var node *db.Node
	for _, n := range nodes {
		if strings.Contains(string(n.Payload), "e2e-graph-vuln") {
			node = n
		}
	}
	if node == nil {
		t.Fatalf("scan finding did not become an exploration node; nodes=%d", len(nodes))
	}

	// 2. The node payload carries CVSS so the report can show it.
	var pl struct {
		CVSS       float64 `json:"cvss"`
		CVSSVector string  `json:"cvss_vector"`
		Source     string  `json:"source"`
	}
	if err := json.Unmarshal(node.Payload, &pl); err != nil {
		t.Fatal(err)
	}
	if pl.CVSS != 9.8 || pl.CVSSVector == "" || pl.Source == "" {
		t.Errorf("node payload missing cvss/source: %+v", pl)
	}

	// 3. The findings row persists the same score.
	var score float64
	var vector string
	if err := m.pg.QueryRow(`SELECT cvss_score, cvss_vector FROM findings WHERE node_id=$1`, node.ID).
		Scan(&score, &vector); err != nil {
		t.Fatal(err)
	}
	if score != 9.8 || vector == "" {
		t.Errorf("findings row cvss = %v/%q", score, vector)
	}

	// 4. The rendered report includes it.
	md := report.Markdown(report.Input{
		Title: task.Description, Goal: task.Goal, GeneratedAt: time.Now(),
		AssetCounts: map[string]int{"service": 1}, Findings: nodes,
	})
	if !strings.Contains(md, "9.8") {
		t.Error("report does not show the CVSS score")
	}
	page := report.HTML(report.Input{
		Title: task.Description, Goal: task.Goal, GeneratedAt: time.Now(),
		AssetCounts: map[string]int{"service": 1}, Findings: nodes,
	})
	if !strings.Contains(page, "9.8") || !strings.Contains(page, "<!doctype html>") {
		t.Error("HTML report missing the score or the document shell")
	}

	// 5. A rescan is a duplicate, not a second node.
	again, err := s.runScanner(context.Background(), id, domain, nil, taskID, "test")
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if again.FindingsNew != 0 || again.FindingsDup != 1 {
		t.Errorf("rescan new/dup = %d/%d, want 0/1", again.FindingsNew, again.FindingsDup)
	}
	after, _ := task.Store.ListByKind(db.KindFinding, 50)
	if len(after) != len(nodes) {
		t.Errorf("rescan added a finding node: %d -> %d", len(nodes), len(after))
	}
}

// TestScannerProfilesSeedAndView checks the builtin profiles are seeded and that
// the agent-facing view reports availability + the extra vars a profile needs.
func TestScannerProfilesSeedAndView(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	seedScannerProfiles(m.pg)

	rows, err := m.pg.ListScannerProfiles()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*db.ScannerProfile{}
	for _, p := range rows {
		byName[p.Name] = p
	}
	for _, want := range []string{"nuclei", "httpx", "subfinder", "katana", "ffuf"} {
		if byName[want] == nil || !byName[want].Builtin {
			t.Errorf("builtin profile %q missing", want)
		}
	}
	if byName["ffuf"] != nil {
		vars := formatVarsForTest(byName["ffuf"].Args)
		if !containsStr(vars, "wordlist") {
			t.Errorf("ffuf vars = %v, want wordlist", vars)
		}
	}

	s := &Server{m: m}
	var nucleus *agentScannerView
	for _, v := range s.scannerGateway().Profiles() {
		if v.Name == "nuclei" {
			copied := v
			nucleus = &agentScannerView{available: copied.Available, missing: copied.Missing}
		}
	}
	if nucleus == nil {
		t.Fatal("nuclei missing from the agent-facing view")
	}
}

type agentScannerView struct {
	available bool
	missing   string
}

func formatVarsForTest(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.Contains(a, "{{wordlist}}") {
			out = append(out, "wordlist")
		}
	}
	return out
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// strconvQuote renders s as a Python string literal (single-quoted), escaping the
// characters Python treats specially inside one.
func strconvQuote(s string) string {
	b, _ := json.Marshal(s) // JSON string escaping is a superset of Python's
	return string(b)
}
