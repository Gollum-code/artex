package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func node(t *testing.T, payload map[string]any) *db.Node {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &db.Node{Kind: db.KindFinding, Payload: raw}
}

func input(ns ...*db.Node) Input {
	return Input{
		Title: "ACME 外部渗透", Goal: "拿到边界入口",
		GeneratedAt: time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC),
		AssetCounts: map[string]int{"service": 3, "subdomain": 7},
		Findings:    ns,
	}
}

func TestMarkdownShowsCVSSAndSource(t *testing.T) {
	n := node(t, map[string]any{
		"vulnclass": "CVE-2021-44228", "name": "Log4j RCE", "severity": "critical",
		"summary": "JNDI 注入", "cvss": 10.0,
		"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		"source":      "nuclei",
		"evidence":    map[string]any{"poc": "${jndi:ldap://x}"},
	})
	md := Markdown(input(n))
	for _, want := range []string{"**CVSS**", "10（CVSS:3.1", "**来源**：nuclei", "Log4j RCE"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestHTMLIsSelfContainedAndEscaped(t *testing.T) {
	n := node(t, map[string]any{
		"vulnclass": "xss", "name": `<script>alert(1)</script>`, "severity": "high",
		"summary": "<img src=x onerror=alert(1)>", "cvss": 8.1,
		"evidence": map[string]any{"poc": "<b>raw</b>"},
	})
	page := HTML(input(n))

	if !strings.HasPrefix(page, "<!doctype html>") {
		t.Error("missing doctype")
	}
	if !strings.Contains(page, "<style>") {
		t.Error("styles should be inline (no external assets)")
	}
	if strings.Contains(page, "<script>alert(1)</script>") {
		t.Error("finding text must be HTML-escaped")
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("expected escaped script text in the output")
	}
	if !strings.Contains(page, "8.1") {
		t.Error("missing CVSS score")
	}
	if strings.Contains(page, "http://") || strings.Contains(page, "https://fonts") {
		// Only inline resources: a deliverable must open offline.
		for _, line := range strings.Split(page, "\n") {
			if strings.Contains(line, "<link") || strings.Contains(line, "<script src") {
				t.Errorf("external resource in report: %s", line)
			}
		}
	}
}

func TestHTMLEmptyFindings(t *testing.T) {
	page := HTML(input())
	if !strings.Contains(page, "本次未确认漏洞") {
		t.Error("empty report should say so")
	}
}
