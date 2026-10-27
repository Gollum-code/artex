// Package report renders a deliverable Markdown report from the exploration
// graph: confirmed findings (with severity/evidence) (docs §15 P5).
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Input bundles what the report needs.
type Input struct {
	Title       string
	Goal        string
	GeneratedAt time.Time
	AssetCounts map[string]int
	Findings    []*db.Node
}

type findingView struct {
	VulnClass string
	Name      string
	Severity  string
	Summary   string
	PoC       string
	CVSSScore float64
	CVSSVec   string
	Source    string
}

func parseFinding(n *db.Node) findingView {
	var p struct {
		VulnClass  string  `json:"vulnclass"`
		Name       string  `json:"name"`
		Severity   string  `json:"severity"`
		Summary    string  `json:"summary"`
		CVSS       float64 `json:"cvss"`
		CVSSVector string  `json:"cvss_vector"`
		Source     string  `json:"source"`
		Evidence   struct {
			PoC string `json:"poc"`
		} `json:"evidence"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return findingView{
		VulnClass: p.VulnClass, Name: p.Name, Severity: p.Severity,
		Summary: p.Summary, PoC: p.Evidence.PoC,
		CVSSScore: p.CVSS, CVSSVec: p.CVSSVector, Source: p.Source,
	}
}

// formatCVSS renders a score without a trailing ".0" and appends the vector.
func formatCVSS(score float64, vector string) string {
	s := strconv.FormatFloat(score, 'f', 1, 64)
	if score == float64(int64(score)) {
		s = strconv.FormatInt(int64(score), 10)
	}
	if vector != "" {
		return s + "（" + vector + "）"
	}
	return s
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

// Markdown renders the report.
func Markdown(in Input) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 渗透测试报告 — %s\n\n", nz(in.Title, "未命名任务"))
	fmt.Fprintf(&b, "- **任务目标**：%s\n", nz(in.Goal, "（未指定）"))
	fmt.Fprintf(&b, "- **生成时间**：%s\n\n", in.GeneratedAt.Format("2006-01-02 15:04:05"))

	// summary
	fmt.Fprintf(&b, "## 摘要\n\n")
	fmt.Fprintf(&b, "- 确认发现：**%d** 个\n", len(in.Findings))
	fmt.Fprintf(&b, "- 资产：")
	var types []string
	for t := range in.AssetCounts {
		types = append(types, t)
	}
	sort.Strings(types)
	for i, t := range types {
		if i > 0 {
			b.WriteString("、")
		}
		fmt.Fprintf(&b, "%s %d", t, in.AssetCounts[t])
	}
	b.WriteString("\n\n")

	// findings
	fmt.Fprintf(&b, "## 发现\n\n")
	if len(in.Findings) == 0 {
		b.WriteString("_本次未确认漏洞。_\n\n")
	} else {
		fs := make([]findingView, 0, len(in.Findings))
		for _, n := range in.Findings {
			fs = append(fs, parseFinding(n))
		}
		sort.SliceStable(fs, func(i, j int) bool { return sevRank[fs[i].Severity] < sevRank[fs[j].Severity] })
		for i, f := range fs {
			fmt.Fprintf(&b, "### %d. [%s] %s\n\n", i+1, strings.ToUpper(nz(f.Severity, "info")), nz(f.Name, nz(f.VulnClass, "未分类")))
			if f.CVSSScore > 0 {
				fmt.Fprintf(&b, "- **CVSS**：%s\n", formatCVSS(f.CVSSScore, f.CVSSVec))
			}
			if f.Source != "" {
				fmt.Fprintf(&b, "- **来源**：%s\n", f.Source)
			}
			fmt.Fprintf(&b, "%s\n\n", nz(f.Summary, ""))
			if f.PoC != "" {
				fmt.Fprintf(&b, "**PoC / 证据：**\n\n```\n%s\n```\n\n", f.PoC)
			}
		}
	}

	return b.String()
}

func nz(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
