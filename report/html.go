package report

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

// HTML renders the same data as Markdown but as a single self-contained document:
// inline CSS, no external assets, printable to PDF from any browser. A pentest
// deliverable that a customer can open without a Markdown viewer is the difference
// between "a file in the repo" and "a report".
func HTML(in Input) string {
	fs := make([]findingView, 0, len(in.Findings))
	for _, n := range in.Findings {
		fs = append(fs, parseFinding(n))
	}
	sort.SliceStable(fs, func(i, j int) bool { return sevRank[fs[i].Severity] < sevRank[fs[j].Severity] })

	counts := map[string]int{}
	for _, f := range fs {
		counts[nz(f.Severity, "")]++
	}

	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	fmt.Fprintf(&b, "<title>渗透测试报告 — %s</title>\n", esc(nz(in.Title, "未命名任务")))
	b.WriteString(`<style>
:root{--fg:#1f2328;--muted:#656d76;--line:#d0d7de;--bg:#fff;--card:#f6f8fa}
*{box-sizing:border-box}
body{margin:0;padding:40px 20px;background:var(--bg);color:var(--fg);
  font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:920px;margin:0 auto}
h1{font-size:26px;margin:0 0 6px}
h2{font-size:19px;margin:34px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:22px 0 8px}
.meta{color:var(--muted);font-size:13px;margin-bottom:24px}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:104px}
.stat b{display:block;font-size:20px;line-height:1.2}
.stat span{color:var(--muted);font-size:12px}
.sev{display:inline-block;border-radius:999px;padding:1px 9px;font-size:11px;font-weight:600;
  letter-spacing:.04em;text-transform:uppercase;vertical-align:middle}
.sev-critical{background:#ffebe9;color:#a40e26}
.sev-high{background:#fff1e5;color:#bc4c00}
.sev-medium{background:#fff8c5;color:#7d4e00}
.sev-low{background:#dafbe1;color:#116329}
.sev-info{background:#eaeef2;color:#57606a}
.finding{border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:14px 0}
.finding h3{margin-top:0;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.kv{color:var(--muted);font-size:12.5px;margin:2px 0 10px}
.kv code{color:var(--fg)}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;
  overflow:auto;font:12.5px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace}
.empty{color:var(--muted);font-style:italic}
@media print{body{padding:0}.finding,.stat{break-inside:avoid}h2{break-after:avoid}}
</style></head><body><main>`)

	fmt.Fprintf(&b, "<h1>渗透测试报告 — %s</h1>\n", esc(nz(in.Title, "未命名任务")))
	fmt.Fprintf(&b, "<div class=\"meta\">任务目标：%s　·　生成时间：%s　·　确认发现：%d 个</div>\n",
		esc(nz(in.Goal, "（未指定）")), esc(in.GeneratedAt.Format("2006-01-02 15:04:05")), len(fs))

	b.WriteString("<h2>摘要</h2>\n")
	b.WriteString("<div class=\"stats\">")
	for _, s := range []struct{ key, label string }{
		{"critical", "严重"}, {"high", "高危"}, {"medium", "中危"}, {"low", "低危"},
	} {
		fmt.Fprintf(&b, "<div class=\"stat\"><b>%d</b><span>%s</span></div>", counts[s.key], s.label)
	}
	for _, t := range sortedKeys(in.AssetCounts) {
		fmt.Fprintf(&b, "<div class=\"stat\"><b>%d</b><span>%s</span></div>", in.AssetCounts[t], esc(t))
	}
	b.WriteString("</div>\n")

	b.WriteString("<h2>发现</h2>\n")
	if len(fs) == 0 {
		b.WriteString("<p class=\"empty\">本次未确认漏洞。</p>\n")
	}
	for i, f := range fs {
		sev := nz(strings.ToLower(f.Severity), "info")
		fmt.Fprintf(&b, "<section class=\"finding\"><h3>%d. %s <span class=\"sev sev-%s\">%s</span></h3>\n",
			i+1, esc(nz(f.Name, nz(f.VulnClass, "未分类"))), esc(sev), esc(strings.ToUpper(sev)))
		var kv []string
		if f.VulnClass != "" {
			kv = append(kv, "类别 <code>"+esc(f.VulnClass)+"</code>")
		}
		if f.CVSSScore > 0 {
			kv = append(kv, "CVSS <code>"+esc(formatCVSS(f.CVSSScore, f.CVSSVec))+"</code>")
		}
		if f.Source != "" {
			kv = append(kv, "来源 "+esc(f.Source))
		}
		if len(kv) > 0 {
			fmt.Fprintf(&b, "<div class=\"kv\">%s</div>\n", strings.Join(kv, "　·　"))
		}
		if s := strings.TrimSpace(f.Summary); s != "" {
			fmt.Fprintf(&b, "<p>%s</p>\n", esc(s))
		}
		if p := strings.TrimSpace(f.PoC); p != "" {
			fmt.Fprintf(&b, "<pre>%s</pre>\n", esc(p))
		}
		b.WriteString("</section>\n")
	}

	b.WriteString("</main></body></html>\n")
	return b.String()
}

func esc(s string) string { return html.EscapeString(s) }

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
