package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// ScannerGateway is what the agent tools need from the host. The server implements
// it over db.ScannerProfile + scan.Runner; the indirection keeps agent free of the
// execution details (temp files, process env, arg expansion).
type ScannerGateway interface {
	// Profiles returns the scanners available to agents, with availability
	// resolved (binary present on PATH or at its configured path).
	Profiles() []ScannerProfileView
	// Run executes one profile against target and ingests the result. The owning
	// task is read from the run context (agent.RunInfo), not passed in: these are
	// host tools shared by every agent, so the ToolSet's own taskID is always 0.
	Run(ctx context.Context, profileID int64, target string, vars map[string]string) (*ScannerRunResult, error)
}

// ScannerProfileView is a profile plus whether it can actually run here.
type ScannerProfileView struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	Binary         string   `json:"binary"`
	Args           []string `json:"args"`
	Format         string   `json:"format"`
	Enabled        bool     `json:"enabled"`
	Builtin        bool     `json:"builtin"`
	Available      bool     `json:"available"`
	Missing        string   `json:"missing,omitempty"`
	Vars           []string `json:"vars,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	LastRunAt      string   `json:"last_run_at,omitempty"`
	LastError      string   `json:"last_error,omitempty"`
}

// ScannerRunResult is the summary an agent gets back after a scan.
type ScannerRunResult struct {
	ProfileName  string   `json:"profile_name"`
	Target       string   `json:"target"`
	AssetsSeen   int      `json:"assets_seen"`
	AssetsAdded  int      `json:"assets_added"`
	FindingsSeen int      `json:"findings_seen"`
	FindingsNew  int      `json:"findings_new"`
	FindingsDup  int      `json:"findings_dup"`
	DurationMS   int64    `json:"duration_ms"`
	TimedOut     bool     `json:"timed_out"`
	Error        string   `json:"error,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// SetScannerGateway wires the scanner bridge into a ToolSet. nil = tools unavailable.
func (t *ToolSet) SetScannerGateway(g ScannerGateway) { t.scanner = g }

// ProfileVars extracts the non-target variable names a profile's argument template
// needs ({{wordlist}}, {{extensions}}, ...) so the tool can tell the model which
// fields it must supply.
func ProfileVars(args []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range args {
		rest := a
		for {
			i := strings.Index(rest, "{{")
			if i < 0 {
				break
			}
			rest = rest[i+2:]
			j := strings.Index(rest, "}}")
			if j < 0 {
				break
			}
			name := strings.TrimSpace(rest[:j])
			rest = rest[j+2:]
			if name == "" || name == "target" || name == "outfile" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

const scannerListDescription = `列出可用的扫描器（nuclei/httpx/subfinder/ffuf/katana 等）及其当前可用状态。

每个扫描器返回：name、binary、format、enabled（是否已启用）、available（本机能否实际执行）、vars（除 target 外还需调用方提供的参数名）、last_run_at/last_error。

先调它确认目标扫描器 available=true，再用 scan_run 执行。available=false 时把 missing 里的原因告诉用户（需要安装该二进制或修正路径），不要反复重试同一个不可用的扫描器。`

const scannerRunDescription = `执行一个扫描器并把结果直接写进资产库与漏洞库。

target 传域名 / URL / IP（按扫描器语义：subfinder 用根域名，nuclei/httpx/katana 用 URL，ffuf 用带 FUZZ 占位的 URL）。
vars 传该扫描器额外需要的参数（如 wordlist、extensions、mc、rate），键名与 list_scanners 返回的 vars 一致；不需要的扫描器传空对象即可。

执行结果自动去重：同一扫描器在同一目标上重复命中同一漏洞只会登记一次，返回 findings_dup 表示"已存在"。
产出包括资产（subdomain/service/endpoint）与漏洞（带 severity/evidence）。扫描器发现的目标不需要再手动 insert_assets。

纪律：
- 扫描只是侦察手段，不等于漏洞确认；scanner 报的漏洞也要看 evidence 再决定后续动作。
- 大范围扫描会跑很久，超时后已产出的部分仍会入库；如果 timed_out=true，考虑缩小目标或调大该扫描器的 timeout_seconds。
- 授权范围内才扫。`

// listScanners advertises availability and the profile's argument template, so the
// model can tell "not installed" apart from "not enabled" and know which vars it
// must supply before calling scan_run.
func (t *ToolSet) listScanners() actool.CoreTool {
	return readTool(
		"list_scanners",
		scannerListDescription,
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			if t.scanner == nil {
				return actool.Errorf("扫描器桥接未启用"), nil
			}
			profiles := t.scanner.Profiles()
			out := make([]map[string]any, 0, len(profiles))
			for _, p := range profiles {
				out = append(out, map[string]any{
					"id":              p.ID,
					"name":            p.Name,
					"binary":          p.Binary,
					"args":            p.Args,
					"format":          p.Format,
					"enabled":         p.Enabled,
					"builtin":         p.Builtin,
					"available":       p.Available,
					"missing":         p.Missing,
					"vars":            p.Vars,
					"timeout_seconds": p.TimeoutSeconds,
					"last_run_at":     p.LastRunAt,
					"last_error":      p.LastError,
				})
			}
			return jsonResult(map[string]any{"count": len(out), "scanners": out})
		},
	)
}

func (t *ToolSet) scanRun() actool.CoreTool {
	return writeTool(
		"scan_run",
		scannerRunDescription,
		obj(map[string]any{
			"profile_id": idp("list_scanners 返回的扫描器 id"),
			"target":     str("扫描目标：根域名（subfinder）/ URL（nuclei、httpx、katana）/ 带占位符的 URL（ffuf）"),
			"vars": map[string]any{
				"type":        "object",
				"description": "该扫描器额外参数（键名见 list_scanners 的 vars），如 {\"wordlist\": \"/usr/share/wordlists/dir.txt\"}",
			},
		}, "profile_id", "target"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.scanner == nil {
				return actool.Errorf("扫描器桥接未启用"), nil
			}
			var a struct {
				ProfileID json.RawMessage `json:"profile_id"`
				Target    string          `json:"target"`
				Vars      json.RawMessage `json:"vars"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			vars := map[string]string{}
			if len(a.Vars) > 0 {
				if err := json.Unmarshal(a.Vars, &vars); err != nil {
					return actool.Errorf("vars 必须是对象，如 {\"wordlist\": \"...\"}"), nil
				}
			}
			profileID := pid(a.ProfileID)
			if profileID <= 0 {
				return actool.Errorf("profile_id 必须是 list_scanners 返回的 id"), nil
			}
			target := strings.TrimSpace(a.Target)
			if target == "" {
				return actool.Errorf("target 不能为空"), nil
			}
			res, err := t.scanner.Run(ctx, profileID, target, vars)
			if res == nil {
				if err != nil {
					return actool.Errorf(fmt.Sprintf("扫描执行失败：%v", err)), nil
				}
				return actool.Errorf("扫描器没有返回结果"), nil
			}
			// A timeout (or a non-zero exit after the scanner already printed
			// usable JSON) still ingests what it found. Report those counts and
			// surface the error alongside them instead of discarding the partial
			// result the agent could act on.
			if err != nil && res.AssetsAdded == 0 && res.FindingsNew == 0 {
				return actool.Errorf(fmt.Sprintf("扫描执行失败：%v", err)), nil
			}
			if err != nil && res.Error == "" {
				res.Error = err.Error()
			}
			return jsonResult(res)
		},
	)
}

// ScannerTools is the bridge's agent-facing surface. Both are read/write as
// declared: list is read-only and concurrent, run mutates the graph.
func ScannerTools(g ScannerGateway) []actool.CoreTool {
	if g == nil {
		return nil
	}
	ts := NewToolSet(nil, "")
	ts.SetScannerGateway(g)
	return []actool.CoreTool{ts.listScanners(), ts.scanRun()}
}

// ScannerSeedMetas returns metadata-only copies for seeding the tools table,
// mirroring oast.SeedToolMetas. The handlers close over a nil gateway and are
// never invoked during seeding.
func ScannerSeedMetas() []actool.CoreTool {
	ts := NewToolSet(nil, "")
	// The seed shell must produce the tools regardless of gateway availability,
	// so it calls the constructors directly instead of through ScannerTools(nil).
	return []actool.CoreTool{ts.listScanners(), ts.scanRun()}
}

// PackageGateway is the process-wide scanner bridge, set by the host at startup
// (nil = the scan tools are not advertised to any agent).
var PackageGateway ScannerGateway

// SetScannerGateway installs the process-wide bridge.
func SetScannerGateway(g ScannerGateway) { PackageGateway = g }

// formatScannerProfileRow maps a DB profile plus availability onto the tool's view.
func formatScannerProfileRow(p *db.ScannerProfile, available bool, reason string) ScannerProfileView {
	v := ScannerProfileView{
		ID:             p.ID,
		Name:           p.Name,
		Binary:         p.Binary,
		Format:         p.Format,
		Enabled:        p.Enabled,
		Available:      available,
		Vars:           ProfileVars(p.Args),
		TimeoutSeconds: p.TimeoutSeconds,
		LastError:      p.LastError,
	}
	if !available {
		v.Missing = reason
	}
	if p.LastRunAt != nil {
		v.LastRunAt = p.LastRunAt.UTC().Format(time.RFC3339)
	}
	return v
}
