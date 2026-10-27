package oast

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// ToolDescriptions is the shared copy for the OAST tools. Kept in one place so
// the tools table's seeded description and the tool itself cannot drift.
const (
	NewToolDescription = `申请一个 OAST 外带回连探针（盲打漏洞的"回连眼"）。返回唯一的 subdomain 和 URL；把它填进目标参数里（URL/域名/回调地址/文件名/邮箱域等），然后用 oast_poll 查是否有回连。

**适用**：盲 SSRF、盲 XXE、盲命令注入、盲 SQL 注入（库函数 egress）、盲 SSTI、Log4Shell 类 JNDI 探测，以及任何"目标可能向外发请求但回显不可见"的场景。

**用法纪律**：
- 一个探针对应一个探测意图，label 写清用途（如 "ssrf-order-id-42"），便于回连后归因。
- 拿到探针后把 payload 植入目标，等几秒再 poll；DNS 回连通常比 HTTP 快。
- 只有【确实收到回连】才算证实；没收到不代表漏洞不存在，只代表这条路径没触发。
- 上报漏洞时把 payload id 填进 report_finding 的 oast_refs，作为证据链。`
	PollToolDescription = `轮询本任务已申请的 OAST 探针是否收到回连。传 payload_id 只查某一个；不传则查本任务全部未过期的探针。since 传 ISO8601 时间则只返回该时刻之后的新回连（配合首次调用记录的时间戳，避免重复拿旧数据）。

回连记录含协议(dns/http/https)、类型(A/TXT/HTTP)、来源 IP、时间；有完整请求原文时也一并返回。空结果就是还没回连。`
	ListToolDescription = `列出本任务已申请的 OAST 探针及其回连计数（未过期的），用于回顾已布探针、确认哪些已被触发、避免重复申请。`
)

// RunContext identifies the run a tool call belongs to. The agent package fills
// it from its own RunInfo; this indirection exists so oast does not import
// agent (agent imports oast for these tools).
type RunContext struct {
	TaskID        int64
	ExplorationID int64
	IntentID      int64
	Worker        string
}

// RunInfoResolver, when set, reads the current run's identity from a tool
// context. Wired by the agent package at init.
var RunInfoResolver func(ctx context.Context) RunContext

func runContext(ctx context.Context) RunContext {
	if RunInfoResolver == nil {
		return RunContext{}
	}
	return RunInfoResolver(ctx)
}

// Tools exposes OAST to an agent. It is bound into worker/planner/mainagent like
// any other host tool; the engine decides whether it actually runs.
func Tools(e *Engine) []actool.CoreTool {
	if e == nil {
		return nil
	}
	return []actool.CoreTool{newTool(e), pollTool(e), listTool(e)}
}

// SeedToolMetas returns metadata-only copies for seeding the tools catalog,
// mirroring traffic.SeedToolMetas. The handlers close over a nil engine and are
// never invoked during seeding.
func SeedToolMetas() []actool.CoreTool { return Tools(nil) }

func newTool(e *Engine) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "oast_new", Description: NewToolDescription,
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"label": map[string]any{"type": "string", "description": "用途标签，如 'ssrf-order-id-42' / 'xxe-file-upload'，便于回连后归因"},
			},
		},
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if e == nil {
				return actool.Errorf("OAST 引擎未初始化"), nil
			}
			var a struct {
				Label string `json:"label"`
			}
			_ = json.Unmarshal(in, &a)

			rc := runContext(ctx)
			p, err := e.Mint(ctx, MintRequest{
				TaskID:        rc.TaskID,
				ExplorationID: rc.ExplorationID,
				IntentID:      rc.IntentID,
				Worker:        rc.Worker,
				Label:         strings.TrimSpace(a.Label),
			})
			if err != nil {
				return actool.Errorf("申请 OAST 探针失败：" + err.Error()), nil
			}
			return actool.Text(renderMinted(p)), nil
		},
	})
}

func pollTool(e *Engine) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "oast_poll", Description: PollToolDescription,
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"payload_id": map[string]any{"type": "string", "description": "只查这一个探针（oast_new 返回的 id）；省略则查本任务全部探针"},
				"since":      map[string]any{"type": "string", "description": "ISO8601 时间戳，只返回该时刻之后的新回连（可选）"},
				"limit":      map[string]any{"type": "integer", "description": "返回条数上限，默认 50，最大 200"},
			},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if e == nil {
				return actool.Errorf("OAST 引擎未初始化"), nil
			}
			var a struct {
				PayloadID string `json:"payload_id"`
				Since     string `json:"since"`
				Limit     int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			var since time.Time
			if s := strings.TrimSpace(a.Since); s != "" {
				t, err := time.Parse(time.RFC3339Nano, s)
				if err != nil {
					return actool.Errorf("since 需为 ISO8601 时间，如 2026-01-02T15:04:05Z07:00"), nil
				}
				since = t
			}

			rc := runContext(ctx)
			if rc.TaskID == 0 {
				return actool.Errorf("oast_poll 需要任务上下文"), nil
			}
			items, err := e.Poll(ctx, rc.TaskID, strings.TrimSpace(a.PayloadID), since, a.Limit)
			if err != nil {
				return actool.Errorf("轮询失败：" + err.Error()), nil
			}
			if len(items) == 0 {
				return actool.Text("无回连（尚未收到任何 OOB 交互）。"), nil
			}
			// Payload labels ride along so the agent can name what triggered.
			labels := map[string]string{}
			if ps, err := e.List(ctx, rc.TaskID, 500); err == nil {
				for _, p := range ps {
					labels[p.ID] = p.Label
				}
			}
			type row struct {
				PayloadID string `json:"payload_id"`
				Label     string `json:"label,omitempty"`
				Protocol  string `json:"protocol"`
				Kind      string `json:"kind"`
				FullHost  string `json:"full_host"`
				Method    string `json:"method,omitempty"`
				Path      string `json:"path,omitempty"`
				URL       string `json:"url,omitempty"`
				Remote    string `json:"remote_addr"`
				UserAgent string `json:"user_agent,omitempty"`
				At        string `json:"at"`
				Raw       string `json:"raw_request,omitempty"`
				Body      string `json:"body,omitempty"`
			}
			out := make([]row, 0, len(items))
			for _, it := range items {
				out = append(out, row{
					PayloadID: it.PayloadID, Label: labels[it.PayloadID], Protocol: it.Protocol,
					Kind: it.Kind, FullHost: it.FullHost, Method: it.Method, Path: it.Path,
					URL: it.URL, Remote: it.RemoteAddr, UserAgent: it.UserAgent,
					At:  it.Timestamp.UTC().Format(time.RFC3339Nano),
					Raw: clip(it.RawRequest, 4000), Body: clip(it.Body, 4000),
				})
			}
			b, _ := json.Marshal(map[string]any{"count": len(out), "interactions": out})
			return actool.Text(string(b)), nil
		},
	})
}

func listTool(e *Engine) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "oast_list", Description: ListToolDescription,
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"limit": map[string]any{"type": "integer", "description": "返回条数上限，默认 100"}},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if e == nil {
				return actool.Errorf("OAST 引擎未初始化"), nil
			}
			var a struct {
				Limit int `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			rc := runContext(ctx)
			if rc.TaskID == 0 {
				return actool.Errorf("oast_list 需要任务上下文"), nil
			}
			items, err := e.List(ctx, rc.TaskID, a.Limit)
			if err != nil {
				return actool.Errorf("列出探针失败：" + err.Error()), nil
			}
			if len(items) == 0 {
				return actool.Text("本任务尚未申请任何 OAST 探针。"), nil
			}
			type row struct {
				ID        string `json:"id"`
				Label     string `json:"label,omitempty"`
				URL       string `json:"url"`
				Subdomain string `json:"subdomain,omitempty"`
				Hits      int    `json:"hits"`
				ExpiresAt string `json:"expires_at"`
			}
			out := make([]row, 0, len(items))
			for _, p := range items {
				out = append(out, row{
					ID: p.ID, Label: p.Label, URL: p.URL, Subdomain: p.Subdomain,
					Hits: p.Hits(), ExpiresAt: p.ExpiresAt.UTC().Format(time.RFC3339Nano),
				})
			}
			b, _ := json.Marshal(map[string]any{"count": len(out), "payloads": out})
			return actool.Text(string(b)), nil
		},
	})
}

// renderMinted formats the mint result: the two addresses to plant, plus the id
// the agent must cite later. It states the DNS surface explicitly because a
// payload with only a domain is the one that works for non-HTTP egress.
func renderMinted(p *Payload) string {
	var b strings.Builder
	fmt.Fprintf(&b, "已申请 OAST 探针：%s\n", p.ID)
	if p.Label != "" {
		fmt.Fprintf(&b, "用途：%s\n", p.Label)
	}
	if p.Subdomain != "" {
		fmt.Fprintf(&b, "DNS 探针（填进域名/URL/回调地址参数）：%s\n", p.Subdomain)
	}
	if p.URL != "" {
		fmt.Fprintf(&b, "HTTP 探针（填进 URL/回调地址参数）：%s\n", p.URL)
	}
	fmt.Fprintf(&b, "有效期至：%s\n", p.ExpiresAt.UTC().Format(time.RFC3339))
	b.WriteString("\n把上面地址植入目标参数，等待数秒后用 oast_poll 查询回连；")
	b.WriteString("上报漏洞时把探针 id 填进 report_finding 的 oast_refs。")
	return b.String()
}

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n...[截断，共 %d 字节]", len(s))
}
