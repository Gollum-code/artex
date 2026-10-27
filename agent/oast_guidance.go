package agent

import "context"

// 本文件把「外带回连（OAST）」接到 agent 提示词与漏洞落库路径上。
//
// 为什么需要提示词段落：oast_new / oast_poll 是 host 工具，模型能看见它们的
// Description，但"什么时候该用、什么算证实"是判断层面的纪律，工具描述装不下。
// 没有这段，模型容易把「发了探针」当成「找到漏洞」，而外带回连恰恰是唯一能
// 把两者区分开的证据。

// OASTEnabled reports whether the OOB subsystem is live. Wired by the server to
// the engine; nil = off (no prompt block, no tools).
var OASTEnabled func() bool

// OASTBinder links minted payloads to a finding. Wired by the server; nil = the
// report_finding oast_refs parameter is ignored.
var OASTBinder func(ctx context.Context, findingID int64, payloadIDs []string) error

// ScannerEnabled reports whether the scanner bridge is wired (the server sets
// agent.PackageGateway). Used to gate the prompt block below.
var ScannerEnabled func() bool

func oastEnabled() bool { return OASTEnabled != nil && OASTEnabled() }

// scannerGuidance is appended alongside oastGuidance: both are host subsystems
// that only exist when the operator installed them, so neither is advertised to a
// build that lacks them. It tells the model the decision rule that the tool
// descriptions cannot carry: when a scan beats hand-rolled Bash, and what a scan
// result does and does not prove.
const scannerGuidance = `

━━ 扫描器桥接（已启用）━━
可用扫描器见 list_scanners；用 scan_run 执行，结果直接入资产库/漏洞库（不必先跑命令再手工 insert_assets/report_finding）。

什么时候用：
- 目标明确、适合模板化批量探测时（指纹、已知 CVE、目录暴破、子域名枚举），扫描器比逐条 Bash 更快也更完整。
- 需要结构化结果做后续判断时（状态码、技术栈、命中的模板 id）。

什么时候别用：
- 需要交互、需要按响应内容自适应改变攻击路径的逻辑型漏洞（越权、复杂业务逻辑）——那是你自己的事。
- 目标不在授权范围内。

纪律：
- 扫描器的漏洞只是【候选】，不是结论。看它带的 evidence 再决定复现/深入，不要直接当作已确认漏洞汇报。
- 重复扫同一目标不会产生重复漏洞（按 source + 目标 + 模板去重），返回里的 findings_dup 就是"已存在"。
- timed_out=true 表示只入库了部分结果：据此判断要不要缩小目标或调大该扫描器的 timeout_seconds。`

// oastGuidance is appended to the worker/planner system prompt only when the
// engine is live, so an install without OAST does not advertise a tool it lacks.
const oastGuidance = `

━━ 带外回连（OAST，已启用）━━
当漏洞的**结果不可见**时——盲 SSRF、盲 XXE、盲命令注入、盲 SQL 注入（库函数 egress）、盲 SSTI、JNDI/Log4Shell 探测——用 oast_new 申请一个回连探针，把返回的域名/URL 填进目标参数，再用 oast_poll 查回连。

纪律（比工具本身更重要）：
- **回连才是证据**。发了探针不算发现；只有 oast_poll 确实收到一次回连（含来源 IP、协议、时间），才能据此上报漏洞。
- **没回连 ≠ 没有漏洞**，只说明这条构造没触发。换编码、换协议、换注入点，别用"没回连"当作"已验证安全"。
- 一个探针对应一个探测意图，label 写清用途（如 "ssrf-fetch-url-order-42"），回连时才能对上号。
- 上报漏洞时把 oast_new 返回的 payload id 填进 report_finding 的 oast_refs，报告会引用这条外带证据。`
