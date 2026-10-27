package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/scan"
)

// =====================================================================
// 扫描器桥接（server 侧实现 agent.ScannerGateway）
// =====================================================================
//
// 分三层，各自只做一件事：
//   profiles()  读库 + 解析二进制可用性（不执行）
//   run()       执行一次扫描、把结果写进资产/漏洞库、留下审计记录
//   scannerGateway  把上面两件事暴露成 agent 侧两个工具（list_scanners / scan_run）
//
// 执行走 scan.Runner：参数模板在 Go 侧展开（不经 shell），输出有上限与超时，
// 解析是纯函数，入库复用资产库与漏洞库的既有路径。

// seedScannerProfiles writes the built-in scanners on startup (first-insert only,
// so an operator's edits to binary/args/enabled survive restarts).
func seedScannerProfiles(pg *db.DB) {
	for _, p := range scan.DefaultProfiles() {
		row := &db.ScannerProfile{
			Name:           p.Name,
			Binary:         p.Binary,
			Args:           p.Args,
			Format:         p.Format,
			TimeoutSeconds: p.TimeoutSeconds,
			Enabled:        p.Enabled,
			Builtin:        true,
		}
		if _, err := pg.SaveScannerProfile(row); err != nil {
			log.Printf("[scan] seed %s 失败: %v", p.Name, err)
		}
	}
}

// scannerGateway adapts *Server to agent.ScannerGateway. A distinct type keeps
// generic names like Run/Profiles off the Server method set.
type scannerGateway struct{ s *Server }

func (s *Server) scannerGateway() agent.ScannerGateway { return scannerGateway{s: s} }

var _ agent.ScannerGateway = scannerGateway{}

// Profiles returns the configured scanners with binary availability resolved.
func (g scannerGateway) Profiles() []agent.ScannerProfileView {
	rows, err := g.s.m.pg.ListScannerProfiles()
	if err != nil {
		log.Printf("[scan] 读取扫描器配置失败: %v", err)
		return nil
	}
	out := make([]agent.ScannerProfileView, 0, len(rows))
	for _, p := range rows {
		view := agent.ScannerProfileView{
			ID:             p.ID,
			Name:           p.Name,
			Binary:         p.Binary,
			Args:           p.Args,
			Format:         p.Format,
			Enabled:        p.Enabled,
			Builtin:        p.Builtin,
			Vars:           agent.ProfileVars(p.Args),
			TimeoutSeconds: p.TimeoutSeconds,
			LastError:      p.LastError,
		}
		if p.LastRunAt != nil {
			view.LastRunAt = p.LastRunAt.UTC().Format(time.RFC3339)
		}
		if _, rerr := scan.ResolveBinary(p.Binary); rerr != nil {
			view.Missing = rerr.Error()
		} else {
			view.Available = true
		}
		out = append(out, view)
	}
	return out
}

// Run executes one scanner, ingests its output, and records the audit row. The
// task comes from the run context because host tools are shared by every agent.
func (g scannerGateway) Run(ctx context.Context, profileID int64, target string, vars map[string]string) (*agent.ScannerRunResult, error) {
	return g.s.runScanner(ctx, profileID, target, vars, agent.RunInfoFrom(ctx).TaskID, "agent")
}

func (s *Server) runScanner(ctx context.Context, profileID int64, target string, vars map[string]string, taskID int64, triggeredBy string) (*agent.ScannerRunResult, error) {
	profile, err := s.m.pg.GetScannerProfile(profileID)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, errors.New("扫描器不存在")
	}
	if !profile.Enabled {
		return nil, errors.New("扫描器未启用，请先在设置里开启")
	}
	if _, berr := scan.ResolveBinary(profile.Binary); berr != nil {
		return nil, berr
	}

	// The owning node anchors scanner-discovered assets into the graph. Without a
	// task there is no graph, so anchoring is a no-op.
	//
	// Findings need an INTENT as the edge source (intent --yields--> finding), while
	// assets can be anchored to any node. A worker-triggered scan knows its intent
	// from the run context; a manual/heartbeat scan falls back to the task's origin
	// node, which is only usable as an edge source when it actually is an intent.
	ri := agent.RunInfoFrom(ctx)
	nodeID := int64(0)
	intentID := int64(0)
	anchor := func(_, _ int64) error { return nil }
	var ts *db.ExplorationStore
	if taskID > 0 {
		if task, terr := s.m.pg.GetTask(taskID); terr == nil && task != nil && task.ExplorationID > 0 {
			ts = s.m.pg.Exploration(task.ExplorationID)
			if ri.IntentID > 0 {
				nodeID, intentID = ri.IntentID, ri.IntentID
			} else if origin, oerr := ts.OriginFactID(); oerr == nil && origin > 0 {
				nodeID = origin
				if n, nerr := ts.GetNode(origin); nerr == nil && n != nil && n.Kind == db.KindIntent {
					intentID = origin
				}
			}
			if nodeID > 0 {
				owner := nodeID
				anchor = func(_, assetID int64) error { return ts.Anchor(owner, assetID) }
			}
		}
	}

	runID, derr := s.m.pg.StartScannerRun(ctx, profile.ID, profile.Name, target, taskID, triggeredBy)
	if derr != nil {
		log.Printf("[scan] 记录运行失败: %v", derr)
	}

	out, rerr := scan.Run(ctx, scan.RunSpec{
		Profile: scan.Profile{
			Name:           profile.Name,
			Binary:         profile.Binary,
			Args:           profile.Args,
			Format:         profile.Format,
			TimeoutSeconds: profile.TimeoutSeconds,
		},
		Target: target,
		Vars:   vars,
	})

	res := &agent.ScannerRunResult{ProfileName: profile.Name, Target: target}
	if out != nil && out.Result != nil {
		res.AssetsSeen = len(out.Result.Assets)
		res.FindingsSeen = len(out.Result.Findings)
		res.TimedOut = out.TimedOut
		res.DurationMS = out.FinishedAt.Sub(out.StartedAt).Milliseconds()
		res.Warnings = append(res.Warnings, out.Result.Warnings...)

		stats, ierr := scan.Ingest(ctx, scan.Sink{Assets: s.m.assets, DB: s.m.pg}, scan.IngestOptions{
			TaskID:      taskID,
			NodeID:      nodeID,
			IntentID:    intentID,
			Worker:      "scanner:" + profile.Name,
			TriggeredBy: triggeredBy,
			Anchor:      anchor,
			Exploration: ts,
		}, out.Result)
		switch {
		case ierr != nil:
			log.Printf("[scan] %s 入库失败: %v", profile.Name, ierr)
			res.Error = "入库失败: " + ierr.Error()
		case stats != nil:
			res.AssetsAdded = stats.AssetsAdded
			res.FindingsNew = stats.FindingsNew
			res.FindingsDup = stats.FindingsDup
			res.Warnings = append(res.Warnings, stats.Notes...)
		}
		// One fact per run: it marks the touched assets as tested (coverage counts
		// fact anchors) and leaves a replayable trail of what the scanner found.
		if stats != nil && nodeID > 0 && (stats.AssetsAdded > 0 || stats.FindingsNew > 0) {
			recordScanFact(ctx, s.m.pg, taskID, nodeID, profile.Name, target, stats, res)
		}
		if runID > 0 {
			finishScannerRun(ctx, s.m.pg, runID, out, stats, res.Error)
		}
	}
	if rerr != nil {
		res.Error = rerr.Error()
		if runID > 0 && (out == nil || out.Result == nil) {
			_ = s.m.pg.FinishScannerRun(ctx, &db.ScannerRun{
				ID: runID, ExitCode: -1, Error: rerr.Error(),
				FinishedAt: timePtr(time.Now()),
			})
		}
		_ = s.m.pg.MarkScannerProfileRun(profile.ID, time.Now(), rerr.Error())
		return res, rerr
	}
	_ = s.m.pg.MarkScannerProfileRun(profile.ID, time.Now(), res.Error)
	return res, nil
}

func finishScannerRun(ctx context.Context, pg *db.DB, runID int64, out *scan.RunOutput, stats *scan.IngestStats, runErr string) {
	if out == nil {
		return
	}
	warn := append([]string(nil), out.Result.Warnings...)
	if out.TimedOut {
		warn = append(warn, "扫描超时，仅入库已产出的部分")
	}
	_ = pg.FinishScannerRun(ctx, &db.ScannerRun{
		ID:           runID,
		Records:      out.Result.Records,
		ExitCode:     out.ExitCode,
		TimedOut:     out.TimedOut,
		AssetsSeen:   stats.AssetsSeen,
		AssetsAdded:  stats.AssetsAdded,
		FindingsSeen: stats.FindingsSeen,
		FindingsNew:  stats.FindingsNew,
		FindingsDup:  stats.FindingsDup,
		Error:        runErr,
		Warnings:     warn,
		FinishedAt:   timePtr(out.FinishedAt),
	})
}

func timePtr(t time.Time) *time.Time { return &t }

// recordScanFact writes one fact node summarizing the scan and links it to the
// owning intent. Coverage counts fact anchors, so this is what turns "we ran a
// scanner over these hosts" into "these hosts are tested".
func recordScanFact(ctx context.Context, pg *db.DB, taskID, intentID int64, scannerName, target string, stats *scan.IngestStats, res *agent.ScannerRunResult) {
	task, err := pg.GetTask(taskID)
	if err != nil || task == nil || task.ExplorationID <= 0 {
		return
	}
	ts := pg.Exploration(task.ExplorationID)
	if ts == nil {
		return
	}
	summary := fmt.Sprintf("%s 扫描 %s：资产 %d 个（本次写入 %d），漏洞 %d 条（新增 %d）",
		scannerName, target, stats.AssetsSeen, stats.AssetsAdded, stats.FindingsSeen, stats.FindingsNew)
	detail := fmt.Sprintf("目标 %s；解析记录 %d；耗时 %dms", target, stats.AssetsSeen+stats.FindingsSeen, res.DurationMS)
	if res.TimedOut {
		detail += "；已超时，仅入库部分结果"
	}
	evidence := fmt.Sprintf("%s: %s", scannerName, target)
	if res.FindingsNew > 0 {
		evidence += fmt.Sprintf("，新增漏洞 %d 条", res.FindingsNew)
	}
	factID, ferr := ts.AddNode(db.KindFact, map[string]any{
		"summary":    summary,
		"detail":     detail,
		"evidence":   evidence,
		"confidence": "observed",
	}, 5, "confirmed", "scanner", stats.AssetIDs)
	if ferr != nil {
		log.Printf("[scan] 写入扫描事实失败: %v", ferr)
		return
	}
	if intentID > 0 {
		_ = ts.Link(intentID, db.RelYields, factID)
	}
}

// --- HTTP API ---

// scannerProfilesHandler lists profiles with availability + recent runs.
func (s *Server) scannerProfilesHandler(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	var runs []*db.ScannerRun
	var err error
	if taskID := queryInt64(r, "task_id"); taskID > 0 {
		runs, err = s.m.pg.ListScannerRuns(taskID, 20)
	} else {
		runs, err = s.m.pg.ListScannerRuns(0, 50)
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"scanners": s.scannerGateway().Profiles(),
		"runs":     runs,
	})
}

// scannerRunHandler runs a profile manually.
func (s *Server) scannerRunHandler(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	var body struct {
		ProfileID int64             `json:"profile_id"`
		Target    string            `json:"target"`
		Vars      map[string]string `json:"vars"`
		TaskID    int64             `json:"task_id"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	if body.ProfileID <= 0 || strings.TrimSpace(body.Target) == "" {
		writeErr(w, 400, "profile_id 与 target 不能为空")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	res, err := s.runScanner(ctx, body.ProfileID, body.Target, body.Vars, body.TaskID, "manual")
	if err != nil && (res == nil || (res.AssetsAdded == 0 && res.FindingsNew == 0)) {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

// scannerProfileSaveHandler creates or updates a profile.
func (s *Server) scannerProfileSaveHandler(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	var p db.ScannerProfile
	if err := decode(r, &p); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	p.Name = strings.TrimSpace(p.Name)
	p.Binary = strings.TrimSpace(p.Binary)
	if p.Name == "" || p.Binary == "" {
		writeErr(w, 400, "name 与 binary 不能为空")
		return
	}
	// Only an enabled profile must be runnable: an operator has to be able to
	// disable a scanner whose binary is not installed yet.
	if p.Enabled {
		if _, err := scan.ResolveBinary(p.Binary); err != nil {
			writeErr(w, 400, err.Error()+"（如需先保存/禁用，请关闭 enabled）")
			return
		}
	}
	if p.TimeoutSeconds < 0 || p.TimeoutSeconds > 86400 {
		writeErr(w, 400, "timeout_seconds 需在 0-86400 之间")
		return
	}
	// builtin is a server-owned flag: a create is always non-builtin, and an
	// update must not be able to flip it (the UPDATE does not touch the column).
	if p.ID > 0 {
		existing, gerr := s.m.pg.GetScannerProfile(p.ID)
		if gerr != nil {
			writeErr(w, 500, gerr.Error())
			return
		}
		if existing == nil {
			writeErr(w, 404, "扫描器不存在")
			return
		}
		p.Builtin = existing.Builtin
	} else {
		p.Builtin = false
	}
	id, err := s.m.pg.SaveScannerProfile(&p)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id})
}

// scannerProfileDeleteHandler removes a non-builtin profile.
func (s *Server) scannerProfileDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "id 无效")
		return
	}
	ok, err := s.m.pg.DeleteScannerProfile(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok {
		writeErr(w, 400, "内置扫描器不可删除；可改为禁用")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// queryInt64 reads an int64 query param (0 when absent/invalid).
func queryInt64(r *http.Request, key string) int64 {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

var _ = fmt.Sprintf
