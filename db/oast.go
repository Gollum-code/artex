package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Autumn-27/artex/oast"
)

// =====================================================================
// OAST 外带回连持久化（schema.sql §N）
// =====================================================================
//
// 三张表的分工与约束：
//
//   oast_payloads          探针申请。主键用字符串（oast_<correlation>_<seq>），
//                          因为回连处理器只有 correlation_id 可用，直接拼主键
//                          比再建一张映射表省一次查询。
//   oast_interactions      回连证据。主键由证据字段哈希派生（引擎侧生成），
//                          所以 DNS 重试、连接重放不会产生两行。
//   finding_oast_payloads  漏洞 ↔ 探针绑定。
//
// 任务删除会级联删掉它的探针与回连（payloads.task_id 引用 tasks），
// 与任务整体"不留孤儿数据"的语义一致；漏洞删除则级联掉绑定行，但探针本身
// 可能仍被其他漏洞引用，故不做双向级联。

// OastPayload 是持久化的探针申请。字段与 oast.Payload 一一对应；包边界上
// 转成 struct 而不是直接存 oast.Payload，是为了让 db 包不依赖 oast 的类型
// 定义（engine 那边才是权威）。
type OastPayload struct {
	ID               string    `json:"id"`
	CorrelationID    string    `json:"correlation_id"`
	BaseDomain       string    `json:"base_domain"`
	Subdomain        string    `json:"subdomain"`
	URL              string    `json:"url"`
	Label            string    `json:"label"`
	TaskID           int64     `json:"task_id"`
	ExplorationID    int64     `json:"exploration_id"`
	IntentID         int64     `json:"intent_id"`
	Worker           string    `json:"worker"`
	InteractionCount int       `json:"interaction_count"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (p *OastPayload) expired(now time.Time) bool { return !now.Before(p.ExpiresAt) }

// OastInteraction 是持久化的回连证据。
type OastInteraction struct {
	ID           string    `json:"id"`
	PayloadID    string    `json:"payload_id"`
	Correlation  string    `json:"correlation_id"`
	Protocol     string    `json:"protocol"`
	Kind         string    `json:"kind"`
	FullHost     string    `json:"full_host"`
	QueryName    string    `json:"query_name"`
	QueryType    string    `json:"query_type"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	URL          string    `json:"url"`
	UserAgent    string    `json:"user_agent"`
	RemoteAddr   string    `json:"remote_addr"`
	RawRequest   string    `json:"raw_request"`
	RawResponse  string    `json:"raw_response"`
	Body         string    `json:"body"`
	InteractedAt time.Time `json:"interacted_at"`
}

const oastPayloadCols = `id, correlation_id, base_domain, subdomain, url, label, task_id, exploration_id, intent_id, worker, interaction_count, created_at, expires_at`

const oastInteractionCols = `id, payload_id, correlation_id, protocol, kind, full_host, query_name, query_type, method, path, url, user_agent, remote_addr, raw_request, raw_response, body, interacted_at`

// OastStore 实现 oast.Store。它在 DB 上构造，由 Manager 在 OAST 开启时创建。
type OastStore struct{ db *DB }

// OAST 返回外带回连存储。
func (d *DB) OAST() *OastStore { return &OastStore{db: d} }

// --- payloads ---

// InsertOastPayload 写入一个探针申请。幂等键是 correlation_id 的唯一索引：
// 引擎 mint 成功后立刻写入，重启后重新注册同一 session 的场景不会重复建行。
func (s *OastStore) InsertOastPayload(ctx context.Context, p *OastPayload) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO oast_payloads
 (id, correlation_id, base_domain, subdomain, url, label, task_id, exploration_id, intent_id, worker, interaction_count, created_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (id) DO NOTHING`,
		p.ID, p.CorrelationID, p.BaseDomain, p.Subdomain, p.URL, p.Label,
		nullZero(p.TaskID), nullZero(p.ExplorationID), nullZero(p.IntentID), p.Worker, p.InteractionCount, p.CreatedAt, p.ExpiresAt)
	return err
}

func scanOastPayload(row interface{ Scan(...any) error }) (*OastPayload, error) {
	var p OastPayload
	var taskID, expID, intentID sql.NullInt64
	err := row.Scan(&p.ID, &p.CorrelationID, &p.BaseDomain, &p.Subdomain, &p.URL, &p.Label,
		&taskID, &expID, &intentID, &p.Worker, &p.InteractionCount, &p.CreatedAt, &p.ExpiresAt)
	if err != nil {
		return nil, err
	}
	p.TaskID, p.ExplorationID, p.IntentID = taskID.Int64, expID.Int64, intentID.Int64
	return &p, nil
}

// GetOastPayload 按主键取探针。
func (s *OastStore) GetOastPayload(ctx context.Context, id string) (*OastPayload, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+oastPayloadCols+` FROM oast_payloads WHERE id=$1`, id)
	p, err := scanOastPayload(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

// GetOastPayloadByCorrelation 是回连处理器的查找路径：只有 hostname 里的
// correlation id 可用，必须能 O(唯一索引) 定位到探针。找不到返回 nil,nil
// （未知 token = 背景噪声，不建证据）。
func (s *OastStore) GetOastPayloadByCorrelation(ctx context.Context, correlationID string) (*OastPayload, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+oastPayloadCols+` FROM oast_payloads WHERE correlation_id=$1`, correlationID)
	p, err := scanOastPayload(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

// ListOastPayloads 列出探针。taskID>0 限定任务；<=0 表示全部（管理端视图）。
func (s *OastStore) ListOastPayloads(ctx context.Context, taskID int64, limit int) ([]*OastPayload, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var (
		rows *sql.Rows
		err  error
	)
	if taskID > 0 {
		rows, err = s.db.QueryContext(ctx, `SELECT `+oastPayloadCols+` FROM oast_payloads WHERE task_id=$1 ORDER BY created_at DESC LIMIT $2`, taskID, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT `+oastPayloadCols+` FROM oast_payloads ORDER BY created_at DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*OastPayload, 0, limit)
	for rows.Next() {
		p, err := scanOastPayload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// --- interactions ---

// InsertOastInteraction 写入一条回连。幂等键是主键（证据哈希），重复投递
// 只会 DO NOTHING。命中计数在同一个事务里 +1，避免"有回连但计数还是 0"。
func (s *OastStore) InsertOastInteraction(ctx context.Context, in *OastInteraction) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
INSERT INTO oast_interactions
 (id, payload_id, correlation_id, protocol, kind, full_host, query_name, query_type, method, path, url, user_agent, remote_addr, raw_request, raw_response, body, interacted_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
ON CONFLICT (id) DO NOTHING`,
		in.ID, in.PayloadID, in.Correlation, in.Protocol, in.Kind, in.FullHost, in.QueryName,
		in.QueryType, in.Method, in.Path, in.URL, in.UserAgent, in.RemoteAddr,
		in.RawRequest, in.RawResponse, in.Body, in.InteractedAt)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE oast_payloads SET interaction_count = interaction_count + 1 WHERE id=$1`, in.PayloadID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func scanOastInteraction(row interface{ Scan(...any) error }) (*OastInteraction, error) {
	var in OastInteraction
	err := row.Scan(&in.ID, &in.PayloadID, &in.Correlation, &in.Protocol, &in.Kind, &in.FullHost,
		&in.QueryName, &in.QueryType, &in.Method, &in.Path, &in.URL, &in.UserAgent, &in.RemoteAddr,
		&in.RawRequest, &in.RawResponse, &in.Body, &in.InteractedAt)
	if err != nil {
		return nil, err
	}
	return &in, nil
}

// ListOastInteractions 列出回连。since 为零值表示不限时间；payloadID 为空表示
// 该任务的全部探针。按时间倒序（最新在前），与 agent 的"先看最新"习惯一致。
func (s *OastStore) ListOastInteractions(ctx context.Context, taskID int64, payloadID string, since time.Time, limit int) ([]*OastInteraction, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT ` + oastInteractionCols + ` FROM oast_interactions WHERE 1=1`
	args := []any{}
	idx := 1
	add := func(cond string, v any) {
		q += " AND " + cond
		args = append(args, v)
	}
	if payloadID != "" {
		add("payload_id=$"+itoa(int64(idx)), payloadID)
		idx++
	}
	if taskID > 0 {
		add("payload_id IN (SELECT id FROM oast_payloads WHERE task_id=$"+itoa(int64(idx))+")", taskID)
		idx++
	}
	if !since.IsZero() {
		add("interacted_at > $"+itoa(int64(idx)), since)
		idx++
	}
	q += " ORDER BY interacted_at DESC LIMIT $" + itoa(int64(idx))
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*OastInteraction, 0, limit)
	for rows.Next() {
		in, err := scanOastInteraction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// --- 清理 ---

// DeleteExpiredOast 删除过期探针及其回连，返回各自的条数。回连依赖
// payloads 的 ON DELETE CASCADE，所以先删 payloads 即可连带删掉回连。
func (s *OastStore) DeleteExpiredOast(ctx context.Context, now time.Time) (payloads, interactions int64, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM oast_interactions WHERE payload_id IN (SELECT id FROM oast_payloads WHERE expires_at <= $1)`, now).Scan(&interactions); err != nil {
		return 0, 0, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM oast_payloads WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, 0, err
	}
	if payloads, err = res.RowsAffected(); err != nil {
		return 0, 0, err
	}
	return payloads, interactions, tx.Commit()
}

// --- 漏洞绑定 ---

// BindFindingOastPayloads 把探针绑定到漏洞。幂等（主键冲突忽略），重复上报
// 同一探针不会产生重复行。
func (s *OastStore) BindFindingOastPayloads(ctx context.Context, findingID int64, payloadIDs []string) error {
	if findingID <= 0 || len(payloadIDs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, pid := range payloadIDs {
		if pid == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO finding_oast_payloads (finding_id, payload_id) VALUES ($1,$2)
ON CONFLICT DO NOTHING`, findingID, pid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListFindingOastPayloads 列出绑定到某漏洞的探针，供报告与漏洞详情页引用。
func (s *OastStore) ListFindingOastPayloads(ctx context.Context, findingID int64) ([]*OastPayload, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT `+oastPayloadCols+` FROM oast_payloads p
JOIN finding_oast_payloads b ON b.payload_id = p.id
WHERE b.finding_id=$1 ORDER BY p.created_at DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*OastPayload, 0, 8)
	for rows.Next() {
		p, err := scanOastPayload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// OastStats 是管理端概览的一行汇总。
type OastStats struct {
	Payloads     int64 `json:"payloads"`
	Interactions int64 `json:"interactions"`
	Bound        int64 `json:"bound"`
}

// OastStats 汇总探针/回连/绑定数量。
func (s *OastStore) OastStats(ctx context.Context) (OastStats, error) {
	var st OastStats
	err := s.db.QueryRowContext(ctx, `
SELECT
 (SELECT count(*) FROM oast_payloads),
 (SELECT count(*) FROM oast_interactions),
 (SELECT count(*) FROM finding_oast_payloads)`).Scan(&st.Payloads, &st.Interactions, &st.Bound)
	return st, err
}

// nullZero maps 0 to SQL NULL for nullable FK columns (task_id / intent_id).
func nullZero(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

// 下面是 db.OastStore 对 oast.Store 接口的实现。值类型转换集中在这几个方法里，
// 让 engine 完全不认识 DB 的行类型。
var _ = json.Marshal

// =====================================================================
// oast.Store 适配层
// =====================================================================
// engine 使用 oast.Payload / oast.Interaction，本包的行类型是 OastPayload /
// OastInteraction。两套类型字段完全一致，转换放在这里而不是让 engine 认识
// DB 行类型，保持引擎可脱离数据库单测。

// OASTStoreAdapter 把 *OastStore 适配成 oast.Store。配置文件名的原因是
// db 包不能反向 import server，而 oast.Store 是引擎定义的小接口。
type OASTStoreAdapter struct{ s *OastStore }

// OastAdapter 返回适配器。调用方可把它直接传给 oast.New。
func (s *OastStore) OastAdapter() *OASTStoreAdapter { return &OASTStoreAdapter{s: s} }

func toOastPayload(p *OastPayload) *oast.Payload {
	if p == nil {
		return nil
	}
	return &oast.Payload{
		ID: p.ID, CorrelationID: p.CorrelationID, BaseDomain: p.BaseDomain,
		Subdomain: p.Subdomain, URL: p.URL, Label: p.Label, TaskID: p.TaskID,
		ExplorationID: p.ExplorationID, IntentID: p.IntentID, Worker: p.Worker,
		CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt,
		InteractionCount: p.InteractionCount,
	}
}

func fromOastPayload(p *oast.Payload) *OastPayload {
	if p == nil {
		return nil
	}
	return &OastPayload{
		ID: p.ID, CorrelationID: p.CorrelationID, BaseDomain: p.BaseDomain,
		Subdomain: p.Subdomain, URL: p.URL, Label: p.Label, TaskID: p.TaskID,
		ExplorationID: p.ExplorationID, IntentID: p.IntentID, Worker: p.Worker,
		CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt,
		InteractionCount: p.InteractionCount,
	}
}

func fromOastInteraction(in *oast.Interaction) *OastInteraction {
	if in == nil {
		return nil
	}
	return &OastInteraction{
		ID: in.ID, PayloadID: in.PayloadID, Correlation: in.Correlation,
		Protocol: in.Protocol, Kind: in.Kind, FullHost: in.FullHost,
		QueryName: in.QueryName, QueryType: in.QueryType, Method: in.Method,
		Path: in.Path, URL: in.URL, UserAgent: in.UserAgent,
		RemoteAddr: in.RemoteAddr, RawRequest: in.RawRequest,
		RawResponse: in.RawResponse, Body: in.Body, InteractedAt: in.Timestamp,
	}
}

func toOastInteraction(in *OastInteraction) *oast.Interaction {
	if in == nil {
		return nil
	}
	return &oast.Interaction{
		ID: in.ID, PayloadID: in.PayloadID, Correlation: in.Correlation,
		Protocol: in.Protocol, Kind: in.Kind, FullHost: in.FullHost,
		QueryName: in.QueryName, QueryType: in.QueryType, Method: in.Method,
		Path: in.Path, URL: in.URL, UserAgent: in.UserAgent,
		RemoteAddr: in.RemoteAddr, RawRequest: in.RawRequest,
		RawResponse: in.RawResponse, Body: in.Body, Timestamp: in.InteractedAt,
	}
}

// --- oast.Store 实现 ---

func (a *OASTStoreAdapter) InsertPayload(ctx context.Context, p *oast.Payload) error {
	return a.s.InsertOastPayload(ctx, fromOastPayload(p))
}

func (a *OASTStoreAdapter) GetPayload(ctx context.Context, id string) (*oast.Payload, error) {
	p, err := a.s.GetOastPayload(ctx, id)
	return toOastPayload(p), err
}

func (a *OASTStoreAdapter) GetPayloadByCorrelation(ctx context.Context, correlationID string) (*oast.Payload, error) {
	p, err := a.s.GetOastPayloadByCorrelation(ctx, correlationID)
	return toOastPayload(p), err
}

func (a *OASTStoreAdapter) ListPayloads(ctx context.Context, taskID int64, limit int) ([]*oast.Payload, error) {
	rows, err := a.s.ListOastPayloads(ctx, taskID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]*oast.Payload, 0, len(rows))
	for _, r := range rows {
		out = append(out, toOastPayload(r))
	}
	return out, nil
}

func (a *OASTStoreAdapter) InsertInteraction(ctx context.Context, in *oast.Interaction) error {
	return a.s.InsertOastInteraction(ctx, fromOastInteraction(in))
}

func (a *OASTStoreAdapter) ListInteractions(ctx context.Context, taskID int64, payloadID string, since time.Time, limit int) ([]*oast.Interaction, error) {
	rows, err := a.s.ListOastInteractions(ctx, taskID, payloadID, since, limit)
	if err != nil {
		return nil, err
	}
	out := make([]*oast.Interaction, 0, len(rows))
	for _, r := range rows {
		out = append(out, toOastInteraction(r))
	}
	return out, nil
}

func (a *OASTStoreAdapter) DeleteExpired(ctx context.Context, now time.Time) (int64, int64, error) {
	return a.s.DeleteExpiredOast(ctx, now)
}

func (a *OASTStoreAdapter) BindFindingPayloads(ctx context.Context, findingID int64, payloadIDs []string) error {
	return a.s.BindFindingOastPayloads(ctx, findingID, payloadIDs)
}

func (a *OASTStoreAdapter) ListFindingPayloads(ctx context.Context, findingID int64) ([]*oast.Payload, error) {
	rows, err := a.s.ListFindingOastPayloads(ctx, findingID)
	if err != nil {
		return nil, err
	}
	out := make([]*oast.Payload, 0, len(rows))
	for _, r := range rows {
		out = append(out, toOastPayload(r))
	}
	return out, nil
}
