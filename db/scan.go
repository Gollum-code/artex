package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Autumn-27/artex/notify"
)

// =====================================================================
// 扫描器桥接持久化（schema.sql §O）
// =====================================================================
//
// scanner_profiles 是"怎么跑一个扫描器"的声明；scanner_runs 是每次执行的审计。
// 两者分开是因为同一份声明会被跑很多次（不同目标/不同任务），审计必须独立保留。
// findings 上的 source + external_key 构成扫描器去重键：nuclei 同一模板在同一
// 端点重复命中时，第二次写入被唯一索引吞掉，而不是产生两条重复漏洞。

// ScannerProfile 是一行 scanner_profiles。Args 为参数模板，占位符由 scan 包展开。
type ScannerProfile struct {
	ID             int64      `json:"id"`
	Name           string     `json:"name"`
	Binary         string     `json:"binary"`
	Args           []string   `json:"args"`
	Format         string     `json:"format"`
	TimeoutSeconds int        `json:"timeout_seconds"`
	Enabled        bool       `json:"enabled"`
	Builtin        bool       `json:"builtin"`
	Note           string     `json:"note"`
	LastRunAt      *time.Time `json:"last_run_at"`
	LastError      string     `json:"last_error"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

const scannerProfileCols = `id, name, binary_path, args, format, timeout_seconds, enabled, builtin, note, last_run_at, last_error, created_at, updated_at`

func scanScannerProfile(row interface{ Scan(...any) error }) (*ScannerProfile, error) {
	var p ScannerProfile
	var raw string
	var lastRun sql.NullTime
	err := row.Scan(&p.ID, &p.Name, &p.Binary, &raw, &p.Format, &p.TimeoutSeconds,
		&p.Enabled, &p.Builtin, &p.Note, &lastRun, &p.LastError, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(raw), &p.Args)
	if lastRun.Valid {
		p.LastRunAt = &lastRun.Time
	}
	return &p, nil
}

// ListScannerProfiles returns every configured scanner, builtin first.
func (d *DB) ListScannerProfiles() ([]*ScannerProfile, error) {
	rows, err := d.Query(`SELECT ` + scannerProfileCols + ` FROM scanner_profiles ORDER BY builtin DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ScannerProfile
	for rows.Next() {
		p, err := scanScannerProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetScannerProfile returns one profile, or (nil, nil) when it does not exist.
func (d *DB) GetScannerProfile(id int64) (*ScannerProfile, error) {
	p, err := scanScannerProfile(d.QueryRow(`SELECT `+scannerProfileCols+` FROM scanner_profiles WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

// GetScannerProfileByName returns one profile by its unique name.
func (d *DB) GetScannerProfileByName(name string) (*ScannerProfile, error) {
	p, err := scanScannerProfile(d.QueryRow(`SELECT `+scannerProfileCols+` FROM scanner_profiles WHERE name=$1`, name))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

// SaveScannerProfile inserts or updates a profile. A builtin row keeps builtin=true
// and cannot be renamed; its binary/args/format stay editable so an operator can
// point it at a different install or narrow its flags.
func (d *DB) SaveScannerProfile(p *ScannerProfile) (int64, error) {
	args, err := json.Marshal(p.Args)
	if err != nil {
		return 0, err
	}
	var id int64
	if p.ID > 0 {
		err = d.QueryRow(`
UPDATE scanner_profiles SET name=$2, binary_path=$3, args=$4, format=$5, timeout_seconds=$6,
       enabled=$7, note=$8
WHERE id=$1 RETURNING id`,
			p.ID, p.Name, p.Binary, string(args), p.Format, p.TimeoutSeconds, p.Enabled, p.Note).Scan(&id)
		return id, err
	}
	err = d.QueryRow(`
INSERT INTO scanner_profiles(name, binary_path, args, format, timeout_seconds, enabled, builtin, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (name) DO UPDATE SET binary_path=EXCLUDED.binary_path, args=EXCLUDED.args,
       format=EXCLUDED.format, timeout_seconds=EXCLUDED.timeout_seconds,
       enabled=EXCLUDED.enabled, note=EXCLUDED.note
RETURNING id`,
		p.Name, p.Binary, string(args), p.Format, p.TimeoutSeconds, p.Enabled, p.Builtin, p.Note).Scan(&id)
	return id, err
}

// DeleteScannerProfile removes a non-builtin profile. Builtin rows are protected:
// the seed would recreate them on next boot anyway, and deleting one that an agent
// prompt references is more surprising than useful.
func (d *DB) DeleteScannerProfile(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM scanner_profiles WHERE id=$1 AND builtin=false`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// MarkScannerProfileRun stamps the last run time / error on a profile.
func (d *DB) MarkScannerProfileRun(id int64, at time.Time, lastErr string) error {
	_, err := d.Exec(`UPDATE scanner_profiles SET last_run_at=$2, last_error=$3 WHERE id=$1`, id, at, lastErr)
	return err
}

// ScannerRun is one execution record.
type ScannerRun struct {
	ID           int64      `json:"id"`
	ProfileID    *int64     `json:"profile_id"`
	ProfileName  string     `json:"profile_name"`
	Target       string     `json:"target"`
	TaskID       *int64     `json:"task_id"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at"`
	DurationMS   int64      `json:"duration_ms"`
	ExitCode     int        `json:"exit_code"`
	TimedOut     bool       `json:"timed_out"`
	Records      int        `json:"records"`
	AssetsSeen   int        `json:"assets_seen"`
	AssetsAdded  int        `json:"assets_added"`
	FindingsSeen int        `json:"findings_seen"`
	FindingsNew  int        `json:"findings_new"`
	FindingsDup  int        `json:"findings_dup"`
	Error        string     `json:"error"`
	Warnings     []string   `json:"warnings"`
	TriggeredBy  string     `json:"triggered_by"`
}

// StartScannerRun allocates a run row before execution so a crash still leaves a
// visible in-flight record.
func (d *DB) StartScannerRun(ctx context.Context, profileID int64, profileName, target string, taskID int64, triggeredBy string) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO scanner_runs(profile_id, profile_name, target, task_id, triggered_by)
VALUES (NULLIF($1,0),$2,$3,NULLIF($4,0),$5) RETURNING id`,
		profileID, profileName, target, taskID, triggeredBy).Scan(&id)
	return id, err
}

// FinishScannerRun writes the outcome of a run.
func (d *DB) FinishScannerRun(ctx context.Context, run *ScannerRun) error {
	warn, _ := json.Marshal(run.Warnings)
	if warn == nil {
		warn = []byte("[]")
	}
	var finished any
	if run.FinishedAt != nil {
		finished = *run.FinishedAt
	}
	_, err := d.ExecContext(ctx, `
UPDATE scanner_runs SET finished_at=$2, duration_ms=$3, exit_code=$4, timed_out=$5,
       records=$6, assets_seen=$7, assets_added=$8, findings_seen=$9, findings_new=$10,
       findings_dup=$11, error=$12, warnings=$13
WHERE id=$1`,
		run.ID, finished, run.DurationMS, run.ExitCode, run.TimedOut, run.Records,
		run.AssetsSeen, run.AssetsAdded, run.FindingsSeen, run.FindingsNew,
		run.FindingsDup, run.Error, string(warn))
	return err
}

// ListScannerRuns pages through run history, optionally scoped to one task.
func (d *DB) ListScannerRuns(taskID int64, limit int) ([]*ScannerRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	var (
		rows *sql.Rows
		err  error
	)
	if taskID > 0 {
		rows, err = d.Query(`SELECT id, profile_id, profile_name, target, task_id, started_at,
       finished_at, duration_ms, exit_code, timed_out, records, assets_seen, assets_added,
       findings_seen, findings_new, findings_dup, error, warnings, triggered_by
FROM scanner_runs WHERE task_id=$1 ORDER BY id DESC LIMIT $2`, taskID, limit)
	} else {
		rows, err = d.Query(`SELECT id, profile_id, profile_name, target, task_id, started_at,
       finished_at, duration_ms, exit_code, timed_out, records, assets_seen, assets_added,
       findings_seen, findings_new, findings_dup, error, warnings, triggered_by
FROM scanner_runs ORDER BY id DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ScannerRun
	for rows.Next() {
		var r ScannerRun
		var pid, tid sql.NullInt64
		var fin sql.NullTime
		var warn string
		if err := rows.Scan(&r.ID, &pid, &r.ProfileName, &r.Target, &tid, &r.StartedAt,
			&fin, &r.DurationMS, &r.ExitCode, &r.TimedOut, &r.Records, &r.AssetsSeen,
			&r.AssetsAdded, &r.FindingsSeen, &r.FindingsNew, &r.FindingsDup,
			&r.Error, &warn, &r.TriggeredBy); err != nil {
			return nil, err
		}
		if pid.Valid {
			r.ProfileID = &pid.Int64
		}
		if tid.Valid {
			r.TaskID = &tid.Int64
		}
		if fin.Valid {
			r.FinishedAt = &fin.Time
		}
		_ = json.Unmarshal([]byte(warn), &r.Warnings)
		out = append(out, &r)
	}
	return out, rows.Err()
}

// ScannerFindingInput is one finding produced by a scanner.
type ScannerFindingInput struct {
	TaskID    int64
	NodeID    int64
	VulnClass string
	Name      string
	Severity  string
	Summary   string
	Evidence  string
	Worker    string
	// Source is the scanner name; ExternalKey is the dedup identity computed by
	// scan.Finding.FingerprintKey. Both empty means "not a scanner finding".
	Source      string
	ExternalKey string
	AssetIDs    []int64
	CVSSScore   float64
	CVSSVector  string
}

// AddScannerFinding inserts a scanner finding, deduplicating on
// (source, external_key). It returns created=false when an identical finding was
// already recorded, so a rescan reports "already known" instead of duplicating.
func (d *DB) AddScannerFinding(ctx context.Context, in ScannerFindingInput) (id int64, created bool, err error) {
	assets := in.AssetIDs
	if assets == nil {
		assets = []int64{}
	}
	raw, _ := json.Marshal(assets)

	err = d.QueryRowContext(ctx, `
INSERT INTO findings(task_id, node_id, vulnclass, name, severity, summary, evidence, worker, asset_ids, source, external_key, cvss_score, cvss_vector)
VALUES (NULLIF($1,0), NULLIF($2,0), $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (source, external_key) WHERE source <> '' AND external_key <> ''
DO NOTHING
RETURNING id`,
		in.TaskID, in.NodeID, in.VulnClass, in.Name, in.Severity, in.Summary,
		in.Evidence, in.Worker, string(raw), in.Source, in.ExternalKey,
		in.CVSSScore, in.CVSSVector).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}

	// Anchor the affected assets to the owning node so coverage and lineage see
	// them. A scanner finding without a node still exists as evidence.
	if in.NodeID > 0 {
		for _, aid := range assets {
			_, _ = d.ExecContext(ctx,
				`INSERT INTO exploration_anchors(node_id, asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,
				in.NodeID, aid)
		}
	}

	// Push notification in the same call: a scan finding must reach the channels
	// exactly like an agent-reported one.
	_, _ = d.AddNotificationEvent(ctx, notify.EventFindingCreated, id, notify.Snapshot{
		Kind:      notify.EventFindingCreated,
		FindingID: id,
		TaskID:    in.TaskID,
		VulnClass: in.VulnClass,
		Name:      in.Name,
		Severity:  in.Severity,
		Summary:   in.Summary,
		AssetIDs:  assets,
	})
	return id, true, nil
}
