package scan

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Autumn-27/artex/db"
)

// Sink is what ingestion writes into. Both stores come from the same DB handle.
type Sink struct {
	Assets *db.AssetStore
	DB     *db.DB
}

// IngestOptions binds a result to its owner.
type IngestOptions struct {
	TaskID int64
	// NodeID owns the asset anchors (lineage / coverage); 0 = no graph anchor.
	NodeID int64
	// IntentID is the edge source for findings (intent --yields--> finding). It must
	// be an intent node; 0 means "record the finding without an edge".
	IntentID    int64
	Worker      string
	TriggeredBy string
	// Anchor, when set, links an asset to the owning node (graph lineage /
	// coverage). Kept as a callback so scan does not depend on ExplorationStore.
	Anchor func(nodeID, assetID int64) error
	// Exploration, when set, makes findings go through RecordFinding: the finding
	// lands in the graph (and therefore in the task report) with its node, edge,
	// anchors and notification. When nil (a platform-level manual scan with no task)
	// findings are written to the findings table only.
	Exploration *db.ExplorationStore
}

// IngestStats reports what a single parsed result contributed.
type IngestStats struct {
	AssetsSeen   int
	AssetsAdded  int
	FindingsSeen int
	FindingsNew  int
	FindingsDup  int
	AssetIDs     []int64
	Notes        []string
}

// Ingest writes a parsed Result into the asset and finding stores.
//
// Assets are upserted through the same calls the agent's insert_assets tool uses,
// so scanner-discovered rows are indistinguishable from agent-discovered ones: the
// same company attribution, the same task linkage, the same scope accumulation.
// Findings take one of two paths. With an ExplorationStore (a scan inside a task)
// they go through RecordFinding, so they become graph nodes — visible to the
// planner, the coverage view and the task report — and dedup on
// (source, external_key). Without one (a platform-level manual scan) they are
// written to the findings table only.
func Ingest(ctx context.Context, sink Sink, opts IngestOptions, res *Result) (*IngestStats, error) {
	if sink.Assets == nil || sink.DB == nil {
		return nil, fmt.Errorf("scan: 存储未初始化")
	}
	if res == nil {
		return nil, fmt.Errorf("scan: 结果为空")
	}
	st := &IngestStats{AssetsSeen: len(res.Assets), FindingsSeen: len(res.Findings)}
	// A concurrent scanner run can add the same asset between our upserts; the
	// unique indexes make the writes idempotent, and this set keeps the finding's
	// affected-asset list free of repeats.
	assetSeen := map[int64]bool{}
	assetIDs := make([]int64, 0, len(res.Assets))
	// Index the assets so each finding can cite the endpoint it actually fired on
	// instead of every asset the run happened to touch.
	exact := map[string]int64{}
	origin := map[string]int64{}
	name := map[string]int64{}

	for _, a := range res.Assets {
		id, err := ingestAsset(sink.Assets, opts.TaskID, a)
		if err != nil {
			st.Notes = append(st.Notes, fmt.Sprintf("资产 %s 写入失败: %v", assetLabel(a), err))
			continue
		}
		st.AssetsAdded++
		if id > 0 && !assetSeen[id] {
			assetSeen[id] = true
			assetIDs = append(assetIDs, id)
		}
		if id > 0 {
			if a.URL != "" {
				u := lower(a.URL)
				if _, ok := exact[u]; !ok {
					exact[u] = id
				}
				if o := originOf(a.URL); o != "" {
					if _, ok := origin[o]; !ok {
						origin[o] = id
					}
				}
			}
			if a.Domain != "" {
				if _, ok := name[lower(a.Domain)]; !ok {
					name[lower(a.Domain)] = id
				}
			}
		}
	}
	st.AssetIDs = assetIDs

	// Anchor every asset this scan touched to the owning node once, so graph
	// lineage does not depend on findings happening to exist.
	if opts.NodeID > 0 && opts.Anchor != nil {
		for _, id := range st.AssetIDs {
			_ = opts.Anchor(opts.NodeID, id)
		}
	}

	worker := opts.Worker
	if worker == "" {
		worker = "scanner"
	}
	for _, f := range res.Findings {
		refs := findingAssetRefs(f, exact, origin, name)
		key := taskScopedKey(opts.TaskID, f)
		if opts.Exploration != nil {
			in := db.RecordFindingInput{
				TaskID:      opts.TaskID,
				IntentID:    opts.IntentID,
				VulnClass:   f.VulnClass,
				Name:        f.Name,
				Severity:    f.Severity,
				Summary:     f.Summary,
				Evidence:    f.Evidence,
				Worker:      worker,
				AssetIDs:    refs,
				Source:      f.Source,
				ExternalKey: key,
				CVSSScore:   f.CVSSScore,
				CVSSVector:  f.CVSSVector,
			}
			_, err := opts.Exploration.RecordFinding(ctx, in)
			switch {
			case errors.Is(err, db.ErrDuplicateFinding):
				st.FindingsDup++
			case err != nil:
				st.Notes = append(st.Notes, fmt.Sprintf("漏洞 %s 写入失败: %v", f.VulnClass, err))
			default:
				st.FindingsNew++
			}
			continue
		}
		in := db.ScannerFindingInput{
			TaskID:      opts.TaskID,
			NodeID:      opts.NodeID,
			VulnClass:   f.VulnClass,
			Name:        f.Name,
			Severity:    f.Severity,
			Summary:     f.Summary,
			Evidence:    f.Evidence,
			Worker:      worker,
			Source:      f.Source,
			ExternalKey: key,
			AssetIDs:    refs,
			CVSSScore:   f.CVSSScore,
			CVSSVector:  f.CVSSVector,
		}
		if _, created, err := sink.DB.AddScannerFinding(ctx, in); err != nil {
			st.Notes = append(st.Notes, fmt.Sprintf("漏洞 %s 写入失败: %v", f.VulnClass, err))
		} else if created {
			st.FindingsNew++
		} else {
			st.FindingsDup++
		}
	}
	return st, nil
}

// findingAssetRefs resolves the asset a finding actually fired on. It prefers an
// exact URL match, then the URL's origin (the service), then the host name
// (subdomain assets). An unmatched finding keeps an empty list rather than
// inheriting unrelated assets.
func findingAssetRefs(f Finding, exact, origin, name map[string]int64) []int64 {
	for _, raw := range []string{f.MatchedAt, f.Host} {
		if raw == "" {
			continue
		}
		if id, ok := exact[lower(raw)]; ok {
			return []int64{id}
		}
		if o := originOf(raw); o != "" {
			if id, ok := origin[o]; ok {
				return []int64{id}
			}
		}
		if id, ok := name[lower(raw)]; ok {
			return []int64{id}
		}
	}
	return nil
}

// taskScopedKey keeps the dedup identity unique per task: the same template firing
// on the same host inside two different engagements is two findings, not one.
func taskScopedKey(taskID int64, f Finding) string {
	return strconv.FormatInt(taskID, 10) + "|" + f.FingerprintKey()
}

func ingestAsset(as *db.AssetStore, taskID int64, a Asset) (int64, error) {
	var (
		id  int64
		err error
	)
	switch a.Kind {
	case AssetSubdomain:
		if a.Domain == "" {
			return 0, fmt.Errorf("domain 为空")
		}
		id, err = as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      a.Domain,
			RecordType:  a.RecordType,
			RecordValue: a.RecordValue,
			TaskID:      taskID,
		})
	case AssetIP:
		if a.IP == "" {
			return 0, fmt.Errorf("ip 为空")
		}
		var bound []string
		if a.BoundDomain != "" {
			bound = []string{a.BoundDomain}
		}
		id, err = as.UpsertIP(db.UpsertIPReq{IP: a.IP, BoundDomains: bound, TaskID: taskID})
	case AssetService:
		if a.URL == "" {
			return 0, fmt.Errorf("url 为空")
		}
		var status *int
		if a.StatusCode > 0 {
			v := a.StatusCode
			status = &v
		}
		var length *int64
		if a.ContentLength > 0 {
			v := a.ContentLength
			length = &v
		}
		id, err = as.UpsertHTTPService(db.UpsertHTTPServiceReq{
			URL:           a.URL,
			Technologies:  a.Technologies,
			StatusCode:    status,
			ContentLength: length,
			PageTitle:     a.PageTitle,
			FaviconMMH3:   a.FaviconMMH3,
			IP:            a.IP,
			TaskID:        taskID,
		})
	case AssetEndpoint:
		if a.URL == "" {
			return 0, fmt.Errorf("url 为空")
		}
		method := a.Method
		if method == "" {
			method = "GET"
		}
		id, err = as.UpsertEndpoint(db.UpsertEndpointReq{
			URL:    a.URL,
			Method: method,
			IP:     a.IP,
			TaskID: taskID,
		})
	default:
		return 0, fmt.Errorf("未知资产类型 %q", a.Kind)
	}
	if err != nil {
		return 0, err
	}
	// Mirror insert_assets' auto-scope hook so a scanner-discovered host becomes
	// part of the task's boundary and shows up in coverage / untested queries.
	_ = as.AddAutoScope(taskID, a.Kind, a.Domain, a.URL, a.IP)
	return id, nil
}

func assetLabel(a Asset) string {
	switch a.Kind {
	case AssetSubdomain:
		return a.Domain
	case AssetIP:
		return a.IP
	case AssetService, AssetEndpoint:
		return a.URL
	}
	return a.Kind
}
