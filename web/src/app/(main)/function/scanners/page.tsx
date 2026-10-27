"use client";

import * as React from "react";

import { AlertCircleIcon, CheckCircle2Icon, PlayIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ScannerProfile, ScannerRunResult, ScannerRunRow } from "@/lib/types";

// 扫描器桥接页：配置"怎么跑一个扫描器" + 手动执行 + 看审计。
// 真正的执行在 Go 侧（参数模板不经 shell 展开），这里只负责编辑与触发。
export default function ScannersPage() {
  const [scanners, setScanners] = React.useState<ScannerProfile[]>([]);
  const [runs, setRuns] = React.useState<ScannerRunRow[]>([]);
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .scanners()
      .then((r) => {
        setScanners(r.scanners);
        setRuns(r.runs);
      })
      .catch((e) => toast.error(`读取扫描器配置失败：${e.message}`))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="p-4 md:p-6">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl">扫描器</h1>
          <p className="text-muted-foreground text-sm">
            把 nuclei / httpx / subfinder / ffuf 等外部工具的结果直接写进资产库与漏洞库。
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}>
          <RefreshCwIcon className="mr-2 size-4" />
          刷新
        </Button>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <RunPanel scanners={scanners} onDone={load} />
        <Card>
          <CardHeader>
            <CardTitle className="text-base">运行历史</CardTitle>
            <CardDescription>最近 50 次执行（手动 / Agent 触发）。</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <RunHistory runs={runs} />
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-base">扫描器配置</CardTitle>
          <CardDescription>
            参数模板中的 <code>{"{{target}}"}</code> 会替换成目标，<code>{"{{outfile}}"}</code> 是临时输出文件， 其余{" "}
            <code>{"{{var}}"}</code> 在运行时由调用方提供（如 ffuf 的 wordlist）。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {scanners.map((s) => (
            <ScannerRow key={s.id} scanner={s} onSaved={load} />
          ))}
          {!loading && scanners.length === 0 && <p className="text-muted-foreground text-sm">没有可用的扫描器配置。</p>}
        </CardContent>
      </Card>
    </div>
  );
}

function RunPanel({ scanners, onDone }: { scanners: ScannerProfile[]; onDone: () => void }) {
  const [profileID, setProfileID] = React.useState<string>("");
  const [target, setTarget] = React.useState("");
  const [vars, setVars] = React.useState("");
  const [running, setRunning] = React.useState(false);
  const [result, setResult] = React.useState<ScannerRunResult | null>(null);

  React.useEffect(() => {
    if (!profileID && scanners.length > 0) {
      const first = scanners.find((s) => s.enabled && s.available) ?? scanners[0];
      setProfileID(String(first.id));
    }
  }, [scanners, profileID]);

  const selected = scanners.find((s) => String(s.id) === profileID);

  const run = async () => {
    if (!selected) return;
    if (!target.trim()) {
      toast.error("请填写目标");
      return;
    }
    const parsed: Record<string, string> = {};
    for (const line of vars.split("\n")) {
      const i = line.indexOf("=");
      if (i > 0) parsed[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    setRunning(true);
    setResult(null);
    try {
      const r = await api.runScanner({ profile_id: selected.id, target: target.trim(), vars: parsed });
      setResult(r);
      toast.success(`完成：新增资产 ${r.assets_added}，新增漏洞 ${r.findings_new}`);
      onDone();
    } catch (e) {
      toast.error(`执行失败：${(e as Error).message}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">执行扫描</CardTitle>
        <CardDescription>手动跑一次，结果直接入库；同一目标重复跑不会产生重复漏洞。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-2">
          <Label htmlFor="scanner">扫描器</Label>
          <select
            id="scanner"
            className="h-9 rounded-md border bg-transparent px-2 text-sm"
            value={profileID}
            onChange={(e) => setProfileID(e.target.value)}
          >
            {scanners.map((s) => (
              <option key={s.id} value={s.id} disabled={!s.enabled}>
                {s.name}（{s.format}）{s.enabled ? "" : " — 未启用"}
              </option>
            ))}
          </select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="target">目标</Label>
          <Input
            id="target"
            placeholder="example.com / https://example.com / https://example.com/FUZZ"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="vars">
            额外参数{selected?.vars?.length ? `（${selected.vars.join(", ")}）` : "（可选）"}
          </Label>
          <Textarea
            id="vars"
            placeholder={"wordlist=/usr/share/wordlists/dir.txt"}
            rows={2}
            value={vars}
            onChange={(e) => setVars(e.target.value)}
          />
        </div>
        <Button onClick={run} disabled={running || !selected}>
          <PlayIcon className="mr-2 size-4" />
          {running ? "执行中…" : "执行"}
        </Button>
        {result && <RunResult result={result} />}
      </CardContent>
    </Card>
  );
}

function RunResult({ result }: { result: ScannerRunResult }) {
  return (
    <div className="rounded-md border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={result.error ? "destructive" : "secondary"}>
          {result.error ? "失败" : result.timed_out ? "超时（部分入库）" : "完成"}
        </Badge>
        <span className="text-muted-foreground">
          {result.profile_name} · {result.target} · {result.duration_ms}ms
        </span>
      </div>
      <div className="mt-2 grid grid-cols-2 gap-1 sm:grid-cols-4">
        <Stat label="资产" value={`${result.assets_added}/${result.assets_seen}`} />
        <Stat label="新漏洞" value={String(result.findings_new)} />
        <Stat label="重复" value={String(result.findings_dup)} />
        <Stat label="命中" value={String(result.findings_seen)} />
      </div>
      {(result.warnings ?? []).length > 0 && (
        <ul className="text-muted-foreground mt-2 list-inside list-disc text-xs">
          {(result.warnings ?? []).map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ul>
      )}
      {result.error && <p className="mt-2 text-destructive text-xs">{result.error}</p>}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-muted-foreground text-xs">{label}</div>
      <div className="font-medium tabular-nums">{value}</div>
    </div>
  );
}

function RunHistory({ runs }: { runs: ScannerRunRow[] }) {
  if (runs.length === 0) {
    return <p className="text-muted-foreground p-4 text-sm">还没有执行记录。</p>;
  }
  return (
    <div className="max-h-[360px] overflow-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>扫描器</TableHead>
            <TableHead>目标</TableHead>
            <TableHead>结果</TableHead>
            <TableHead>耗时</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {runs.map((r) => (
            <TableRow key={r.id}>
              <TableCell className="font-mono text-xs">{r.profile_name}</TableCell>
              <TableCell className="max-w-[180px] truncate text-xs" title={r.target}>
                {r.target}
              </TableCell>
              <TableCell className="text-xs">
                {r.error ? (
                  <span className="text-destructive" title={r.error}>
                    失败
                  </span>
                ) : r.timed_out ? (
                  "超时"
                ) : (
                  `资产 ${r.assets_added} / 漏洞 ${r.findings_new}`
                )}
              </TableCell>
              <TableCell className="text-xs tabular-nums">{Math.round(r.duration_ms / 100) / 10}s</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function ScannerRow({ scanner, onSaved }: { scanner: ScannerProfile; onSaved: () => void }) {
  const [binary, setBinary] = React.useState(scanner.binary);
  const [args, setArgs] = React.useState((scanner.args ?? []).join("\n"));
  const [timeout, setTimeout] = React.useState(String(scanner.timeout_seconds));
  const [saving, setSaving] = React.useState(false);

  return (
    <div className="rounded-md border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{scanner.name}</span>
        <Badge variant="outline">{scanner.format}</Badge>
        {scanner.available ? (
          <Badge variant="secondary">
            <CheckCircle2Icon className="mr-1 size-3" />
            可用
          </Badge>
        ) : (
          <Badge variant="destructive" title={scanner.missing}>
            <AlertCircleIcon className="mr-1 size-3" />
            缺少二进制
          </Badge>
        )}
        <div className="ml-auto flex items-center gap-2">
          <Label htmlFor={`en-${scanner.id}`} className="text-muted-foreground text-xs">
            启用
          </Label>
          <Switch
            id={`en-${scanner.id}`}
            checked={scanner.enabled}
            onCheckedChange={(v) =>
              api
                .saveScanner({
                  id: scanner.id,
                  name: scanner.name,
                  binary,
                  args: splitArgs(args),
                  format: scanner.format,
                  timeout_seconds: Number(timeout) || 0,
                  enabled: v,
                })
                .then(onSaved)
                .catch((e) => toast.error(`保存失败：${e.message}`))
            }
          />
        </div>
      </div>
      {!scanner.available && scanner.missing && <p className="text-muted-foreground mt-1 text-xs">{scanner.missing}</p>}
      <div className="mt-3 grid gap-2 md:grid-cols-[1fr_120px]">
        <div className="grid gap-1">
          <Label className="text-xs">可执行文件</Label>
          <Input value={binary} onChange={(e) => setBinary(e.target.value)} className="h-8 font-mono text-xs" />
        </div>
        <div className="grid gap-1">
          <Label className="text-xs">超时（秒）</Label>
          <Input
            value={timeout}
            onChange={(e) => setTimeout(e.target.value)}
            inputMode="numeric"
            className="h-8 text-xs"
          />
        </div>
      </div>
      <div className="mt-2 grid gap-1">
        <Label className="text-xs">参数（一行一个）</Label>
        <Textarea value={args} onChange={(e) => setArgs(e.target.value)} rows={3} className="font-mono text-xs" />
      </div>
      <div className="mt-2 flex gap-2">
        <Button
          size="sm"
          variant="outline"
          disabled={saving}
          onClick={() => {
            setSaving(true);
            api
              .saveScanner({
                id: scanner.id,
                name: scanner.name,
                binary,
                args: splitArgs(args),
                format: scanner.format,
                timeout_seconds: Number(timeout) || 0,
                enabled: scanner.enabled,
              })
              .then(() => {
                toast.success("已保存");
                onSaved();
              })
              .catch((e) => toast.error(`保存失败：${e.message}`))
              .finally(() => setSaving(false));
          }}
        >
          保存
        </Button>
        {!scanner.builtin && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() =>
              api
                .deleteScanner(scanner.id)
                .then(onSaved)
                .catch((e) => toast.error(`删除失败：${e.message}`))
            }
          >
            <Trash2Icon className="mr-1 size-4" />
            删除
          </Button>
        )}
        {scanner.last_run_at && (
          <span className="text-muted-foreground self-center text-xs">
            上次运行 {new Date(scanner.last_run_at).toLocaleString()}
          </span>
        )}
      </div>
    </div>
  );
}

function splitArgs(s: string): string[] {
  return s
    .split("\n")
    .map((x) => x.trim())
    .filter((x) => x !== "");
}
