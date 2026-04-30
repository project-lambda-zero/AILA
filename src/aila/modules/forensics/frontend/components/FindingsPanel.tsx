import { useMemo, useState } from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";

import { useSuppressFinding } from "../mutations";
import type { Finding } from "../queries";
import { useProjectFindings } from "../queries";

function reasonSentence(reasons: string[]): string {
  const parts: string[] = [];
  for (const r of reasons) {
    if (r.startsWith("lolbas:")) {
      const bin = r.slice("lolbas:".length);
      parts.push(`it invokes the Living-Off-The-Land binary ${bin}, a legitimate Windows tool routinely abused by attackers for defense evasion`);
    } else if (r.startsWith("suspicious_path:")) {
      parts.push("it runs from a location legitimate installers almost never write to (AppData/Local/Temp, Users/Public, Windows/Temp, ProgramData), a classic attacker-staging pattern");
    } else if (r === "double_extension") {
      parts.push("the filename uses a double-extension (e.g. `invoice.pdf.exe`) — a classic phishing dropper disguise");
    } else {
      parts.push(`heuristic "${r}" matched`);
    }
  }
  return parts.join("; and ");
}

function narrativeFor(f: Finding): { title: string; body: string } {
  const where = f.path ? ` at \`${f.path}\`` : "";
  const who = f.user ? ` under user \`${f.user}\`` : "";
  const when = f.last_run ? ` last observed ${f.last_run.replace("T", " ").replace(/\.\d+.*/, "")}` : "";
  const runs = typeof f.run_count === "number" && f.run_count > 0 ? `, executed ${f.run_count}×` : "";
  const evidence =
    (typeof f.executable === "string" && f.executable) ||
    (typeof f.name === "string" && f.name) ||
    "";

  const reason = reasonSentence(f.suspicious_reasons);

  if (f.artifact_type === "runkeys" || f.artifact_type === "runkey") {
    return {
      title: `Persistence — Run-key entry "${f.name ?? evidence.slice(0, 60)}"`,
      body: `A Windows Run-key${who} was configured to launch \`${evidence}\`${where}${when}${runs}. It is worth examining because ${reason}. Run keys execute at user logon, so this grants the binary automatic re-execution privileges on every session.`,
    };
  }
  if (f.artifact_type.startsWith("services")) {
    return {
      title: `Persistence — Windows service "${f.name ?? evidence.slice(0, 60)}"`,
      body: `A Windows service${who} targets \`${evidence}\`${where}. Suspicious because ${reason}. Services run with SYSTEM privilege at boot — a strong persistence primitive.`,
    };
  }
  if (f.artifact_type.startsWith("tasks")) {
    return {
      title: `Persistence — Scheduled task "${f.name ?? evidence.slice(0, 60)}"`,
      body: `A scheduled task${who} runs \`${evidence}\`${where}${when}. Flagged because ${reason}. Scheduled tasks can trigger on user idle, logon, or arbitrary times — useful for stealthy re-triggering.`,
    };
  }
  if (f.artifact_type === "prefetch" || f.artifact_type.startsWith("prefetch")) {
    return {
      title: `Execution — ${evidence} ran${runs}`,
      body: `The binary \`${evidence}\`${where} was executed${runs}${when}. Flagged because ${reason}. Prefetch is Windows' own record — this is proof the binary ran, not just existed.`,
    };
  }
  if (f.artifact_type.startsWith("startup")) {
    return {
      title: `Persistence — Startup item "${f.name ?? evidence.slice(0, 60)}"`,
      body: `A startup entry${who} points to \`${evidence}\`${where}. Flagged because ${reason}.`,
    };
  }
  return {
    title: `${f.artifact_family}/${f.artifact_type}: ${evidence.slice(0, 80)}`,
    body: `Evidence${where}${who}${when}${runs}. Flagged because ${reason}.`,
  };
}

/** Extract every key from the raw dissect record that likely contains a
 *  command string, args, or a full launch spec. This is what the user
 *  wants to see when expanded — the actual "how it was run". */
function extractCommandFields(raw: Record<string, unknown> | undefined): Array<[string, string]> {
  if (!raw || typeof raw !== "object") return [];
  const interesting = [
    "command",
    "command_line",
    "commandline",
    "argline",
    "arguments",
    "args",
    "value",
    "image_path",
    "binary_path",
    "target",
    "action",
    "action_command",
    "executable",
    "path",
    "uri",
    "url",
    "parameters",
  ];
  const out: Array<[string, string]> = [];
  for (const k of interesting) {
    const v = raw[k];
    if (typeof v === "string" && v.length > 0) out.push([k, v]);
    else if (typeof v === "number") out.push([k, String(v)]);
  }
  return out;
}

function downloadFindings(findings: Finding[], projectId: string) {
  const blob = new Blob([JSON.stringify(findings, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `findings-${projectId}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function FindingRow({
  f,
  index,
  expanded,
  onToggle,
  projectId,
}: {
  f: Finding;
  index: number;
  expanded: boolean;
  onToggle: () => void;
  projectId: string;
}) {
  const suppress = useSuppressFinding(projectId);
  const n = narrativeFor(f);
  const commandFields = useMemo(() => extractCommandFields(f.raw_record), [f.raw_record]);
  const occ = f.occurrences ?? 1;

  return (
    <li className="rounded-md border border-red-900/40 bg-red-950/20 overflow-hidden">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        className="w-full px-4 py-2.5 flex items-center gap-3 text-left hover:bg-red-950/40 transition-colors"
      >
        <span className="text-[10px] font-mono text-red-300/80 shrink-0 w-6">#{index + 1}</span>
        <span className="text-xs font-mono text-red-300/70 shrink-0 select-none">
          {expanded ? "▾" : "▸"}
        </span>
        <h4 className="text-sm font-semibold text-foreground flex-1 truncate">{n.title}</h4>
        {occ > 1 && (
          <span className="shrink-0 px-1.5 py-0.5 rounded bg-red-900/60 text-red-200 text-[10px] font-mono">
            ×{occ}
          </span>
        )}
        <span className="shrink-0 text-[10px] font-mono text-red-300/70">
          {f.suspicious_reasons.length} reason{f.suspicious_reasons.length === 1 ? "" : "s"}
        </span>
      </button>

      {expanded && (
        <div className="px-4 pb-3 pt-1 space-y-2 border-t border-red-900/30">
          <p className="text-sm text-text-muted leading-relaxed">{n.body}</p>

          <div className="flex flex-wrap gap-1">
            {f.suspicious_reasons.map((r, j) => (
              <span
                key={j}
                className="px-1.5 py-0.5 rounded bg-red-900/60 text-red-200 text-[10px] font-mono"
              >
                {r}
              </span>
            ))}
          </div>

          {commandFields.length > 0 && (
            <div className="rounded border border-red-900/30 bg-black/30 p-2">
              <div className="text-[10px] font-mono text-red-300/70 mb-1 uppercase tracking-wide">
                Exact parameters
              </div>
              <dl className="grid grid-cols-[min-content_1fr] gap-x-3 gap-y-1 text-xs font-mono">
                {commandFields.map(([k, v]) => (
                  <div key={k} className="contents">
                    <dt className="text-red-300/80">{k}</dt>
                    <dd className="text-foreground break-all whitespace-pre-wrap">{v}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}

          {f.raw_record && (
            <details className="rounded border border-red-900/30 bg-black/30">
              <summary className="cursor-pointer px-2 py-1 text-[10px] font-mono text-red-300/70 uppercase tracking-wide hover:text-red-200">
                Full raw record
              </summary>
              <pre className="p-2 text-[11px] font-mono text-foreground/80 overflow-x-auto max-h-96">
                {JSON.stringify(f.raw_record, null, 2)}
              </pre>
            </details>
          )}

          <div className="flex items-center justify-between gap-2">
            <div className="flex gap-2 text-[10px] font-mono text-red-300/60">
              <span>family: {f.artifact_family}</span>
              <span>·</span>
              <span>type: {f.artifact_type}</span>
              {f.source_tool && (
                <>
                  <span>·</span>
                  <span>tool: {f.source_tool}</span>
                </>
              )}
            </div>
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2 text-[10px] border-amber-600 text-amber-400 hover:bg-amber-950/30"
              disabled={suppress.isPending || !f.fingerprint}
              onClick={() => {
                if (!f.fingerprint) return;
                if (
                  !window.confirm(
                    "Mark this finding as false positive? It will be hidden from the list, and every future investigation will see 'analyst cleared this as benign'.",
                  )
                )
                  return;
                suppress.mutate({
                  fingerprint: f.fingerprint,
                  artifact_type: f.artifact_type,
                  executable:
                    typeof f.executable === "string" ? f.executable : null,
                  path: f.path ?? null,
                  name: f.name ?? null,
                  finding_user: f.user ?? null,
                  reasons: f.suspicious_reasons,
                });
              }}
            >
              {suppress.isPending ? "Saving…" : "Mark false positive"}
            </Button>
          </div>
        </div>
      )}
    </li>
  );
}

/**
 * Auto-findings view — flat, collapsible list of every record the
 * collector heuristics tagged with `suspicious_reasons` (LOLBAS,
 * AppData/Temp execution, double-extension, etc.). One row = one
 * concrete piece of evidence; expand to see exact parameters + raw
 * record. Each row can be marked as false positive — that hides it
 * and drops a `verdict="false"` directive so every future
 * investigation sees "analyst cleared this as benign".
 */
export function FindingsPanel({ projectId }: { projectId: string }) {
  const { data, isLoading, isError } = useProjectFindings(projectId);
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set());
  const [expandAll, setExpandAll] = useState(false);

  if (isLoading) return <LoadingSkeleton size="md" width="full" />;
  if (isError) {
    return (
      <AilaCard className="border-border-danger">
        <p className="text-sm text-text-danger">Failed to load findings.</p>
      </AilaCard>
    );
  }

  const findings = data?.data ?? [];

  const toggle = (i: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  };

  const toggleAll = () => {
    if (expandAll) {
      setExpanded(new Set());
      setExpandAll(false);
    } else {
      setExpanded(new Set(findings.map((_, i) => i)));
      setExpandAll(true);
    }
  };

  return (
    <AilaCard>
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-foreground">Auto-findings</h3>
          <p className="text-xs text-text-muted mt-0.5">
            Rows the collector heuristics flagged as suspicious (LOLBAS, AppData/Temp execution,
            double-extension…). Click a row to see the exact command parameters, or mark as false
            positive to hide it and teach future runs it's benign.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-xs text-text-muted font-mono">
            {findings.length}
          </span>
          {findings.length > 0 && (
            <>
              <button
                type="button"
                onClick={toggleAll}
                className="text-[10px] font-mono px-2 py-1 rounded border border-red-900/40 bg-red-950/20 text-red-200 hover:bg-red-900/40"
              >
                {expandAll ? "collapse all" : "expand all"}
              </button>
              <button
                type="button"
                onClick={() => downloadFindings(findings, projectId)}
                className="text-[10px] font-mono px-2 py-1 rounded border border-red-900/40 bg-red-950/20 text-red-200 hover:bg-red-900/40"
                title="Download all findings as JSON"
              >
                download json
              </button>
            </>
          )}
        </div>
      </div>

      {findings.length === 0 ? (
        <p className="text-sm text-text-muted italic py-6 text-center">
          No suspicious findings yet. Run Full Analysis to populate — the heuristics will tag any
          LOLBAS, AppData/Temp execution, or double-extension patterns automatically.
        </p>
      ) : (
        <ol className="space-y-1.5">
          {findings.map((f, i) => (
            <FindingRow
              key={f.fingerprint ?? i}
              f={f}
              index={i}
              expanded={expanded.has(i)}
              onToggle={() => toggle(i)}
              projectId={projectId}
            />
          ))}
        </ol>
      )}
    </AilaCard>
  );
}
