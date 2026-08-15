import { useMemo, useState } from "react";

import { Warning } from "@phosphor-icons/react/dist/csr/Warning";

import { EmptyState } from "@/components/aila/EmptyState";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge } from "@/components/aila/mock";

import { FindingRowSkeletonList } from "./skeletons";
import { useSuppressFinding } from "../mutations";
import type { Finding } from "../queries";
import { useProjectFindings } from "../queries";

// ---------------------------------------------------------------------------
// Business-logic helpers (preserved verbatim from the previous panel).
// ---------------------------------------------------------------------------

function reasonSentence(reasons: string[]): string {
  const parts: string[] = [];
  for (const r of reasons) {
    if (r.startsWith("lolbas:")) {
      const bin = r.slice("lolbas:".length);
      parts.push(`it invokes the Living-Off-The-Land binary ${bin}, a legitimate Windows tool routinely abused by attackers for defense evasion`);
    } else if (r.startsWith("suspicious_path:")) {
      parts.push("it runs from a location legitimate installers almost never write to (AppData/Local/Temp, Users/Public, Windows/Temp, ProgramData), a classic attacker-staging pattern");
    } else if (r === "double_extension") {
      parts.push("the filename uses a double-extension (e.g. `invoice.pdf.exe`) -- a classic phishing dropper disguise");
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
      title: `Persistence -- Run-key entry "${f.name ?? evidence.slice(0, 60)}"`,
      body: `A Windows Run-key${who} was configured to launch \`${evidence}\`${where}${when}${runs}. It is worth examining because ${reason}. Run keys execute at user logon, so this grants the binary automatic re-execution privileges on every session.`,
    };
  }
  if (f.artifact_type.startsWith("services")) {
    return {
      title: `Persistence -- Windows service "${f.name ?? evidence.slice(0, 60)}"`,
      body: `A Windows service${who} targets \`${evidence}\`${where}. Suspicious because ${reason}. Services run with SYSTEM privilege at boot -- a strong persistence primitive.`,
    };
  }
  if (f.artifact_type.startsWith("tasks")) {
    return {
      title: `Persistence -- Scheduled task "${f.name ?? evidence.slice(0, 60)}"`,
      body: `A scheduled task${who} runs \`${evidence}\`${where}${when}. Flagged because ${reason}. Scheduled tasks can trigger on user idle, logon, or arbitrary times -- useful for stealthy re-triggering.`,
    };
  }
  if (f.artifact_type === "prefetch" || f.artifact_type.startsWith("prefetch")) {
    return {
      title: `Execution -- ${evidence} ran${runs}`,
      body: `The binary \`${evidence}\`${where} was executed${runs}${when}. Flagged because ${reason}. Prefetch is Windows' own record -- this is proof the binary ran, not just existed.`,
    };
  }
  if (f.artifact_type.startsWith("startup")) {
    return {
      title: `Persistence -- Startup item "${f.name ?? evidence.slice(0, 60)}"`,
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
 *  wants to see when expanded -- the actual "how it was run". */
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

// ---------------------------------------------------------------------------
// Raw mono button styles (mock language).
// ---------------------------------------------------------------------------

const CHROME_BTN: React.CSSProperties = {
  height: 24,
  padding: "0 10px",
  fontSize: 9,
  letterSpacing: "0.1em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

const DANGER_BTN: React.CSSProperties = {
  height: 24,
  padding: "0 10px",
  fontSize: 9,
  letterSpacing: "0.1em",
  color: "var(--accent)",
  background: "color-mix(in srgb, var(--accent) 8%, transparent)",
  border: "1px solid color-mix(in srgb, var(--accent) 40%, transparent)",
  borderRadius: 3,
  cursor: "pointer",
};

// ---------------------------------------------------------------------------
// FindingRow -- one collapsible WindowPanel in the findings stack.
// ---------------------------------------------------------------------------

function FindingRow({
  f,
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
    <div
      role="button"
      tabIndex={0}
      aria-expanded={expanded}
      onClick={onToggle}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onToggle();
        }
      }}
      style={{ cursor: "pointer" }}
    >
      <WindowPanel
        title={n.title}
        tone="accent"
        flush={!expanded}
        actions={
          <div className="flex items-center" style={{ gap: 6 }}>
            {occ > 1 ? <MonoBadge tone="critical">{`\u00d7${occ}`}</MonoBadge> : null}
            <MonoBadge tone="critical">
              {`${f.suspicious_reasons.length} reason${f.suspicious_reasons.length === 1 ? "" : "s"}`}
            </MonoBadge>
            <span
              aria-hidden="true"
              className="font-mono"
              style={{
                fontSize: 11,
                color: "var(--accent)",
                width: 14,
                textAlign: "center",
                userSelect: "none",
              }}
            >
              {expanded ? "\u25be" : "\u25b8"}
            </span>
          </div>
        }
      >
        {expanded ? (
          <div
            className="space-y-3"
            onClick={(e) => e.stopPropagation()}
            role="presentation"
          >
            <p
              className="font-mono"
              style={{ fontSize: 11, lineHeight: 1.6, color: "var(--text-primary)" }}
            >
              {n.body}
            </p>

            <div className="flex flex-wrap items-center" style={{ gap: 6 }}>
              {f.suspicious_reasons.map((r) => (
                <MonoBadge key={r} tone="critical">
                  {r}
                </MonoBadge>
              ))}
            </div>

            {commandFields.length > 0 && (
              <div
                style={{
                  border: "1px solid var(--border-soft)",
                  background: "var(--surface-sunk)",
                  borderRadius: 3,
                  padding: 10,
                }}
              >
                <div
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.12em",
                    color: "var(--text-faint)",
                    marginBottom: 6,
                  }}
                >
                  Exact parameters
                </div>
                <dl
                  className="grid font-mono"
                  style={{
                    gridTemplateColumns: "minmax(0,140px) 1fr",
                    columnGap: 12,
                    rowGap: 4,
                    fontSize: 10,
                  }}
                >
                  {commandFields.map(([k, v]) => (
                    <div key={k} className="contents">
                      <dt style={{ color: "var(--text-faint)" }}>{k}</dt>
                      <dd
                        style={{
                          color: "var(--text-primary)",
                          wordBreak: "break-all",
                          whiteSpace: "pre-wrap",
                        }}
                      >
                        {v}
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>
            )}

            {f.raw_record && (
              <details
                style={{
                  border: "1px solid var(--border-soft)",
                  background: "var(--surface-sunk)",
                  borderRadius: 3,
                }}
              >
                <summary
                  className="font-mono uppercase"
                  style={{
                    cursor: "pointer",
                    padding: "6px 10px",
                    fontSize: 9,
                    letterSpacing: "0.12em",
                    color: "var(--text-faint)",
                    listStyle: "none",
                  }}
                >
                  Full raw record
                </summary>
                <pre
                  className="font-mono"
                  style={{
                    padding: 10,
                    fontSize: 10,
                    lineHeight: 1.5,
                    color: "var(--text-muted)",
                    overflowX: "auto",
                    maxHeight: 384,
                    margin: 0,
                  }}
                >
                  {JSON.stringify(f.raw_record, null, 2)}
                </pre>
              </details>
            )}

            <div className="flex items-center justify-between" style={{ gap: 8 }}>
              <div
                className="flex font-mono"
                style={{ gap: 10, fontSize: 9, color: "var(--text-faint)" }}
              >
                <span>family: {f.artifact_family}</span>
                <span>{"\u00b7"}</span>
                <span>type: {f.artifact_type}</span>
                {f.source_tool && (
                  <>
                    <span>{"\u00b7"}</span>
                    <span>tool: {f.source_tool}</span>
                  </>
                )}
              </div>
              <button
                type="button"
                className="font-mono uppercase"
                style={{
                  ...DANGER_BTN,
                  color: "var(--status-warn)",
                  borderColor:
                    "color-mix(in srgb, var(--status-warn) 40%, transparent)",
                  background:
                    "color-mix(in srgb, var(--status-warn) 8%, transparent)",
                }}
                disabled={suppress.isPending || !f.fingerprint}
                onClick={(e) => {
                  e.stopPropagation();
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
                {suppress.isPending ? "Saving\u2026" : "Mark false positive"}
              </button>
            </div>
          </div>
        ) : null}
      </WindowPanel>
    </div>
  );
}

/**
 * Auto-findings view -- flat, collapsible list of every record the
 * collector heuristics tagged with `suspicious_reasons` (LOLBAS,
 * AppData/Temp execution, double-extension, etc.). One row = one
 * concrete piece of evidence; expand to see exact parameters + raw
 * record. Each row can be marked as false positive -- that hides it
 * and drops a `verdict="false"` directive so every future
 * investigation sees "analyst cleared this as benign".
 */
export function FindingsPanel({ projectId }: { projectId: string }) {
  const { data, isLoading, isError } = useProjectFindings(projectId);
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set());
  const [expandAll, setExpandAll] = useState(false);

  if (isLoading) return <FindingRowSkeletonList count={5} />;
  if (isError) {
    return (
      <WindowPanel
        title="auto-findings"
        tone="warn"
        status="forensics ; findings unavailable"
      >
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--accent)" }}
        >
          Failed to load findings.
        </p>
      </WindowPanel>
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
    <WindowPanel
      title="auto-findings"
      tone="accent"
      status={`forensics ; ${findings.length} suspicious row${findings.length === 1 ? "" : "s"}`}
    >
      <div className="flex items-start justify-between" style={{ gap: 12, marginBottom: 12 }}>
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)", maxWidth: 640, lineHeight: 1.5 }}
        >
          Rows the collector heuristics flagged as suspicious (LOLBAS,
          AppData/Temp execution, double-extension\u2026). Click a row to see the
          exact command parameters, or mark as false positive to hide it and
          teach future runs it's benign.
        </p>
        {findings.length > 0 && (
          <div className="flex items-center shrink-0" style={{ gap: 6 }}>
            <button
              type="button"
              onClick={toggleAll}
              className="font-mono uppercase"
              style={CHROME_BTN}
            >
              {expandAll ? "Collapse all" : "Expand all"}
            </button>
            <button
              type="button"
              onClick={() => downloadFindings(findings, projectId)}
              className="font-mono uppercase"
              style={CHROME_BTN}
              title="Download all findings as JSON"
            >
              Download JSON
            </button>
          </div>
        )}
      </div>

      {findings.length === 0 ? (
        <EmptyState
          icon={<Warning className="h-10 w-10" />}
          title="No suspicious findings yet."
          description="Run Full Analysis on the project dashboard to populate this list -- the collector heuristics tag LOLBAS, AppData/Temp execution, and double-extension patterns automatically."
        />
      ) : (
        <div className="space-y-2">
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
        </div>
      )}
    </WindowPanel>
  );
}
