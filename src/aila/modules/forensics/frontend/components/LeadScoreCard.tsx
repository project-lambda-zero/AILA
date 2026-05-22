import { useMemo, useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useProjectLeads } from "../queries";
import type { PromotedLead } from "../types";

type Severity = "critical" | "high" | "medium" | "low" | "info";

function scoreSeverity(score: number): Severity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "info";
}

function scoreBucket(score: number): string {
  if (score >= 80) return "Strong finding";
  if (score >= 60) return "High-confidence lead";
  if (score >= 40) return "Worth investigating";
  if (score >= 20) return "Weak signal";
  return "Noise";
}

interface ParsedReason {
  headline: string;
  meta: string[];
  question: string | null;
  answer: string | null;
  iocSummaries: string[];
}

function parseReason(reason: string): ParsedReason {
  const parts = reason
    .split("; ")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  let headline = parts[0] ?? reason;
  const meta: string[] = [];
  let question: string | null = null;
  let answer: string | null = null;
  const iocSummaries: string[] = [];

  for (const clause of parts.slice(1)) {
    if (clause.startsWith("Q: ")) {
      question = clause.slice(3).trim();
    } else if (clause.startsWith("A: ")) {
      answer = clause.slice(3).trim();
    } else if (/^severity=/.test(clause)) {
      meta.push(clause);
    } else if (/^inv=/.test(clause)) {
      meta.push(clause);
    } else if (/\bextracted\b|\(e\.g\./.test(clause)) {
      iocSummaries.push(clause);
    } else if (/^'[^']+' matched at /.test(clause)) {
      // legacy keyword-match line; drop
      continue;
    } else if (headline === parts[0] && !headline.includes("(score")) {
      // If the first clause wasn't a "(score N)" header, treat this as part
      // of the headline by merging.
      headline = `${headline} · ${clause}`;
    } else {
      meta.push(clause);
    }
  }

  return { headline, meta, question, answer, iocSummaries };
}

function LeadRow({ lead }: { lead: PromotedLead }) {
  const [open, setOpen] = useState(false);
  const parsed = useMemo(() => parseReason(lead.reason), [lead.reason]);
  const evidence = lead.evidence ?? [];
  const typeLabel = lead.artifact_type
    ? `${lead.artifact_family}/${lead.artifact_type}`
    : lead.artifact_family;

  const expandable =
    evidence.length > 0 ||
    parsed.question !== null ||
    parsed.answer !== null ||
    parsed.iocSummaries.length > 0 ||
    (lead.related_artifact_ids?.length ?? 0) > 0;

  const severity = scoreSeverity(lead.score);

  return (
    <div className="border border-border rounded-md bg-surface text-xs overflow-hidden">
      <div className="px-3 py-2.5 space-y-1.5">
        {/* Header row: score · bucket · type */}
        <div className="flex items-center gap-2">
          <AilaBadge severity={severity} size="sm">
            {lead.score.toFixed(0)}
          </AilaBadge>
          <span className="text-[10px] text-text-muted font-medium uppercase tracking-wide">
            {scoreBucket(lead.score)}
          </span>
          <span className="text-text-muted font-mono text-[11px] ml-auto shrink-0">
            {typeLabel}
          </span>
          {lead.source_tool && (
            <span className="text-text-muted text-[10px] shrink-0">
              via {lead.source_tool}
            </span>
          )}
        </div>

        {/* Full multi-line headline — NOT truncated. */}
        <div className="text-foreground leading-relaxed whitespace-pre-wrap">
          {parsed.headline}
        </div>

        {/* Meta chips */}
        {parsed.meta.length > 0 && (
          <div className="flex flex-wrap gap-1.5 pt-0.5">
            {parsed.meta.map((m, i) => (
              <span
                key={i}
                className="px-1.5 py-0.5 text-[10px] rounded bg-surface-secondary text-text-muted font-mono"
              >
                {m}
              </span>
            ))}
          </div>
        )}

        {expandable && (
          <button
            type="button"
            onClick={() => setOpen((p) => !p)}
            className="text-[11px] text-primary hover:underline pt-0.5"
            aria-expanded={open}
          >
            {open ? "Hide details ▾" : "Show details ▸"}
          </button>
        )}
      </div>

      {open && expandable && (
        <div className="border-t border-border bg-black/10 px-3 py-2.5 space-y-2">
          {parsed.question && (
            <div>
              <div className="text-[10px] font-mono text-text-muted uppercase tracking-wide mb-0.5">
                Question
              </div>
              <div className="text-foreground leading-relaxed whitespace-pre-wrap">
                {parsed.question}
              </div>
            </div>
          )}
          {parsed.answer && (
            <div>
              <div className="text-[10px] font-mono text-text-muted uppercase tracking-wide mb-0.5">
                Answer
              </div>
              <div className="text-foreground leading-relaxed whitespace-pre-wrap">
                {parsed.answer}
              </div>
            </div>
          )}
          {evidence.length > 0 && (
            <div>
              <div className="text-[10px] font-mono text-text-muted uppercase tracking-wide mb-1">
                Evidence ({evidence.length})
              </div>
              <ul className="space-y-1.5">
                {evidence.map((e, i) => (
                  <li
                    key={i}
                    className="font-mono text-[11px] leading-relaxed border-l-2 border-border-muted pl-2"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="px-1.5 py-0.5 rounded bg-surface-secondary text-foreground text-[10px] shrink-0">
                        {e.keyword}
                      </span>
                      <span className="text-text-muted">{e.path}</span>
                    </div>
                    <div className="text-foreground break-all whitespace-pre-wrap pl-1 mt-0.5">
                      &ldquo;{e.excerpt}&rdquo;
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {parsed.iocSummaries.length > 0 && (
            <div>
              <div className="text-[10px] font-mono text-text-muted uppercase tracking-wide mb-0.5">
                IOC rollups
              </div>
              <ul className="space-y-0.5 text-foreground">
                {parsed.iocSummaries.map((c, i) => (
                  <li key={i} className="leading-relaxed">
                    · {c}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {(lead.related_artifact_ids?.length ?? 0) > 0 && (
            <div>
              <div className="text-[10px] font-mono text-text-muted uppercase tracking-wide mb-0.5">
                Related artefacts
              </div>
              <div className="flex flex-wrap gap-1">
                {(lead.related_artifact_ids ?? []).slice(0, 8).map((id) => (
                  <span
                    key={id}
                    className="px-1.5 py-0.5 text-[10px] rounded bg-surface-secondary text-text-muted font-mono"
                    title={id}
                  >
                    {id.slice(0, 8)}
                  </span>
                ))}
                {(lead.related_artifact_ids?.length ?? 0) > 8 && (
                  <span className="text-text-muted text-[10px]">
                    +{(lead.related_artifact_ids?.length ?? 0) - 8} more
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const INITIAL_CAP = 25;

export function LeadScoreCard({ projectId }: { projectId: string }) {
  const { data: leads, isLoading } = useProjectLeads(projectId);
  const [showAll, setShowAll] = useState(false);

  if (isLoading) return <LoadingSkeleton size="md" width="full" />;

  const items = leads ?? [];
  const visible = showAll ? items : items.slice(0, INITIAL_CAP);
  const remaining = Math.max(0, items.length - visible.length);

  return (
    <div className="space-y-2">
      <div className="flex items-baseline gap-2">
        <h3 className="text-sm font-semibold text-foreground">Top Leads</h3>
        <span className="text-xs text-text-muted">
          {items.length === 0
            ? "none"
            : `${visible.length} of ${items.length}`}
        </span>
      </div>
      {items.length === 0 ? (
        <AilaCard  techBorder glow><p className="text-sm text-text-muted text-center py-4">
          No leads promoted yet. Leads are the investigator&apos;s own
          conclusions — run an investigation turn to populate this panel.
        </p></AilaCard>
      ) : (
        <>
          <div className="space-y-1.5">
            {visible.map((lead: PromotedLead) => (
              <LeadRow key={lead.id} lead={lead} />
            ))}
          </div>
          {remaining > 0 && (
            <button
              type="button"
              onClick={() => setShowAll(true)}
              className="w-full text-xs text-primary hover:underline py-2 border border-dashed border-border rounded-md"
            >
              Show {remaining} more lead{remaining === 1 ? "" : "s"}
            </button>
          )}
          {showAll && items.length > INITIAL_CAP && (
            <button
              type="button"
              onClick={() => setShowAll(false)}
              className="w-full text-xs text-text-muted hover:underline py-1"
            >
              Collapse to top {INITIAL_CAP}
            </button>
          )}
        </>
      )}
    </div>
  );
}
