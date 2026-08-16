import { useMemo, useState } from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge } from "@/components/aila/mock";

import { useProjectLeads } from "../queries";
import type { PromotedLead } from "../types";

function scoreTone(score: number): string {
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
      headline = `${headline} \u00b7 ${clause}`;
    } else {
      meta.push(clause);
    }
  }

  return { headline, meta, question, answer, iocSummaries };
}

const SECTION_LABEL: React.CSSProperties = {
  fontSize: 9,
  letterSpacing: "0.14em",
  color: "var(--text-faint)",
  marginBottom: 3,
};

const META_CHIP: React.CSSProperties = {
  padding: "2px 6px",
  fontSize: 9.5,
  borderRadius: 2,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-faint)",
  color: "var(--text-faint)",
};

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

  const tone = scoreTone(lead.score);

  return (
    <div
      style={{
        border: "1px solid var(--border-soft)",
        background: "var(--surface-card)",
        borderRadius: 3,
        overflow: "hidden",
      }}
    >
      <div style={{ padding: "10px 12px" }} className="space-y-1.5">
        {/* Header row: score - bucket - type */}
        <div className="flex items-center" style={{ gap: 8 }}>
          <MonoBadge tone={tone}>{lead.score.toFixed(0)}</MonoBadge>
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.1em",
              color: "var(--text-muted)",
            }}
          >
            {scoreBucket(lead.score)}
          </span>
          <span
            className="font-mono ml-auto shrink-0"
            style={{ fontSize: 9.5, color: "var(--text-faint)" }}
          >
            {typeLabel}
          </span>
          {lead.source_tool && (
            <span
              className="font-mono shrink-0"
              style={{ fontSize: 9, color: "var(--text-faint)" }}
            >
              via {lead.source_tool}
            </span>
          )}
        </div>

        {/* Full multi-line headline -- NOT truncated. */}
        <div
          className="font-mono whitespace-pre-wrap"
          style={{
            fontSize: 11,
            color: "var(--text-primary)",
            lineHeight: 1.55,
          }}
        >
          {parsed.headline}
        </div>

        {/* Meta chips */}
        {parsed.meta.length > 0 && (
          <div className="flex flex-wrap" style={{ gap: 4, paddingTop: 2 }}>
            {parsed.meta.map((m, i) => (
              // eslint-disable-next-line react/no-array-index-key
              <span key={i} className="font-mono" style={META_CHIP}>
                {m}
              </span>
            ))}
          </div>
        )}

        {expandable && (
          <button
            type="button"
            onClick={() => setOpen((p) => !p)}
            className="font-mono uppercase"
            aria-expanded={open}
            style={{
              padding: "2px 0",
              fontSize: 9.5,
              letterSpacing: "0.08em",
              color: "var(--accent)",
              background: "transparent",
              border: 0,
              cursor: "pointer",
              textAlign: "left",
            }}
          >
            {open ? "hide details \u25be" : "show details \u25b8"}
          </button>
        )}
      </div>

      {open && expandable && (
        <div
          className="space-y-2"
          style={{
            borderTop: "1px solid var(--border-faint)",
            background: "var(--surface-sunk)",
            padding: "10px 12px",
          }}
        >
          {parsed.question && (
            <div>
              <div className="font-mono uppercase" style={SECTION_LABEL}>
                Question
              </div>
              <div
                className="font-mono whitespace-pre-wrap"
                style={{
                  fontSize: 11,
                  color: "var(--text-primary)",
                  lineHeight: 1.55,
                }}
              >
                {parsed.question}
              </div>
            </div>
          )}
          {parsed.answer && (
            <div>
              <div className="font-mono uppercase" style={SECTION_LABEL}>
                Answer
              </div>
              <div
                className="font-mono whitespace-pre-wrap"
                style={{
                  fontSize: 11,
                  color: "var(--text-primary)",
                  lineHeight: 1.55,
                }}
              >
                {parsed.answer}
              </div>
            </div>
          )}
          {evidence.length > 0 && (
            <div>
              <div className="font-mono uppercase" style={SECTION_LABEL}>
                Evidence ({evidence.length})
              </div>
              <ul className="space-y-1.5">
                {evidence.map((e, i) => (
                  <li
                    // eslint-disable-next-line react/no-array-index-key
                    key={i}
                    className="font-mono"
                    style={{
                      fontSize: 9.5,
                      borderLeft: "2px solid var(--border-faint)",
                      paddingLeft: 8,
                      lineHeight: 1.55,
                    }}
                  >
                    <div
                      className="flex flex-wrap items-center"
                      style={{ gap: 6 }}
                    >
                      <span
                        className="font-mono shrink-0"
                        style={{
                          ...META_CHIP,
                          color: "var(--text-primary)",
                        }}
                      >
                        {e.keyword}
                      </span>
                      <span style={{ color: "var(--text-faint)" }}>
                        {e.path}
                      </span>
                    </div>
                    <div
                      className="break-all whitespace-pre-wrap"
                      style={{
                        color: "var(--text-primary)",
                        paddingLeft: 4,
                        marginTop: 3,
                      }}
                    >
                      &ldquo;{e.excerpt}&rdquo;
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {parsed.iocSummaries.length > 0 && (
            <div>
              <div className="font-mono uppercase" style={SECTION_LABEL}>
                IOC rollups
              </div>
              <ul
                className="font-mono space-y-0.5"
                style={{
                  fontSize: 10.5,
                  color: "var(--text-primary)",
                  lineHeight: 1.55,
                }}
              >
                {parsed.iocSummaries.map((c, i) => (
                  // eslint-disable-next-line react/no-array-index-key
                  <li key={i}>{"\u00b7"} {c}</li>
                ))}
              </ul>
            </div>
          )}
          {(lead.related_artifact_ids?.length ?? 0) > 0 && (
            <div>
              <div className="font-mono uppercase" style={SECTION_LABEL}>
                Related artefacts
              </div>
              <div className="flex flex-wrap" style={{ gap: 4 }}>
                {(lead.related_artifact_ids ?? []).slice(0, 8).map((id) => (
                  <span
                    key={id}
                    className="font-mono"
                    style={META_CHIP}
                    title={id}
                  >
                    {id.slice(0, 8)}
                  </span>
                ))}
                {(lead.related_artifact_ids?.length ?? 0) > 8 && (
                  <span
                    className="font-mono"
                    style={{ fontSize: 9.5, color: "var(--text-faint)" }}
                  >
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
      <div className="flex items-baseline" style={{ gap: 8 }}>
        <h3
          className="font-mono uppercase"
          style={{
            fontSize: 10,
            letterSpacing: "0.14em",
            color: "var(--text-primary)",
          }}
        >
          top leads
        </h3>
        <span
          className="font-mono"
          style={{ fontSize: 10, color: "var(--text-faint)" }}
        >
          {items.length === 0
            ? "none"
            : `${visible.length} of ${items.length}`}
        </span>
      </div>
      {items.length === 0 ? (
        <WindowPanel tone="muted" status="forensics ; no leads promoted">
          <p
            className="font-mono"
            style={{
              fontSize: 11,
              color: "var(--text-muted)",
              textAlign: "center",
              padding: "16px 0",
            }}
          >
            No leads promoted yet. Leads are the investigator&apos;s own
            conclusions -- run an investigation turn to populate this panel.
          </p>
        </WindowPanel>
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
              className="w-full font-mono uppercase"
              style={{
                padding: "8px 0",
                fontSize: 10,
                letterSpacing: "0.08em",
                color: "var(--accent)",
                background: "transparent",
                border: "1px dashed var(--border-soft)",
                borderRadius: 3,
                cursor: "pointer",
              }}
            >
              show {remaining} more lead{remaining === 1 ? "" : "s"}
            </button>
          )}
          {showAll && items.length > INITIAL_CAP && (
            <button
              type="button"
              onClick={() => setShowAll(false)}
              className="w-full font-mono uppercase"
              style={{
                padding: "4px 0",
                fontSize: 9.5,
                letterSpacing: "0.08em",
                color: "var(--text-muted)",
                background: "transparent",
                border: 0,
                cursor: "pointer",
              }}
            >
              collapse to top {INITIAL_CAP}
            </button>
          )}
        </>
      )}
    </div>
  );
}
