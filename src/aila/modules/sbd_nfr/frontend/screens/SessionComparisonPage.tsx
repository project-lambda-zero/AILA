import React from "react";
import { Link, useSearchParams } from "react-router";

import { AilaBadge } from "@/components/aila";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

import { useWizardResolution, useWizardSessionDetail, useWizardSessionList } from "../queries";
import type { ComponentClassificationResponse } from "../types";

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString("en-GB", {
      day: "numeric",
      month: "short",
      year: "numeric",
    });
  } catch {
    return iso;
  }
}

type MatchKind = "match" | "both_na" | "mismatch" | "uncertain" | "absent";

interface ComparisonRow {
  subtaskKey: string;
  subtaskLabel: string;
  classificationA: string | null;
  classificationB: string | null;
  matchKind: MatchKind;
}

function matchKind(a: string | null, b: string | null): MatchKind {
  if (a === null || b === null) return "absent";
  if (a === "uncertain" || b === "uncertain") return "uncertain";
  if (a === "triggered" && b === "triggered") return "match";
  if (a === "not_triggered" && b === "not_triggered") return "both_na";
  return "mismatch";
}

const MATCH_ORDER: Record<MatchKind, number> = {
  mismatch: 0,
  uncertain: 1,
  match: 2,
  both_na: 3,
  absent: 4,
};

function classificationLabel(c: string | null): string {
  if (c === "triggered") return "Triggered";
  if (c === "uncertain") return "Uncertain";
  if (c === "not_triggered") return "Not Applicable";
  if (c === null) return "—";
  return c;
}

function classificationColor(c: string | null): string {
  if (c === "triggered") return "text-high";
  if (c === "uncertain") return "text-medium";
  return "text-text-muted";
}

function MatchPill({ kind }: { kind: MatchKind }) {
  if (kind === "match")
    return <span className="compare-match compare-match--ok">Match</span>;
  if (kind === "both_na")
    return <span className="compare-match compare-match--na">Both N/A</span>;
  if (kind === "mismatch")
    return <span className="compare-match compare-match--diff">Mismatch</span>;
  if (kind === "uncertain")
    return <span className="compare-match compare-match--uncertain">~</span>;
  return <span className="compare-match compare-match--absent">–</span>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Session selector (shown when ?a= or ?b= absent)
// ──────────────────────────────────────────────────────────────────────────────

interface SessionSelectorProps {
  onSelect: (idA: string, idB: string) => void;
}

function SessionSelector({ onSelect }: SessionSelectorProps) {
  const listQuery = useWizardSessionList();
  const [idA, setIdA] = React.useState("");
  const [idB, setIdB] = React.useState("");

  const sessions = listQuery.data ?? [];

  function handleCompare() {
    if (idA && idB && idA !== idB) onSelect(idA, idB);
  }

  return (
    <div className="compare-selector">
      <h2 className="compare-selector__title">Compare Assessments</h2>
      <p className="compare-selector__hint">Select two assessed sessions to compare their component classifications.</p>

      {listQuery.isLoading && (
        <p className="compare-selector__loading">Loading sessions...</p>
      )}

      <div className="compare-selector__row">
        <div className="compare-selector__field">
          <label htmlFor="compare-a" className="compare-selector__label">Session A</label>
          <select
            id="compare-a"
            className="compare-selector__select"
            value={idA}
            onChange={(e) => setIdA(e.target.value)}
          >
            <option value="">— Select session —</option>
            {sessions.map((s) => (
              <option key={s.id} value={s.id}>{s.project_name}</option>
            ))}
          </select>
        </div>

        <div className="compare-selector__field">
          <label htmlFor="compare-b" className="compare-selector__label">Session B</label>
          <select
            id="compare-b"
            className="compare-selector__select"
            value={idB}
            onChange={(e) => setIdB(e.target.value)}
          >
            <option value="">— Select session —</option>
            {sessions.map((s) => (
              <option key={s.id} value={s.id}>{s.project_name}</option>
            ))}
          </select>
        </div>
      </div>

      {idA && idB && idA === idB && (
        <p className="text-sm text-critical">Select two different sessions.</p>
      )}

      <Button
        type="button"
        disabled={!idA || !idB || idA === idB}
        onClick={handleCompare}
      >
        Compare
      </Button>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Answer diff section
// ──────────────────────────────────────────────────────────────────────────────

interface AnswerDiffProps {
  answersA: Array<{ question_id: string; answer_value: string }>;
  answersB: Array<{ question_id: string; answer_value: string }>;
}

function AnswerDiff({ answersA, answersB }: AnswerDiffProps) {
  const mapA = new Map(answersA.map((a) => [a.question_id, a.answer_value]));
  const mapB = new Map(answersB.map((a) => [a.question_id, a.answer_value]));

  const allIds = Array.from(new Set([...mapA.keys(), ...mapB.keys()]));
  const diffs = allIds.filter((id) => mapA.get(id) !== mapB.get(id));

  if (diffs.length === 0) {
    return <p className="compare-diff__empty">No answer differences found.</p>;
  }

  return (
    <table className="compare-diff-table">
      <thead>
        <tr>
          <th className="compare-diff-table__head">Question</th>
          <th className="compare-diff-table__head">Session A</th>
          <th className="compare-diff-table__head">Session B</th>
        </tr>
      </thead>
      <tbody>
        {diffs.map((id) => (
          <tr key={id} className="compare-diff-table__row">
            <td className="compare-diff-table__cell compare-diff-table__cell--id">{id}</td>
            <td className="compare-diff-table__cell">{mapA.get(id) ?? "—"}</td>
            <td className="compare-diff-table__cell">{mapB.get(id) ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Main comparison view
// ──────────────────────────────────────────────────────────────────────────────

interface ComparisonViewProps {
  sessionIdA: string;
  sessionIdB: string;
}

function ComparisonView({ sessionIdA, sessionIdB }: ComparisonViewProps) {
  const sessionAQuery = useWizardSessionDetail(sessionIdA);
  const sessionBQuery = useWizardSessionDetail(sessionIdB);
  const resolutionAQuery = useWizardResolution(sessionIdA);
  const resolutionBQuery = useWizardResolution(sessionIdB);

  const [showDiff, setShowDiff] = React.useState(false);

  const isLoading =
    sessionAQuery.isLoading ||
    sessionBQuery.isLoading ||
    resolutionAQuery.isLoading ||
    resolutionBQuery.isLoading;

  if (isLoading) {
    return (
      <div className="compare-page">
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="animate-pulse bg-surface rounded-md" style={{ height: 48, marginBottom: 8 }} />
        ))}
      </div>
    );
  }

  const sessionA = sessionAQuery.data?.session;
  const sessionB = sessionBQuery.data?.session;
  const resA = resolutionAQuery.data;
  const resB = resolutionBQuery.data;

  if (!sessionA || !sessionB) {
    return (
      <div className="compare-page compare-page--error">
        <p className="text-sm text-critical">Failed to load one or both sessions.</p>
        <Link className={cn(buttonVariants({ variant: "outline" }))} to="/assessments">Back to Assessments</Link>
      </div>
    );
  }

  // Build comparison rows from union of component keys
  const compMapA = new Map<string, ComponentClassificationResponse>(
    (resA?.components ?? []).map((c) => [c.subtask_key, c]),
  );
  const compMapB = new Map<string, ComponentClassificationResponse>(
    (resB?.components ?? []).map((c) => [c.subtask_key, c]),
  );
  const allKeys = Array.from(
    new Set([...compMapA.keys(), ...compMapB.keys()]),
  );

  const rows: ComparisonRow[] = allKeys.map((key) => {
    const cA = compMapA.get(key) ?? null;
    const cB = compMapB.get(key) ?? null;
    return {
      subtaskKey: key,
      subtaskLabel: cA?.subtask_label ?? cB?.subtask_label ?? key,
      classificationA: cA?.classification ?? null,
      classificationB: cB?.classification ?? null,
      matchKind: matchKind(cA?.classification ?? null, cB?.classification ?? null),
    };
  });

  rows.sort((a, b) => MATCH_ORDER[a.matchKind] - MATCH_ORDER[b.matchKind]);

  const answersA = sessionAQuery.data?.answers ?? [];
  const answersB = sessionBQuery.data?.answers ?? [];

  return (
    <div className="compare-page">
      {/* Header */}
      <div className="compare-page__header">
        <div className="compare-page__header-col">
          <h2 className="compare-page__project">{sessionA.project_name}</h2>
          <p className="compare-page__meta">
            {sessionA.requestor_name}
            {sessionA.business_unit ? ` · ${sessionA.business_unit}` : ""}
          </p>
          <p className="compare-page__date">Updated {formatDate(sessionA.updated_at)}</p>
        </div>
        <div className="compare-page__vs" aria-hidden>vs</div>
        <div className="compare-page__header-col compare-page__header-col--right">
          <h2 className="compare-page__project">{sessionB.project_name}</h2>
          <p className="compare-page__meta">
            {sessionB.requestor_name}
            {sessionB.business_unit ? ` · ${sessionB.business_unit}` : ""}
          </p>
          <p className="compare-page__date">Updated {formatDate(sessionB.updated_at)}</p>
        </div>
      </div>

      <div className="compare-page__actions">
        <Link className={cn(buttonVariants({ variant: "outline" }))} to="/assessments">All Assessments</Link>
        <Link
          className={cn(buttonVariants({ variant: "outline" }))}
          to={`/assessments/compare`}
        >
          New Comparison
        </Link>
      </div>

      {/* Component grid */}
      {rows.length === 0 ? (
        <p className="compare-page__empty">No resolution data available for these sessions.</p>
      ) : (
        <table className="compare-grid">
          <thead>
            <tr className="compare-grid__head-row">
              <th className="compare-grid__th">Component</th>
              <th className="compare-grid__th">{sessionA.project_name}</th>
              <th className="compare-grid__th">{sessionB.project_name}</th>
              <th className="compare-grid__th">Match</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.subtaskKey} className={`compare-grid__row compare-grid__row--${row.matchKind}`}>
                <td className="compare-grid__td compare-grid__td--label">{row.subtaskLabel}</td>
                <td
                  className={cn("compare-grid__td", classificationColor(row.classificationA))}
                >
                  {classificationLabel(row.classificationA)}
                </td>
                <td
                  className={cn("compare-grid__td", classificationColor(row.classificationB))}
                >
                  {classificationLabel(row.classificationB)}
                </td>
                <td className="compare-grid__td">
                  <MatchPill kind={row.matchKind} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* Answer diff toggle */}
      <div className="compare-page__diff-section">
        <Button
          type="button"
          variant="outline"
          onClick={() => setShowDiff((v) => !v)}
          aria-expanded={showDiff}
        >
          {showDiff ? "Hide answer differences" : "Show answer differences"}
        </Button>

        {showDiff && (
          <div className="compare-diff">
            <AnswerDiff answersA={answersA} answersB={answersB} />
          </div>
        )}
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// SessionComparisonPage
// ──────────────────────────────────────────────────────────────────────────────

export function SessionComparisonPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const sessionIdA = searchParams.get("a") ?? "";
  const sessionIdB = searchParams.get("b") ?? "";

  function handleSelect(idA: string, idB: string) {
    setSearchParams({ a: idA, b: idB });
  }

  if (!sessionIdA || !sessionIdB) {
    return <SessionSelector onSelect={handleSelect} />;
  }

  return <ComparisonView sessionIdA={sessionIdA} sessionIdB={sessionIdB} />;
}
