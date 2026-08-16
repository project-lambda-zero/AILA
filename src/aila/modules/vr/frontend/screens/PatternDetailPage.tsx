import { useState } from "react";
import { useNavigate, useParams } from "react-router";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { SectionHeader, MonoBadge } from "@/components/aila/mock";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

import { DeleteButton } from "../components/DeleteButton";
import { useDeletePattern, usePatchPattern } from "../mutations";
import { usePattern } from "../queries";
import type {
  PatternConfidence,
  PatternScope,
  PatternStatus,
} from "../types";

// ---------------------------------------------------------------------------
// Scope promotion ladder -- one-way (demotion forbidden). Archive to demote.
// ---------------------------------------------------------------------------
const SCOPE_PROMOTION_ORDER: PatternScope[] = [
  "local",
  "workspace",
  "team",
  "global",
];

const STATUS_TONE: Record<PatternStatus, string> = {
  draft: "warn",
  active: "ok",
  archived: "muted",
};

const SCOPE_TONE: Record<PatternScope, string> = {
  global: "critical",
  team: "warn",
  workspace: "info",
  local: "muted",
};

const CONFIDENCE_OPTIONS: PatternConfidence[] = [
  "exact",
  "strong",
  "medium",
  "caveated",
  "unknown",
];

// ---------------------------------------------------------------------------
// Reusable inline styles (mock CTRL input + action button).
// ---------------------------------------------------------------------------
function actionBtnStyle(primary: boolean, disabled = false): React.CSSProperties {
  return {
    height: 28,
    padding: "0 12px",
    fontSize: 10,
    letterSpacing: "0.08em",
    background: primary ? "var(--accent)" : "var(--surface-sunk)",
    border: `1px solid ${primary ? "var(--accent)" : "var(--border-soft)"}`,
    color: primary ? "var(--text-on-accent)" : "var(--text-primary)",
    borderRadius: 3,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.5 : 1,
  };
}

function ghostBtnStyle(disabled = false): React.CSSProperties {
  return {
    height: 26,
    padding: "0 10px",
    fontSize: 10,
    letterSpacing: "0.06em",
    background: "var(--surface-sunk)",
    border: "1px solid var(--border-soft)",
    color: "var(--text-primary)",
    borderRadius: 3,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.5 : 1,
  };
}

const CTRL_STYLE: React.CSSProperties = {
  height: 30,
  padding: "0 10px",
  fontSize: 12,
  letterSpacing: "0.02em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

const TEXTAREA_STYLE: React.CSSProperties = {
  width: "100%",
  padding: 10,
  fontSize: 12,
  lineHeight: 1.5,
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
  resize: "vertical",
};

const MONO_PRE_STYLE: React.CSSProperties = {
  padding: 12,
  fontSize: 11,
  lineHeight: 1.5,
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  overflow: "auto",
  maxHeight: 500,
  whiteSpace: "pre-wrap",
  margin: 0,
};

// ---------------------------------------------------------------------------
// PatternDetailPage
// ---------------------------------------------------------------------------
export function PatternDetailPage() {
  const { patternId } = useParams<{ patternId: string }>();
  const pid = patternId ?? "";
  const { data: pattern, isLoading } = usePattern(pid);
  const patchMut = usePatchPattern(pid);
  const deleteMut = useDeletePattern();
  const navigate = useNavigate();

  const [editMode, setEditMode] = useState(false);
  const [body, setBody] = useState("");
  const [summary, setSummary] = useState("");
  const [confidence, setConfidence] = useState<PatternConfidence>("medium");

  useUpdatePageHeader({
    title: pattern?.summary,
    subtitle: pattern?.kind,
    status: null,
  });

  if (isLoading || !pattern) {
    return (
      <WindowPanel title="pattern" tone="muted">
        <LoadingSkeleton size="lg" width="full" />
      </WindowPanel>
    );
  }

  const promoteIdx = SCOPE_PROMOTION_ORDER.indexOf(pattern.scope);
  const promote =
    promoteIdx >= 0 && promoteIdx < SCOPE_PROMOTION_ORDER.length - 1
      ? SCOPE_PROMOTION_ORDER[promoteIdx + 1]
      : null;

  const headerActions = (
    <DeleteButton
      id={pid}
      label={`pattern "${pattern.summary.slice(0, 40)}"`}
      mutation={deleteMut}
      onDeleted={() => navigate("/vr/patterns")}
    />
  );

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader
        icon="\u25c8"
        title={pattern.summary || "(untitled pattern)"}
        actions={headerActions}
      />

      {/* Chip row -- status / scope / confidence / retrieved */}
      <div className="flex items-center" style={{ gap: 8, flexWrap: "wrap" }}>
        <MonoBadge tone={STATUS_TONE[pattern.status] ?? "muted"}>
          status:{pattern.status}
        </MonoBadge>
        <MonoBadge tone={SCOPE_TONE[pattern.scope] ?? "muted"}>
          scope:{pattern.scope}
        </MonoBadge>
        <MonoBadge tone="info">confidence:{pattern.confidence}</MonoBadge>
        <MonoBadge tone="muted">
          retrieved:{pattern.times_retrieved}
        </MonoBadge>
      </div>

      {/* Review actions */}
      <WindowPanel title="review actions" tone="accent">
        <div className="flex" style={{ gap: 8, flexWrap: "wrap" }}>
          {pattern.status === "draft" ? (
            <button
              type="button"
              onClick={() => patchMut.mutate({ status: "active" })}
              disabled={patchMut.isPending}
              className="font-mono uppercase"
              style={actionBtnStyle(true, patchMut.isPending)}
            >
              approve {"\u2192"} active
            </button>
          ) : null}
          {pattern.status !== "archived" ? (
            <button
              type="button"
              onClick={() => patchMut.mutate({ status: "archived" })}
              disabled={patchMut.isPending}
              className="font-mono uppercase"
              style={actionBtnStyle(false, patchMut.isPending)}
            >
              archive
            </button>
          ) : null}
          {pattern.status === "archived" ? (
            <button
              type="button"
              onClick={() => patchMut.mutate({ status: "active" })}
              disabled={patchMut.isPending}
              className="font-mono uppercase"
              style={actionBtnStyle(false, patchMut.isPending)}
            >
              reactivate {"\u2192"} active
            </button>
          ) : null}
          {promote && pattern.status === "active" ? (
            <button
              type="button"
              onClick={() => patchMut.mutate({ scope: promote })}
              disabled={patchMut.isPending}
              className="font-mono uppercase"
              style={actionBtnStyle(true, patchMut.isPending)}
            >
              promote scope {"\u2192"} {promote}
            </button>
          ) : null}
        </div>
        <p
          className="font-mono"
          style={{
            marginTop: 10,
            fontSize: 10,
            color: "var(--text-faint)",
            letterSpacing: "0.02em",
            lineHeight: 1.5,
          }}
        >
          scope promotion is one-way (demotion forbidden). archive instead
          to demote.
        </p>
      </WindowPanel>

      {/* Body */}
      <WindowPanel
        title="body"
        tone="info"
        actions={
          !editMode ? (
            <button
              type="button"
              onClick={() => {
                setSummary(pattern.summary);
                setBody(pattern.body);
                setConfidence(pattern.confidence);
                setEditMode(true);
              }}
              className="font-mono uppercase"
              style={ghostBtnStyle()}
            >
              edit
            </button>
          ) : (
            <div className="flex" style={{ gap: 6 }}>
              <button
                type="button"
                onClick={() => setEditMode(false)}
                className="font-mono uppercase"
                style={ghostBtnStyle()}
              >
                cancel
              </button>
              <button
                type="button"
                disabled={patchMut.isPending}
                onClick={() => {
                  patchMut.mutate(
                    { summary, body, confidence },
                    { onSuccess: () => setEditMode(false) },
                  );
                }}
                className="font-mono uppercase"
                style={actionBtnStyle(true, patchMut.isPending)}
              >
                {patchMut.isPending ? "saving\u2026" : "save"}
              </button>
            </div>
          )
        }
      >
        {editMode ? (
          <div className="flex flex-col" style={{ gap: 8 }}>
            <input
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              aria-label="Pattern summary"
              placeholder="One-sentence summary"
              style={{ ...CTRL_STYLE, width: "100%" }}
            />
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={14}
              aria-label="Pattern body"
              placeholder="Full body with code / queries / output"
              style={TEXTAREA_STYLE}
            />
            <select
              value={confidence}
              onChange={(e) =>
                setConfidence(e.target.value as PatternConfidence)
              }
              aria-label="Pattern confidence"
              style={{ ...CTRL_STYLE, width: 220 }}
            >
              {CONFIDENCE_OPTIONS.map((c) => (
                <option key={c} value={c}>
                  confidence:{c}
                </option>
              ))}
            </select>
          </div>
        ) : (
          <pre className="font-mono" style={MONO_PRE_STYLE}>
            {pattern.body || "(empty body)"}
          </pre>
        )}
      </WindowPanel>

      {/* Applicability */}
      <WindowPanel title="applicability" tone="muted">
        <pre
          className="font-mono"
          style={{
            ...MONO_PRE_STYLE,
            color: "var(--text-muted)",
            maxHeight: 300,
          }}
        >
          {JSON.stringify(pattern.applicability, null, 2)}
        </pre>
      </WindowPanel>

      {/* Evidence refs */}
      <WindowPanel
        title={`evidence refs (${pattern.evidence_refs.length})`}
        tone="warn"
      >
        {pattern.evidence_refs.length > 0 ? (
          <ul
            className="font-mono"
            style={{
              margin: 0,
              padding: 0,
              listStyle: "none",
              display: "flex",
              flexDirection: "column",
            }}
          >
            {pattern.evidence_refs.map((ref) => (
              <li
                key={ref}
                style={{
                  padding: "6px 10px",
                  fontSize: 11,
                  color: "var(--text-muted)",
                  borderBottom: "1px solid var(--border-faint)",
                  overflowWrap: "anywhere",
                }}
              >
                {"\u00b7 "}{ref}
              </li>
            ))}
          </ul>
        ) : (
          <p
            className="font-mono"
            style={{
              margin: 0,
              padding: "6px 0",
              fontSize: 11,
              color: "var(--text-muted)",
            }}
          >
            no evidence references.
          </p>
        )}
      </WindowPanel>
    </div>
  );
}
