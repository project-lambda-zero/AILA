import { useState } from "react";
import { useNavigate, useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import { useDeletePattern, usePatchPattern } from "../mutations";
import { usePattern } from "../queries";
import type {
  PatternConfidence,
  PatternScope,
  PatternStatus,
} from "../types";

const SCOPE_PROMOTION_ORDER: PatternScope[] = [
  "local",
  "workspace",
  "team",
  "global",
];

function nextScope(current: PatternScope): PatternScope | null {
  const idx = SCOPE_PROMOTION_ORDER.indexOf(current);
  return idx >= 0 && idx < SCOPE_PROMOTION_ORDER.length - 1
    ? SCOPE_PROMOTION_ORDER[idx + 1]
    : null;
}

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

  if (isLoading || !pattern) {
    return <LoadingSkeleton size="lg" width="full" />;
  }

  const promote = nextScope(pattern.scope);

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold font-mono text-foreground">
            {pattern.summary}
          </h1>
          <p className="text-sm text-text-muted mt-1 font-mono">
            {pattern.kind}
          </p>
        </div>
        <DeleteButton
          id={pid}
          label={`pattern "${pattern.summary.slice(0, 40)}"`}
          mutation={deleteMut}
          onDeleted={() => navigate("/vr/patterns")}
        />
      </div>

      <div className="flex gap-2 items-center flex-wrap">
        <AilaBadge
          severity={
            pattern.status === "active"
              ? "low"
              : pattern.status === "archived"
                ? "high"
                : "info"
          }
          size="sm"
        >
          status:{pattern.status}
        </AilaBadge>
        <AilaBadge
          severity={
            pattern.scope === "global"
              ? "critical"
              : pattern.scope === "team"
                ? "high"
                : pattern.scope === "workspace"
                  ? "medium"
                  : "info"
          }
          size="sm"
        >
          scope:{pattern.scope}
        </AilaBadge>
        <AilaBadge severity="info" size="sm">
          confidence:{pattern.confidence}
        </AilaBadge>
        <AilaBadge severity="info" size="sm">
          retrieved:{pattern.times_retrieved}
        </AilaBadge>
      </div>

      {/* Lifecycle actions */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        Review actions
      </h2>
      <div className="flex flex-wrap gap-2">
        {pattern.status === "draft" && (
          <button
            type="button"
            onClick={() => patchMut.mutate({ status: "active" })}
            disabled={patchMut.isPending}
            className="px-3 py-1.5 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50"
          >
            Approve (→ active)
          </button>
        )}
        {pattern.status !== "archived" && (
          <button
            type="button"
            onClick={() => patchMut.mutate({ status: "archived" })}
            disabled={patchMut.isPending}
            className="px-3 py-1.5 text-sm font-medium rounded-md bg-surface border border-border-default hover:bg-surface-hover disabled:opacity-50"
          >
            Archive
          </button>
        )}
        {pattern.status === "archived" && (
          <button
            type="button"
            onClick={() => patchMut.mutate({ status: "active" })}
            disabled={patchMut.isPending}
            className="px-3 py-1.5 text-sm font-medium rounded-md bg-surface border border-border-default hover:bg-surface-hover disabled:opacity-50"
          >
            Reactivate (→ active)
          </button>
        )}
        {promote && pattern.status === "active" && (
          <button
            type="button"
            onClick={() => patchMut.mutate({ scope: promote })}
            disabled={patchMut.isPending}
            className="px-3 py-1.5 text-sm font-medium rounded-md bg-accent/80 text-white hover:bg-accent/90 disabled:opacity-50"
          >
            Promote scope → {promote}
          </button>
        )}
      </div>
      <p className="text-xs text-text-muted mt-2">
        Scope promotion is one-way (demotion forbidden). Archive instead to
        demote.
      </p></AilaCard>

      {/* Body */}
      <AilaCard  techBorder glow><div className="flex items-center justify-between mb-2">
        <h2 className="text-sm font-semibold text-foreground">Body</h2>
        {!editMode ? (
          <button
            type="button"
            onClick={() => {
              setSummary(pattern.summary);
              setBody(pattern.body);
              setConfidence(pattern.confidence);
              setEditMode(true);
            }}
            className="text-xs px-2 py-1 rounded-md bg-surface border border-border-default hover:bg-surface-hover"
          >
            Edit
          </button>
        ) : (
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setEditMode(false)}
              className="text-xs px-2 py-1 rounded-md bg-surface border border-border-default"
            >
              Cancel
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
              className="text-xs px-3 py-1 rounded-md bg-accent text-white"
            >
              {patchMut.isPending ? "Saving…" : "Save"}
            </button>
          </div>
        )}
      </div>
      {editMode ? (
        <div className="space-y-2">
          <input
            value={summary}
            onChange={(e) => setSummary(e.target.value)}
            className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border-default"
            placeholder="One-sentence summary"
          />
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            rows={12}
            className="w-full px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border-default"
            placeholder="Full body with code/queries/output"
          />
          <select
            value={confidence}
            onChange={(e) => setConfidence(e.target.value as PatternConfidence)}
            className="px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default"
          >
            {(["exact", "strong", "medium", "caveated", "unknown"] as PatternConfidence[]).map(
              (c) => (
                <option key={c} value={c}>
                  confidence:{c}
                </option>
              ),
            )}
          </select>
        </div>
      ) : (
        <pre className="text-xs font-mono text-foreground whitespace-pre-wrap overflow-x-auto">
          {pattern.body || "(empty body)"}
        </pre>
      )}</AilaCard>

      {/* Applicability */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        Applicability
      </h2>
      <pre className="text-xs font-mono text-text-muted whitespace-pre-wrap">
        {JSON.stringify(pattern.applicability, null, 2)}
      </pre></AilaCard>

      {/* Evidence refs */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        Evidence refs ({pattern.evidence_refs.length})
      </h2>
      {pattern.evidence_refs.length > 0 ? (
        <ul className="text-xs font-mono text-text-muted space-y-1">
          {pattern.evidence_refs.map((ref) => (
            <li key={ref}>· {ref}</li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-text-muted">No evidence references.</p>
      )}</AilaCard>
    </div>
  );
}
