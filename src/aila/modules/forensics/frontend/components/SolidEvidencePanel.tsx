import { useNavigate } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { DataGrid, MonoBadge } from "@/components/aila/mock";

import { useUntagSolidEvidence } from "../mutations";
import { useSolidEvidence } from "../queries";
import type { SolidEvidence } from "../types";

interface Props {
  projectId: string;
}

function formatStamp(iso: string): string {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    })}`;
  } catch {
    return iso;
  }
}

export function SolidEvidencePanel({ projectId }: Props) {
  const navigate = useNavigate();
  const { data, isLoading, isError } = useSolidEvidence(projectId);
  const untag = useUntagSolidEvidence(projectId);

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;
  if (isError) {
    return (
      <WindowPanel
        title="solid evidence"
        tone="warn"
        status="forensics ; unavailable"
      >
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--accent)" }}
        >
          Failed to load solid evidence.
        </p>
      </WindowPanel>
    );
  }

  const rows: SolidEvidence[] = data ?? [];

  if (rows.length === 0) {
    return (
      <WindowPanel
        title="solid evidence"
        tone="muted"
        status="forensics ; no tagged findings"
      >
        <div className="space-y-2">
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            no analyst-tagged findings yet.
          </p>
          <p
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-faint)", lineHeight: 1.6 }}
          >
            open a completed investigation and hit the{" "}
            <span style={{ color: "var(--status-ok)" }}>Tag as TRUE</span> or{" "}
            <span style={{ color: "var(--status-warn)" }}>Tag as FALSE</span>{" "}
            button to promote its answer to solid evidence. tagged findings are
            injected into every future investigation's prompt so the agent
            treats them as ground truth / known dead-ends.
          </p>
        </div>
      </WindowPanel>
    );
  }

  const trueCount = rows.filter((r) => r.verdict === "true").length;
  const falseCount = rows.length - trueCount;

  const handleUntag = (id: string) => {
    if (
      !window.confirm(
        "Remove this row from Solid Evidence? Its linked directive will also be deactivated.",
      )
    )
      return;
    untag.mutate(id);
  };

  const openSourceInvestigation = (e: SolidEvidence) => {
    if (!e.source_investigation_id) return;
    navigate(
      `/forensics/projects/${projectId}/investigations/${e.source_investigation_id}`,
    );
  };

  return (
    <WindowPanel
      title="solid evidence"
      status={`total ${rows.length} ; true ${trueCount} ; false ${falseCount}`}
    >
      <DataGrid<SolidEvidence>
        columns={[
          { label: "VERDICT", width: "80px" },
          { label: "ANSWER", width: "2fr" },
          { label: "QUESTION", width: "2fr" },
          { label: "INVESTIGATION", width: "110px" },
          { label: "STAMP", width: "150px" },
          { label: "", width: "110px", align: "right" },
        ]}
        rows={rows}
        getKey={(r) => r.id}
        renderCells={(r) => [
          <MonoBadge key="v" tone={r.verdict === "true" ? "ok" : "warn"}>
            {r.verdict}
          </MonoBadge>,
          <span
            key="a"
            title={r.answer}
            className="truncate"
            style={{
              fontSize: 11,
              color: "var(--text-primary)",
              display: "block",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {r.answer}
          </span>,
          <span
            key="q"
            title={r.question}
            className="truncate"
            style={{
              fontSize: 11,
              color: "var(--text-muted)",
              display: "block",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {r.question}
          </span>,
          r.source_investigation_id ? (
            <button
              key="inv"
              type="button"
              onClick={() => openSourceInvestigation(r)}
              className="font-mono"
              style={{
                background: "transparent",
                border: 0,
                padding: 0,
                cursor: "pointer",
                fontSize: 10,
                color: "var(--accent)",
                textDecoration: "underline",
                textAlign: "left",
              }}
            >
              {`${r.source_investigation_id.slice(0, 8)}\u2026`}
            </button>
          ) : (
            <span
              key="inv"
              style={{ fontSize: 10, color: "var(--text-faint)" }}
            >
              --
            </span>
          ),
          <span
            key="ts"
            style={{ fontSize: 10, color: "var(--text-faint)" }}
          >
            {formatStamp(r.tagged_at)}
          </span>,
          <button
            key="untag"
            type="button"
            onClick={() => handleUntag(r.id)}
            disabled={untag.isPending}
            className="font-mono uppercase"
            style={{
              height: 22,
              padding: "0 10px",
              fontSize: 9,
              letterSpacing: "0.1em",
              color: "var(--text-muted)",
              background: "transparent",
              border: "1px solid var(--border-soft)",
              borderRadius: 3,
              cursor: untag.isPending ? "wait" : "pointer",
              opacity: untag.isPending ? 0.6 : 1,
            }}
          >
            Untag
          </button>,
        ]}
      />
    </WindowPanel>
  );
}
