import { useMemo, useState } from "react";

import { WindowPanel } from "@/components/aila/WindowPanel";

import { useProjectEvidence } from "../queries";
import { useFetchRaw } from "../mutations";
import type { EvidenceItem } from "../types";

interface Props {
  projectId: string;
  /** Compact mode for the dashboard (smaller heading, tighter form). */
  compact?: boolean;
}

const SELECT_STYLE: React.CSSProperties = {
  width: "100%",
  height: 28,
  padding: "0 10px",
  fontSize: 11,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

const ACCENT_BTN: React.CSSProperties = {
  height: 26,
  padding: "0 12px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-on-accent)",
  background: "var(--accent)",
  border: "1px solid var(--accent)",
  borderRadius: 3,
  cursor: "pointer",
  boxShadow: "var(--bevel-key)",
};

/**
 * Fetch-Raw panel -- for ``project_kind === "raw_directory"`` projects.
 * Picks one evidence row (file or directory as recorded during intake)
 * and streams it back; directories are zipped on the analyzer before
 * they ship.
 */
export function FetchRawFilePanel({ projectId, compact = false }: Props) {
  const evidenceQ = useProjectEvidence(projectId);
  const fetchMut = useFetchRaw(projectId);

  const items: EvidenceItem[] = useMemo(
    () => evidenceQ.data ?? [],
    [evidenceQ.data],
  );

  const [evidenceId, setEvidenceId] = useState<string>("");

  const selected = items.find((i) => i.id === evidenceId) ?? null;
  const canSubmit = !!evidenceId && !fetchMut.isPending;

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    await fetchMut.mutateAsync({ evidence_id: evidenceId });
  };

  const title = compact ? "fetch raw file" : "fetch file from raw directory";

  return (
    <WindowPanel
      title={title}
      status={`raw ; ${items.length} file${items.length === 1 ? "" : "s"} catalogued`}
    >
      <form onSubmit={onSubmit} className="space-y-2">
        <select
          aria-label="Select evidence source"
          value={evidenceId}
          onChange={(e) => setEvidenceId(e.target.value)}
          disabled={fetchMut.isPending || items.length === 0}
          className="font-mono"
          style={SELECT_STYLE}
        >
          <option value="">
            {items.length === 0
              ? "-- no files catalogued --"
              : "-- pick a file or directory --"}
          </option>
          {items.map((f) => (
            <option key={f.id} value={f.id}>
              {f.file_path} [{f.evidence_type}]
              {f.size_bytes != null ? ` (${f.size_bytes} B)` : ""}
            </option>
          ))}
        </select>

        <div
          className="flex items-center justify-between"
          style={{ gap: 8 }}
        >
          <p
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-faint)", lineHeight: 1.5 }}
          >
            Directories are zipped on the analyzer and shipped as{" "}
            <code
              className="font-mono"
              style={{
                padding: "1px 4px",
                background: "var(--surface-sunk)",
                border: "1px solid var(--border-faint)",
                borderRadius: 2,
                color: "var(--text-primary)",
              }}
            >
              &lt;name&gt;.zip
            </code>
            .{selected ? ` Selected: ${selected.evidence_type}.` : ""}
          </p>
          <button
            type="submit"
            disabled={!canSubmit}
            className="font-mono uppercase"
            style={{
              ...ACCENT_BTN,
              opacity: canSubmit ? 1 : 0.5,
              cursor: canSubmit ? "pointer" : "not-allowed",
            }}
          >
            {fetchMut.isPending ? "fetching\u2026" : "fetch"}
          </button>
        </div>
      </form>

      {evidenceQ.isError && (
        <p
          className="font-mono"
          style={{
            fontSize: 10.5,
            color: "var(--accent)",
            marginTop: 8,
          }}
        >
          Failed to load evidence list.
        </p>
      )}
      {!evidenceQ.isLoading && items.length === 0 && (
        <p
          className="font-mono"
          style={{
            fontSize: 10.5,
            color: "var(--text-faint)",
            marginTop: 8,
          }}
        >
          No files catalogued yet -- wait for intake to complete or re-run
          readiness.
        </p>
      )}
    </WindowPanel>
  );
}
