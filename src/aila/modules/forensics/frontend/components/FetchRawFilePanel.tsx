import { useMemo, useState } from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import { Button } from "@/components/ui/button";

import { useProjectEvidence } from "../queries";
import { useFetchRaw } from "../mutations";
import type { EvidenceItem } from "../types";

interface Props {
  projectId: string;
  /** Compact mode for the dashboard (smaller heading, tighter form). */
  compact?: boolean;
}

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

  const heading = compact ? "Fetch Raw File" : "Fetch File from Raw Directory";

  return (
    <AilaCard  techBorder glow><div className="flex items-center justify-between mb-3">
      <h3 className="text-sm font-semibold text-foreground">{heading}</h3>
      <span className="text-xs text-text-muted">
        {items.length} file{items.length === 1 ? "" : "s"} catalogued
      </span>
    </div>
    
    <form onSubmit={onSubmit} className="space-y-2">
      <select
        aria-label="Select evidence source"
        value={evidenceId}
        onChange={(e) => setEvidenceId(e.target.value)}
        disabled={fetchMut.isPending || items.length === 0}
        className="w-full text-xs border border-border rounded px-2 py-1 bg-background font-mono"
      >
        <option value="">
          {items.length === 0 ? "-- no files catalogued --" : "-- pick a file or directory --"}
        </option>
        {items.map((f) => (
          <option key={f.id} value={f.id}>
            {f.file_path} [{f.evidence_type}]
            {f.size_bytes != null ? ` (${f.size_bytes} B)` : ""}
          </option>
        ))}
      </select>
    
      <div className="flex items-center justify-between gap-2">
        <p className="text-2xs text-text-muted">
          Directories are zipped on the analyzer and shipped as
          <code className="font-mono mx-1">&lt;name&gt;.zip</code>.
          {selected ? ` Selected: ${selected.evidence_type}.` : ""}
        </p>
        <Button type="submit" size="sm" disabled={!canSubmit}>
          {fetchMut.isPending ? "Fetching…" : "Fetch"}
        </Button>
      </div>
    </form>
    
    {evidenceQ.isError && (
      <p className="text-xs text-status-critical mt-2">
        Failed to load evidence list.
      </p>
    )}
    {!evidenceQ.isLoading && items.length === 0 && (
      <p className="text-xs text-text-muted mt-2">
        No files catalogued yet -- wait for intake to complete or
        re-run readiness.
      </p>
    )}</AilaCard>
  );
}
