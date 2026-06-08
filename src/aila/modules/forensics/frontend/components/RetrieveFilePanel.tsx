import { useMemo, useState } from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import { useProjectEvidence } from "../queries";
import { useRetrieveFile } from "../mutations";
import type { EvidenceItem } from "../types";

interface Props {
  projectId: string;
  /** Compact mode for the dashboard (smaller heading, tighter form). */
  compact?: boolean;
}

/**
 * Retrieve-File panel — pulls an arbitrary artefact out of the
 * project's disk image by its in-image path. Accepts either a file
 * path (streamed back verbatim) or a directory path (zipped on the
 * analyzer, shipped as ``<dirname>.zip``). The backend runs a
 * dissect.target extraction on the analyzer, SFTPs the bytes back,
 * and streams them to the browser as a file download.
 */
export function RetrieveFilePanel({ projectId, compact = false }: Props) {
  const evidenceQ = useProjectEvidence(projectId);
  const retrieveMut = useRetrieveFile(projectId);

  const diskImages: EvidenceItem[] = useMemo(
    () =>
      (evidenceQ.data ?? []).filter((e) => e.evidence_type === "disk_image"),
    [evidenceQ.data],
  );

  const [virtualPath, setVirtualPath] = useState("");
  const [evidenceId, setEvidenceId] = useState<string>("");

  const canSubmit =
    virtualPath.trim().length > 0 &&
    !retrieveMut.isPending &&
    (diskImages.length === 1 || evidenceId.length > 0);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    await retrieveMut.mutateAsync({
      virtual_path: virtualPath.trim(),
      evidence_id:
        diskImages.length === 1 ? diskImages[0].id : evidenceId || null,
    });
  };

  const heading = compact ? "Retrieve File" : "Retrieve File from Image";

  return (
    <AilaCard  techBorder glow><div className="flex items-center justify-between mb-3">
      <h3 className="text-sm font-semibold text-foreground">{heading}</h3>
      <span className="text-xs text-text-muted">
        {diskImages.length} disk image{diskImages.length === 1 ? "" : "s"}
      </span>
    </div>
    
    <form onSubmit={onSubmit} className="space-y-2">
      <Input
        type="text"
        value={virtualPath}
        onChange={(e) => setVirtualPath(e.target.value)}
        placeholder="Full in-image path (file or directory)"
        disabled={retrieveMut.isPending}
        className="text-sm font-mono"
        spellCheck={false}
        autoComplete="off"
      />
    
      {diskImages.length > 1 && (
        <select
          value={evidenceId}
          onChange={(e) => setEvidenceId(e.target.value)}
          disabled={retrieveMut.isPending}
          className="w-full text-xs border border-border rounded px-2 py-1 bg-background"
        >
          <option value="">— pick a disk image —</option>
          {diskImages.map((d) => (
            <option key={d.id} value={d.id}>
              {d.file_path}
            </option>
          ))}
        </select>
      )}
    
      <div className="flex items-center justify-between gap-2">
        <p className="text-2xs text-text-muted">
          Paste the full in-image path — file or directory. Directories
          are zipped on the analyzer and shipped as
          <code className="font-mono mx-1">&lt;name&gt;.zip</code>.
          Windows and POSIX path styles are both accepted.
        </p>
        <Button type="submit" size="sm" disabled={!canSubmit}>
          {retrieveMut.isPending ? "Retrieving…" : "Retrieve"}
        </Button>
      </div>
    </form>
    
    {evidenceQ.isError && (
      <p className="text-xs text-status-critical mt-2">
        Failed to load evidence list.
      </p>
    )}
    {!evidenceQ.isLoading && diskImages.length === 0 && (
      <p className="text-xs text-text-muted mt-2">
        No disk images on this project — run intake first.
      </p>
    )}</AilaCard>
  );
}
