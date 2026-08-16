import { useMemo, useState } from "react";

import { WindowPanel } from "@/components/aila/WindowPanel";

import { useProjectEvidence } from "../queries";
import { useRetrieveFile } from "../mutations";
import type { EvidenceItem } from "../types";

interface Props {
  projectId: string;
  /** Compact mode for the dashboard (smaller heading, tighter form). */
  compact?: boolean;
}

const INPUT_STYLE: React.CSSProperties = {
  width: "100%",
  height: 30,
  padding: "0 10px",
  fontSize: 11,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

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
 * Retrieve-File panel -- pulls an arbitrary artefact out of the
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
    () => (evidenceQ.data ?? []).filter((e) => e.evidence_type === "disk_image"),
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

  const title = compact ? "retrieve file" : "retrieve file from image";

  return (
    <WindowPanel
      title={title}
      status={`image ; ${diskImages.length} disk image${diskImages.length === 1 ? "" : "s"}`}
    >
      <form onSubmit={onSubmit} className="space-y-2">
        <input
          aria-label="Virtual file path"
          type="text"
          value={virtualPath}
          onChange={(e) => setVirtualPath(e.target.value)}
          placeholder="Full in-image path (file or directory)"
          disabled={retrieveMut.isPending}
          className="font-mono"
          spellCheck={false}
          autoComplete="off"
          style={INPUT_STYLE}
        />

        {diskImages.length > 1 && (
          <select
            aria-label="Select disk image"
            value={evidenceId}
            onChange={(e) => setEvidenceId(e.target.value)}
            disabled={retrieveMut.isPending}
            className="font-mono"
            style={SELECT_STYLE}
          >
            <option value="">-- pick a disk image --</option>
            {diskImages.map((d) => (
              <option key={d.id} value={d.id}>
                {d.file_path}
              </option>
            ))}
          </select>
        )}

        <div className="flex items-center justify-between" style={{ gap: 8 }}>
          <p
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-faint)", lineHeight: 1.5 }}
          >
            Paste the full in-image path -- file or directory. Directories are
            zipped on the analyzer and shipped as{" "}
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
            . Windows and POSIX path styles are both accepted.
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
            {retrieveMut.isPending ? "retrieving\u2026" : "retrieve"}
          </button>
        </div>
      </form>

      {evidenceQ.isError && (
        <p
          className="font-mono"
          style={{ fontSize: 10.5, color: "var(--accent)", marginTop: 8 }}
        >
          Failed to load evidence list.
        </p>
      )}
      {!evidenceQ.isLoading && diskImages.length === 0 && (
        <p
          className="font-mono"
          style={{ fontSize: 10.5, color: "var(--text-faint)", marginTop: 8 }}
        >
          No disk images on this project -- run intake first.
        </p>
      )}
    </WindowPanel>
  );
}
