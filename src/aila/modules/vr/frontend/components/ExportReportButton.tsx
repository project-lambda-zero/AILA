import { useState } from "react";

import { requestBlob } from "@platform/api/http";
import { saveBlobResponse } from "@platform/api/download";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";

/** Export the investigation as an enterprise PDF report.
 *
 *  Triggers GET /vr/investigations/{id}/report.pdf which calls the
 *  writer agent + ReportLab renderer server-side. The writer call
 *  can take 5-15 s, so we show a pending state and disable the
 *  button while in flight to prevent duplicate report jobs.
 *
 *  Uses the platform's standard blob download path (same as the
 *  vulnerability module's report export) so token refresh + auth
 *  retry behaviour is identical to the rest of the app.
 *
 *  No React Query — reports are generated on demand and one-shot;
 *  caching the binary would bloat the cache for no benefit.
 */
export function ExportReportButton({
  invId,
  title,
}: {
  invId: string;
  title?: string;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleClick() {
    setBusy(true);
    setError(null);
    try {
      const token = await getAuthTokenStandalone();
      const payload = await requestBlob(
        `/vr/investigations/${encodeURIComponent(invId)}/report.pdf`,
        { method: "GET", token },
      );
      const safeTitle = (title ?? "investigation")
        .replace(/[^a-zA-Z0-9_-]+/g, "_")
        .slice(0, 80);
      const fallback = `AILA_VR_${safeTitle}_${invId.slice(0, 8)}.pdf`;
      saveBlobResponse(payload, payload.fileName ?? fallback);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg.slice(0, 120));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <button
        type="button"
        onClick={handleClick}
        disabled={busy}
        className="text-xs px-3 py-1.5 rounded-md bg-surface border border-border-default hover:bg-surface-hover text-foreground disabled:opacity-50"
        title="Generate enterprise PDF report (writer agent + ReportLab)"
      >
        {busy ? "Generating…" : "Export PDF ↓"}
      </button>
      {error && (
        <span
          className="text-xs text-red-500 max-w-xs truncate"
          title={error}
        >
          {error}
        </span>
      )}
    </div>
  );
}
