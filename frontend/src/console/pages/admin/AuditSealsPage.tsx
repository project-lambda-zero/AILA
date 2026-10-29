/** Audit seals console over /audit/seals (admin): list the cryptographic
 * seals recorded for one run with their verify state, page through them, and
 * export a since/until window as a JSON download. The export reuses the
 * Bearer-authed fetch stack (apiFetch stamps the token) and materializes the
 * file client-side so the download carries the operator's auth. */
import { useState } from "react";
import type { JSX } from "react";

import { fetchAuditSealExport, useAuditSeals } from "../../../api/admin";
import type { AuditSeal } from "../../../api/admin";
import type { ModulePageProps } from "../../contract";
import { css } from "../../css";
import { toast } from "../../toast";
import { ActButton, actionRow, fieldStyle } from "../xray/actions";
import { AdminWindow, FAINT, MONO, QueryState, Section, SubmitButton, Table, fmtTime } from "./kit";

function boolMark(v: boolean | null): JSX.Element {
  if (v == null) return <span style={css(FAINT)}>—</span>;
  return <span style={css(`color:${v ? "var(--status-ok)" : "var(--status-warn)"};`)}>{v ? "pass" : "fail"}</span>;
}

function downloadJson(filename: string, rows: unknown[]): void {
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function AuditSealsPage(props: ModulePageProps): JSX.Element {
  const [runDraft, setRunDraft] = useState("");
  const [runId, setRunId] = useState("");
  const [includeContent, setIncludeContent] = useState(false);
  const [page, setPage] = useState(1);
  const sealsQ = useAuditSeals(runId, includeContent, page);

  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [exporting, setExporting] = useState(false);

  const sealColumns = [
    { label: "timestamp", cell: (s: AuditSeal) => fmtTime(s.timestamp) },
    { label: "task", cell: (s: AuditSeal) => s.task_type },
    { label: "model", cell: (s: AuditSeal) => s.model_id },
    { label: "seal hash", cell: (s: AuditSeal) => <span style={css(MONO)}>{s.seal_hash.slice(0, 16)}…</span> },
    { label: "evidence", cell: (s: AuditSeal) => boolMark(s.evidence_validation_pass) },
    { label: "content", cell: (s: AuditSeal) => (s.content_stored ? "stored" : "—") },
  ] as const;

  const pages = sealsQ.data?.pages ?? 0;

  const runExport = (): void => {
    setExporting(true);
    fetchAuditSealExport(since, until, includeContent)
      .then((rows) => {
        downloadJson(`audit-seals-${since.slice(0, 10)}-${until.slice(0, 10)}.json`, rows);
        toast.success(`exported ${rows.length} seals`);
      })
      .catch((e: unknown) => toast.fail("seal export", e))
      .finally(() => setExporting(false));
  };

  return (
    <AdminWindow page={props}>
      <Section title="seals for run">
        <form
          style={actionRow}
          onSubmit={(e) => {
            e.preventDefault();
            setRunId(runDraft.trim());
            setPage(1);
          }}
        >
          <input value={runDraft} onChange={(e) => setRunDraft(e.target.value)} placeholder="run id" style={{ ...fieldStyle, width: 340 }} />
          <label style={css("display:flex;align-items:center;gap:5px;font-size:11px;color:var(--text-muted);")}>
            <input type="checkbox" checked={includeContent} onChange={(e) => setIncludeContent(e.target.checked)} />
            include content
          </label>
          <SubmitButton label="list" disabled={runDraft.trim() === ""} pending={sealsQ.isFetching} />
        </form>
        {runId === "" ? (
          <div style={css(FAINT + "font-size:11px;")}>Enter a run id to list its seals.</div>
        ) : (
          <>
            <QueryState loading={sealsQ.isLoading} error={sealsQ.error} empty={(sealsQ.data?.items.length ?? 0) === 0} emptyText="no seals recorded for this run" />
            {(sealsQ.data?.items.length ?? 0) > 0 ? (
              <>
                <Table rows={sealsQ.data?.items ?? []} columns={sealColumns} rowKey={(s) => `${s.id ?? s.seal_hash}`} />
                <div style={actionRow}>
                  <ActButton label="prev" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} />
                  <span style={css(FAINT + MONO + "font-size:11px;")}>
                    page {page} of {pages} · {sealsQ.data?.total ?? 0} seals
                  </span>
                  <ActButton label="next" disabled={page >= pages} onClick={() => setPage((p) => p + 1)} />
                </div>
              </>
            ) : null}
          </>
        )}
      </Section>

      <Section title="export by window">
        <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:8px;max-width:560px;")}>
          <label style={css("display:flex;flex-direction:column;gap:3px;")}>
            <span style={css(FAINT + "font-size:11px;")}>since (ISO datetime)</span>
            <input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} style={fieldStyle} />
          </label>
          <label style={css("display:flex;flex-direction:column;gap:3px;")}>
            <span style={css(FAINT + "font-size:11px;")}>until (ISO datetime)</span>
            <input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} style={fieldStyle} />
          </label>
        </div>
        <div style={actionRow}>
          <span style={css(FAINT + "font-size:11px;")}>Exports every page of GET /audit/seals/export with the session Bearer token and downloads a JSON file.</span>
          <span style={css("flex:1;")} />
          <ActButton label="export" tone="accent" pending={exporting} disabled={since === "" || until === ""} onClick={runExport} />
        </div>
      </Section>
    </AdminWindow>
  );
}
