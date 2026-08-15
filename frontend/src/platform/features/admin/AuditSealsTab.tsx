/**
 * AuditSealsTab -- cryptographic seal viewer for the AuditLogsPage.
 *
 * Rebuilt to the AILA mock: SectionHeader top, WindowPanels for filter +
 * verification + seal log (DataGrid). Every status chip is MonoBadge.
 *
 * Wires:
 *   GET /audit/seals?run_id=&include_content=&page=&page_size=
 *   GET /audit/seals/export?since=&until=&include_content=
 *
 * Design notes:
 * - `/seals` requires run_id, so the log is empty until one is supplied.
 * - `?run_id=` search-param seeds the input.
 * - Row expansion is only meaningful when include_content=true; the row
 *   shows prompt_content/response_content in <pre> blocks.
 * - "Check chain" is a LINKAGE integrity check, not HMAC verification. The
 *   HMAC key is server-side (SecretStore) and the client cannot recompute it.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Download } from "@phosphor-icons/react/dist/csr/Download";
import { ShieldCheck } from "@phosphor-icons/react/dist/csr/ShieldCheck";
import { ArrowClockwise } from "@phosphor-icons/react/dist/csr/ArrowClockwise";
import { Copy } from "@phosphor-icons/react/dist/csr/Copy";
import { Check } from "@phosphor-icons/react/dist/csr/Check";
import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { CaretRight } from "@phosphor-icons/react/dist/csr/CaretRight";
import { Shield } from "@phosphor-icons/react/dist/csr/Shield";

import { SectionHeader, MonoBadge, DataGrid, BigStat, StatBar, toneColor } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { toast } from "@/components/ui/sonner";
import { saveBlobResponse } from "@platform/api/download";
import { ApiHttpError } from "@platform/api/http";

import {
  checkSealLinkage,
  exportAuditSeals,
  fetchAuditSeals,
  type AuditSeal,
  type SealLinkageResult,
} from "./audit-seals-api";

// ---------------------------------------------------------------------------
// Constants / helpers
// ---------------------------------------------------------------------------

const PAGE_SIZE = 50;

function truncateHash(hash: string, keep = 10): string {
  if (!hash) return "--";
  return hash.length > keep + 2 ? `${hash.slice(0, keep)}\u2026` : hash;
}

function formatTimestamp(value: string | null): string {
  if (!value) return "--";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

/** `datetime-local` shape used to seed the export inputs. */
function toDatetimeLocal(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// ---------------------------------------------------------------------------
// Shared inline element styles
// ---------------------------------------------------------------------------

const INPUT_STYLE: React.CSSProperties = {
  height: 26, padding: "0 8px", fontSize: 11,
  fontFamily: "var(--font-mono)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

const BUTTON_STYLE: React.CSSProperties = {
  height: 26, padding: "0 11px", fontSize: 9.5,
  fontFamily: "var(--font-mono)",
  letterSpacing: "0.08em", textTransform: "uppercase",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3, cursor: "pointer",
};

const PRIMARY_BUTTON_STYLE: React.CSSProperties = {
  ...BUTTON_STYLE,
  background: "var(--accent)",
  border: "1px solid var(--accent)",
  color: "var(--text-on-accent)",
};

function CopyHashButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="inline-flex items-center justify-center"
      title="Copy hash"
      aria-label="Copy hash"
      style={{
        width: 16, height: 16, marginLeft: 4,
        background: "transparent", border: 0,
        color: copied ? "var(--status-ok)" : "var(--text-faint)",
        cursor: "pointer",
      }}
      onClick={(e) => {
        e.stopPropagation();
        void navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        });
      }}
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

function HashCell({ value, keep = 10 }: { value: string; keep?: number }) {
  return (
    <span
      className="inline-flex items-center font-mono"
      style={{ fontSize: 10.5, color: "var(--text-primary)" }}
      title={value}
    >
      {truncateHash(value, keep)}
      <CopyHashButton text={value} />
    </span>
  );
}

// ---------------------------------------------------------------------------
// Tab
// ---------------------------------------------------------------------------

export function AuditSealsTab() {
  const [searchParams, setSearchParams] = useSearchParams();
  const seededRunId = searchParams.get("run_id") ?? "";

  const [runIdInput, setRunIdInput] = useState(seededRunId);
  const [activeRunId, setActiveRunId] = useState(seededRunId);
  const [includeContent, setIncludeContent] = useState(false);
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});
  const [linkage, setLinkage] = useState<SealLinkageResult | null>(null);
  const [exporting, setExporting] = useState(false);

  const now = useMemo(() => new Date(), []);
  const yesterday = useMemo(() => new Date(now.getTime() - 24 * 3600_000), [now]);
  const [since, setSince] = useState<string>(toDatetimeLocal(yesterday));
  const [until, setUntil] = useState<string>(toDatetimeLocal(now));
  const [exportContent, setExportContent] = useState(false);

  useEffect(() => {
    if (seededRunId && seededRunId !== activeRunId) {
      setRunIdInput(seededRunId);
      setActiveRunId(seededRunId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seededRunId]);

  const sealsQuery = useQuery({
    queryKey: ["platform", "audit-seals", activeRunId, includeContent, page],
    enabled: activeRunId.length > 0,
    queryFn: () =>
      fetchAuditSeals({
        runId: activeRunId,
        includeContent,
        page,
        pageSize: PAGE_SIZE,
      }),
  });

  const items = sealsQuery.data?.items ?? [];
  const total = sealsQuery.data?.total ?? 0;
  const pages = sealsQuery.data?.pages ?? 0;

  const applyRunId = useCallback(() => {
    const next = runIdInput.trim();
    setActiveRunId(next);
    setPage(1);
    setExpanded({});
    setLinkage(null);
    const nextParams = new URLSearchParams(searchParams);
    if (next) nextParams.set("run_id", next);
    else nextParams.delete("run_id");
    setSearchParams(nextParams, { replace: true });
  }, [runIdInput, searchParams, setSearchParams]);

  const clearRunId = useCallback(() => {
    setRunIdInput("");
    setActiveRunId("");
    setPage(1);
    setExpanded({});
    setLinkage(null);
    const nextParams = new URLSearchParams(searchParams);
    nextParams.delete("run_id");
    setSearchParams(nextParams, { replace: true });
  }, [searchParams, setSearchParams]);

  const toggleRow = useCallback((id: number | null) => {
    if (id === null) return;
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  }, []);

  const runChainCheck = useCallback(() => {
    const result = checkSealLinkage(items);
    setLinkage(result);
    if (result.ok) {
      toast.success("Linkage check passed", {
        description: `${result.total} row(s) present with full hash linkage.`,
      });
    } else {
      toast.error("Linkage check failed", {
        description: `${result.missingSealHash + result.missingInputHash + result.missingOutputHash} missing hash(es), ${result.evidenceFail} evidence failure(s).`,
      });
    }
  }, [items]);

  const runExport = useCallback(async () => {
    if (!since || !until) {
      toast.error("Export requires since/until timestamps");
      return;
    }
    setExporting(true);
    try {
      const payload = await exportAuditSeals({
        since: new Date(since).toISOString(),
        until: new Date(until).toISOString(),
        includeContent: exportContent,
      });
      saveBlobResponse(payload, "audit-seals-export.json");
      toast.success("Export downloaded");
    } catch (error) {
      const msg =
        error instanceof ApiHttpError
          ? `${error.status} ${error.message}`
          : error instanceof Error
            ? error.message
            : "Unknown error";
      toast.error("Seal export failed", { description: msg });
    } finally {
      setExporting(false);
    }
  }, [since, until, exportContent]);

  const totalHashes = linkage
    ? Math.max(1, linkage.total)
    : 1;

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25c7"}
        title="audit seals"
        actions={
          <div className="flex items-center" style={{ gap: 8 }}>
            <button
              type="button"
              style={BUTTON_STYLE}
              onClick={() => void sealsQuery.refetch()}
              disabled={!activeRunId || sealsQuery.isFetching}
            >
              <ArrowClockwise
                size={11}
                aria-hidden
                style={{ marginRight: 6, verticalAlign: "-1px", animation: sealsQuery.isFetching ? "spin 1s linear infinite" : undefined }}
              />
              REFRESH
            </button>
            <button
              type="button"
              style={BUTTON_STYLE}
              onClick={runChainCheck}
              disabled={items.length === 0}
              title="Structural hash-linkage check. NOT an HMAC recomputation."
            >
              <ShieldCheck size={11} aria-hidden style={{ marginRight: 6, verticalAlign: "-1px" }} />
              CHECK CHAIN
            </button>
          </div>
        }
      />

      {/* Filter + export controls */}
      <WindowPanel title="filters">
        <div className="flex flex-col" style={{ gap: 12 }}>
          <div className="flex flex-wrap items-end" style={{ gap: 10 }}>
            <div className="flex flex-col" style={{ gap: 4, flex: "1 1 260px" }}>
              <label
                htmlFor="seal-run-id"
                className="font-mono uppercase"
                style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
              >
                RUN ID (REQUIRED)
              </label>
              <input
                id="seal-run-id"
                value={runIdInput}
                onChange={(e) => setRunIdInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    applyRunId();
                  }
                }}
                placeholder="50b5b278-1b3d-\u2026"
                style={INPUT_STYLE}
                data-testid="seal-run-id"
              />
            </div>
            <label
              className="inline-flex items-center font-mono"
              style={{ gap: 6, fontSize: 10.5, color: "var(--text-muted)", height: 26 }}
            >
              <input
                type="checkbox"
                checked={includeContent}
                onChange={(e) => {
                  setIncludeContent(e.target.checked);
                  setExpanded({});
                }}
                style={{ width: 12, height: 12, accentColor: "var(--accent)" }}
              />
              include prompt/response content
            </label>
            <div className="flex items-center" style={{ gap: 6 }}>
              <button
                type="button"
                style={PRIMARY_BUTTON_STYLE}
                onClick={applyRunId}
                disabled={!runIdInput.trim()}
              >
                LOAD
              </button>
              <button
                type="button"
                style={BUTTON_STYLE}
                onClick={clearRunId}
              >
                CLEAR
              </button>
            </div>
          </div>

          <div
            className="flex flex-wrap items-end"
            style={{ gap: 10, paddingTop: 10, borderTop: "1px solid var(--border-faint)" }}
          >
            <div className="flex flex-col" style={{ gap: 4 }}>
              <label
                htmlFor="seal-since"
                className="font-mono uppercase"
                style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
              >
                EXPORT SINCE
              </label>
              <input
                id="seal-since"
                type="datetime-local"
                value={since}
                onChange={(e) => setSince(e.target.value)}
                style={INPUT_STYLE}
              />
            </div>
            <div className="flex flex-col" style={{ gap: 4 }}>
              <label
                htmlFor="seal-until"
                className="font-mono uppercase"
                style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
              >
                EXPORT UNTIL
              </label>
              <input
                id="seal-until"
                type="datetime-local"
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                style={INPUT_STYLE}
              />
            </div>
            <label
              className="inline-flex items-center font-mono"
              style={{ gap: 6, fontSize: 10.5, color: "var(--text-muted)", height: 26 }}
            >
              <input
                type="checkbox"
                checked={exportContent}
                onChange={(e) => setExportContent(e.target.checked)}
                style={{ width: 12, height: 12, accentColor: "var(--accent)" }}
              />
              export with content
            </label>
            <button
              type="button"
              style={BUTTON_STYLE}
              onClick={() => void runExport()}
              disabled={exporting}
            >
              <Download size={11} aria-hidden style={{ marginRight: 6, verticalAlign: "-1px" }} />
              {exporting ? "EXPORTING\u2026" : "EXPORT RANGE"}
            </button>
          </div>
        </div>
      </WindowPanel>

      {/* Verification */}
      <WindowPanel
        title="verification"
        tone={linkage ? (linkage.ok ? "ok" : "warn") : "muted"}
        status={
          linkage
            ? linkage.ok
              ? "LINKAGE OK"
              : "LINKAGE FAIL"
            : "AWAITING CHECK"
        }
      >
        {!linkage && (
          <div
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}
          >
            Structural hash-linkage check only -- the HMAC key is server-side and cannot
            be recomputed by the client. Load a run, then press <span style={{ color: "var(--text-primary)" }}>CHECK CHAIN</span>
            to score the loaded page.
          </div>
        )}
        {linkage && (
          <div className="flex flex-col" style={{ gap: 12 }}>
            <div
              className="grid"
              style={{ gridTemplateColumns: "180px 1fr", gap: 16, alignItems: "start" }}
            >
              <BigStat
                value={linkage.total}
                sub="rows checked"
              />
              <div className="flex flex-col" style={{ gap: 6 }}>
                <StatBar
                  label="MISSING SEAL"
                  color={linkage.missingSealHash > 0 ? "var(--status-warn)" : "var(--status-ok)"}
                  value={linkage.missingSealHash}
                  max={totalHashes}
                />
                <StatBar
                  label="MISSING INPUT"
                  color={linkage.missingInputHash > 0 ? "var(--status-warn)" : "var(--status-ok)"}
                  value={linkage.missingInputHash}
                  max={totalHashes}
                />
                <StatBar
                  label="MISSING OUT"
                  color={linkage.missingOutputHash > 0 ? "var(--status-warn)" : "var(--status-ok)"}
                  value={linkage.missingOutputHash}
                  max={totalHashes}
                />
                <StatBar
                  label="EV FAIL"
                  color={linkage.evidenceFail > 0 ? "var(--accent)" : "var(--status-ok)"}
                  value={linkage.evidenceFail}
                  max={totalHashes}
                />
                <StatBar
                  label="EV UNK"
                  color="var(--status-info)"
                  value={linkage.evidenceUnknown}
                  max={totalHashes}
                />
              </div>
            </div>
            <div className="inline-flex items-center" style={{ gap: 6 }}>
              <Shield size={12} aria-hidden style={{ color: toneColor(linkage.ok ? "ok" : "warn") }} />
              <span
                className="font-mono uppercase"
                style={{ fontSize: 10, letterSpacing: "0.1em", color: "var(--text-muted)" }}
              >
                STRUCTURAL INTEGRITY ONLY {"\u00b7"} NOT AN HMAC RECOMPUTATION
              </span>
            </div>
          </div>
        )}
      </WindowPanel>

      {/* Seal log */}
      <WindowPanel
        title="seal log"
        status={
          activeRunId
            ? sealsQuery.data
              ? `${items.length} OF ${total} \u00b7 RUN ${activeRunId.slice(0, 12)}\u2026`
              : "LOADING\u2026"
            : "AWAITING RUN ID"
        }
        flush
      >
        {!activeRunId && (
          <div
            className="font-mono"
            style={{ padding: 32, textAlign: "center", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}
          >
            The /audit/seals endpoint scopes results to a single run.
            <br />
            Paste a run_id above (or navigate here from the workflow inspector) to load the seal chain.
          </div>
        )}
        {activeRunId && sealsQuery.isLoading && (
          <div style={{ padding: 14 }}>
            <LoadingSkeletonGroup lines={6} />
          </div>
        )}
        {activeRunId && sealsQuery.isError && (
          <div
            className="font-mono"
            style={{
              margin: 12,
              padding: "8px 12px",
              border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
              background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
              color: "var(--status-warn)",
              fontSize: 11, borderRadius: 3,
            }}
          >
            Failed to load audit seals: {(sealsQuery.error as Error).message}
          </div>
        )}
        {activeRunId
          && !sealsQuery.isLoading
          && !sealsQuery.isError
          && items.length === 0 && (
          <div
            className="font-mono"
            style={{ padding: 32, textAlign: "center", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}
          >
            No cryptographic seal records for this run.
            <br />
            Seals are written by the LLM pipeline after every model call.
          </div>
        )}
        {activeRunId && items.length > 0 && (
          <DataGrid<AuditSeal>
            columns={[
              { label: "", width: "24px" },
              { label: "SEAL HASH", width: "150px" },
              { label: "INPUT", width: "110px" },
              { label: "OUTPUT", width: "110px" },
              { label: "MODEL", width: "1fr" },
              { label: "TASK", width: "1fr" },
              { label: "TIMESTAMP", width: "150px" },
              { label: "CLASS", width: "90px" },
              { label: "CONF", width: "56px", align: "right" },
              { label: "EVIDENCE", width: "76px" },
              { label: "CONTENT", width: "76px" },
            ]}
            rows={items}
            getKey={(s) => (s.id ?? s.seal_hash)}
            onRowClick={(s) => {
              const canExpand = includeContent && (s.prompt_content !== null || s.response_content !== null);
              if (canExpand) toggleRow(s.id);
            }}
            renderCells={(seal) => {
              const canExpand = includeContent && (seal.prompt_content !== null || seal.response_content !== null);
              const isExpanded = seal.id !== null && Boolean(expanded[seal.id]);
              const ev = seal.evidence_validation_pass;
              const evBadge =
                ev === true ? <MonoBadge tone="info">pass</MonoBadge>
                : ev === false ? <MonoBadge tone="critical">fail</MonoBadge>
                : <MonoBadge tone="muted">n/a</MonoBadge>;
              return [
                canExpand ? (
                  <span
                    aria-hidden
                    style={{ color: "var(--text-muted)", cursor: "pointer" }}
                  >
                    {isExpanded ? <CaretDown size={11} /> : <CaretRight size={11} />}
                  </span>
                ) : (
                  <span style={{ width: 11, display: "inline-block" }} />
                ),
                <HashCell value={seal.seal_hash} keep={10} />,
                <HashCell value={seal.input_hash} keep={8} />,
                <HashCell value={seal.output_hash} keep={8} />,
                <span className="truncate font-mono" style={{ fontSize: 10.5, color: "var(--text-primary)" }}>
                  {seal.model_id}
                </span>,
                <span className="truncate font-mono" style={{ fontSize: 10.5, color: "var(--text-primary)" }}>
                  {seal.task_type}
                </span>,
                <span className="font-mono" style={{ fontSize: 10, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                  {formatTimestamp(seal.timestamp)}
                </span>,
                <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-muted)" }}>
                  {seal.classification ?? "--"}
                </span>,
                <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-muted)" }}>
                  {seal.confidence ?? "--"}
                </span>,
                evBadge,
                seal.content_stored ? <MonoBadge tone="info">stored</MonoBadge> : <MonoBadge tone="muted">no</MonoBadge>,
              ];
            }}
          />
        )}

        {/* Expanded content rows (mock-styled below the grid) */}
        {activeRunId && includeContent && items.some((s) => s.id !== null && expanded[s.id]) && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10, padding: 12, borderTop: "1px solid var(--border-faint)" }}>
            {items
              .filter((s) => s.id !== null && expanded[s.id])
              .map((seal) => (
                <div
                  key={`content-${seal.id}`}
                  style={{
                    border: "1px solid var(--border-faint)", borderRadius: 3,
                    background: "var(--surface-sunk)", padding: 10,
                  }}
                >
                  <div
                    className="font-mono uppercase"
                    style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)", marginBottom: 6 }}
                  >
                    SEAL {truncateHash(seal.seal_hash, 12)}
                  </div>
                  <div
                    className="grid"
                    style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}
                  >
                    <div>
                      <div
                        className="font-mono uppercase"
                        style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)", marginBottom: 4 }}
                      >
                        PROMPT
                      </div>
                      <pre
                        style={{
                          maxHeight: 260, overflow: "auto",
                          fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-primary)",
                          padding: 8, background: "var(--surface-card)",
                          border: "1px solid var(--border-faint)", borderRadius: 3,
                          whiteSpace: "pre-wrap", wordBreak: "break-word", margin: 0,
                        }}
                      >
                        {seal.prompt_content ?? "(not stored)"}
                      </pre>
                    </div>
                    <div>
                      <div
                        className="font-mono uppercase"
                        style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)", marginBottom: 4 }}
                      >
                        RESPONSE
                      </div>
                      <pre
                        style={{
                          maxHeight: 260, overflow: "auto",
                          fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-primary)",
                          padding: 8, background: "var(--surface-card)",
                          border: "1px solid var(--border-faint)", borderRadius: 3,
                          whiteSpace: "pre-wrap", wordBreak: "break-word", margin: 0,
                        }}
                      >
                        {seal.response_content ?? "(not stored)"}
                      </pre>
                    </div>
                  </div>
                </div>
              ))}
          </div>
        )}
      </WindowPanel>

      {/* Pagination */}
      {activeRunId && pages > 1 && (
        <div
          className="flex items-center justify-between font-mono"
          style={{ fontSize: 10.5, color: "var(--text-muted)" }}
        >
          <span>
            page {page} of {pages} {"\u00b7"} {total} total
          </span>
          <div className="flex" style={{ gap: 6 }}>
            <button
              type="button"
              style={BUTTON_STYLE}
              disabled={page <= 1 || sealsQuery.isFetching}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              PREV
            </button>
            <button
              type="button"
              style={BUTTON_STYLE}
              disabled={page >= pages || sealsQuery.isFetching}
              onClick={() => setPage((p) => p + 1)}
            >
              NEXT
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
