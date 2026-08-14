/**
 * AuditSealsTab -- cryptographic seal viewer for the AuditLogsPage.
 *
 * Wires:
 *   GET /audit/seals?run_id=&include_content=&page=&page_size=
 *   GET /audit/seals/export?since=&until=&include_content=
 *
 * Design notes:
 * - `/seals` requires run_id, so the table is empty until one is supplied.
 * - `?run_id=` search-param seeds the input.
 * - Row expansion is only meaningful when include_content=true; the row shows
 *   prompt_content/response_content in <pre> blocks.
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

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
// Helpers
// ---------------------------------------------------------------------------

const PAGE_SIZE = 50;

function truncateHash(hash: string, keep = 10): string {
  if (!hash) return "--";
  return hash.length > keep + 2 ? `${hash.slice(0, keep)}…` : hash;
}

function formatTimestamp(value: string | null): string {
  if (!value) return "--";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function CopyHashButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="ml-1 shrink-0 opacity-50 hover:opacity-100 transition-opacity"
      title="Copy hash"
      aria-label="Copy hash"
      onClick={(e) => {
        e.stopPropagation();
        void navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
    >
      {copied ? (
        <Check className="h-3 w-3 text-[oklch(72%_0.18_150)]" />
      ) : (
        <Copy className="h-3 w-3" />
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Row
// ---------------------------------------------------------------------------

interface SealRowProps {
  seal: AuditSeal;
  includeContent: boolean;
  expanded: boolean;
  onToggle: () => void;
}

function SealRow({ seal, includeContent, expanded, onToggle }: SealRowProps) {
  const evidence = seal.evidence_validation_pass;
  const evidenceBadge =
    evidence === true ? (
      <AilaBadge severity="info" size="sm">pass</AilaBadge>
    ) : evidence === false ? (
      <AilaBadge severity="critical" size="sm">fail</AilaBadge>
    ) : (
      <AilaBadge severity="neutral" size="sm">n/a</AilaBadge>
    );

  const canExpand = includeContent && (seal.prompt_content !== null || seal.response_content !== null);

  return (
    <>
      <tr
        className={[
          "border-b border-border last:border-0 transition-colors",
          canExpand ? "cursor-pointer hover:bg-elevated" : "",
        ].join(" ")}
        onClick={canExpand ? onToggle : undefined}
      >
        <td className="px-2 py-1.5 whitespace-nowrap">
          {canExpand ? (
            <button
              type="button"
              className="text-text-muted hover:text-text"
              aria-label={expanded ? "Collapse content" : "Expand content"}
              onClick={(e) => {
                e.stopPropagation();
                onToggle();
              }}
            >
              {expanded ? (
                <CaretDown className="h-3 w-3" />
              ) : (
                <CaretRight className="h-3 w-3" />
              )}
            </button>
          ) : (
            <span className="inline-block h-3 w-3" />
          )}
        </td>
        <td className="px-2 py-1.5 whitespace-nowrap">
          <div className="flex items-center gap-1 font-mono text-[11px] text-text">
            <span title={seal.seal_hash}>{truncateHash(seal.seal_hash)}</span>
            <CopyHashButton text={seal.seal_hash} />
          </div>
        </td>
        <td className="px-2 py-1.5 whitespace-nowrap">
          <div className="flex items-center gap-1 font-mono text-[11px] text-text-muted">
            <span title={seal.input_hash}>{truncateHash(seal.input_hash, 8)}</span>
            <CopyHashButton text={seal.input_hash} />
          </div>
        </td>
        <td className="px-2 py-1.5 whitespace-nowrap">
          <div className="flex items-center gap-1 font-mono text-[11px] text-text-muted">
            <span title={seal.output_hash}>{truncateHash(seal.output_hash, 8)}</span>
            <CopyHashButton text={seal.output_hash} />
          </div>
        </td>
        <td className="px-2 py-1.5 font-mono text-[11px] text-text">
          {seal.model_id}
        </td>
        <td className="px-2 py-1.5 font-mono text-[11px] text-text">
          {seal.task_type}
        </td>
        <td className="px-2 py-1.5 whitespace-nowrap font-mono text-[11px] text-text-muted">
          {formatTimestamp(seal.timestamp)}
        </td>
        <td className="px-2 py-1.5 font-mono text-[11px] text-text-muted">
          {seal.classification ?? "--"}
        </td>
        <td className="px-2 py-1.5 font-mono text-[11px] text-text-muted">
          {seal.confidence ?? "--"}
        </td>
        <td className="px-2 py-1.5">{evidenceBadge}</td>
        <td className="px-2 py-1.5">
          {seal.content_stored ? (
            <AilaBadge severity="info" size="sm">stored</AilaBadge>
          ) : (
            <AilaBadge severity="neutral" size="sm">no</AilaBadge>
          )}
        </td>
      </tr>
      {expanded && canExpand && (
        <tr className="bg-elevated/40">
          <td colSpan={11} className="px-4 py-3">
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              <div className="flex flex-col gap-1">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-text-muted">
                  Prompt content
                </p>
                <pre className="max-h-72 overflow-auto rounded-[2px] border border-border bg-background/60 p-2 font-mono text-[10px] text-text whitespace-pre-wrap break-words">
{seal.prompt_content ?? "(not stored)"}
                </pre>
              </div>
              <div className="flex flex-col gap-1">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-text-muted">
                  Response content
                </p>
                <pre className="max-h-72 overflow-auto rounded-[2px] border border-border bg-background/60 p-2 font-mono text-[10px] text-text whitespace-pre-wrap break-words">
{seal.response_content ?? "(not stored)"}
                </pre>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Linkage result banner
// ---------------------------------------------------------------------------

function LinkageBanner({ result }: { result: SealLinkageResult }) {
  const ok = result.ok;
  return (
    <div
      className={[
        "rounded-[4px] border px-3 py-2 font-mono text-[11px]",
        ok
          ? "border-[oklch(72%_0.18_150)]/40 bg-[oklch(72%_0.18_150)]/10 text-[oklch(72%_0.18_150)]"
          : "border-destructive/50 bg-destructive/10 text-destructive",
      ].join(" ")}
    >
      <div className="flex items-center gap-2">
        <Shield className="h-3.5 w-3.5" />
        <span className="font-semibold">
          Linkage check {ok ? "passed" : "failed"}
        </span>
        <span className="opacity-70">
          -- structural integrity only, not an HMAC recomputation
        </span>
      </div>
      <div className="mt-1 grid grid-cols-2 gap-x-4 gap-y-0.5 pl-5 opacity-90 sm:grid-cols-3">
        <span>rows: {result.total}</span>
        <span>missing seal_hash: {result.missingSealHash}</span>
        <span>missing input_hash: {result.missingInputHash}</span>
        <span>missing output_hash: {result.missingOutputHash}</span>
        <span>evidence fail: {result.evidenceFail}</span>
        <span>evidence unknown: {result.evidenceUnknown}</span>
      </div>
    </div>
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

  // Export date range (default: last 24h → now)
  const now = useMemo(() => new Date(), []);
  const yesterday = useMemo(() => new Date(now.getTime() - 24 * 3600_000), [now]);
  const [since, setSince] = useState<string>(toDatetimeLocal(yesterday));
  const [until, setUntil] = useState<string>(toDatetimeLocal(now));
  const [exportContent, setExportContent] = useState(false);

  // Keep URL and inputs in sync when the seed changes externally.
  useEffect(() => {
    if (seededRunId && seededRunId !== activeRunId) {
      setRunIdInput(seededRunId);
      setActiveRunId(seededRunId);
    }
    // Only react to seededRunId changes; ignore activeRunId in deps to avoid a loop.
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
    // Mirror into URL so links are shareable.
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

  return (
    <div className="flex flex-col gap-4">
      {/* Filter card */}
      <AilaCard variant="elevated" padding="md" techBorder glow>
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-2 lg:flex-row lg:items-end">
            <div className="flex flex-1 flex-col gap-1">
              <label
                htmlFor="seal-run-id"
                className="font-mono text-[10px] uppercase tracking-wider text-text-muted"
              >
                Run ID (required)
              </label>
              <Input
                id="seal-run-id"
                value={runIdInput}
                onChange={(e) => setRunIdInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    applyRunId();
                  }
                }}
                placeholder="50b5b278-1b3d-…"
                className="font-mono text-xs"
              />
            </div>
            <label className="flex items-center gap-2 font-mono text-[11px] text-text-muted">
              <input
                type="checkbox"
                checked={includeContent}
                onChange={(e) => {
                  setIncludeContent(e.target.checked);
                  setExpanded({});
                }}
              />
              include prompt/response content
            </label>
            <div className="flex gap-2">
              <Button size="sm" onClick={applyRunId} disabled={!runIdInput.trim()}>
                Load
              </Button>
              <Button size="sm" variant="outline" onClick={clearRunId}>
                Clear
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => sealsQuery.refetch()}
                disabled={!activeRunId || sealsQuery.isFetching}
                className="gap-1.5"
              >
                <ArrowClockwise
                  className={`h-3.5 w-3.5 ${sealsQuery.isFetching ? "animate-spin" : ""}`}
                />
                Refresh
              </Button>
            </div>
          </div>

          <div className="flex flex-col gap-2 border-t border-border pt-3 lg:flex-row lg:items-end">
            <div className="flex flex-col gap-1">
              <label
                htmlFor="seal-since"
                className="font-mono text-[10px] uppercase tracking-wider text-text-muted"
              >
                Export since
              </label>
              <Input
                id="seal-since"
                type="datetime-local"
                value={since}
                onChange={(e) => setSince(e.target.value)}
                className="font-mono text-xs"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label
                htmlFor="seal-until"
                className="font-mono text-[10px] uppercase tracking-wider text-text-muted"
              >
                Export until
              </label>
              <Input
                id="seal-until"
                type="datetime-local"
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                className="font-mono text-xs"
              />
            </div>
            <label className="flex items-center gap-2 font-mono text-[11px] text-text-muted">
              <input
                type="checkbox"
                checked={exportContent}
                onChange={(e) => setExportContent(e.target.checked)}
              />
              export with content
            </label>
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => void runExport()}
              disabled={exporting}
            >
              <Download className="h-3.5 w-3.5" />
              {exporting ? "Exporting…" : "Export range"}
            </Button>
          </div>
        </div>
      </AilaCard>

      {/* Chain check + counts */}
      {activeRunId && (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="font-mono text-[11px] text-text-muted">
            {sealsQuery.data
              ? `Loaded ${items.length} of ${total} seal(s) for run ${activeRunId.slice(0, 12)}…`
              : "Loading…"}
          </div>
          <Button
            size="sm"
            variant="outline"
            className="gap-1.5"
            onClick={runChainCheck}
            disabled={items.length === 0}
            title="Structural hash-linkage check. NOT an HMAC recomputation -- the HMAC key is server-side."
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            Check chain
          </Button>
        </div>
      )}

      {linkage && <LinkageBanner result={linkage} />}

      {/* Body */}
      {!activeRunId && (
        <EmptyState
          icon={<Shield className="h-10 w-10" />}
          title="Enter a run ID"
          description="The /audit/seals endpoint scopes results to a single run. Paste a run_id above (or navigate here from the workflow inspector) to load the seal chain."
        />
      )}

      {activeRunId && sealsQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow>
          <LoadingSkeletonGroup lines={6} />
        </AilaCard>
      )}

      {activeRunId && sealsQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load audit seals:{" "}
          {(sealsQuery.error as Error).message}
        </div>
      )}

      {activeRunId &&
        !sealsQuery.isLoading &&
        !sealsQuery.isError &&
        items.length === 0 && (
          <EmptyState
            icon={<Shield className="h-10 w-10" />}
            title="No seals for this run"
            description="This run has no cryptographic seal records. Seals are written by the LLM pipeline after every model call."
          />
        )}

      {activeRunId && items.length > 0 && (
        <div className="overflow-x-auto rounded-[4px] border border-border">
          <table className="w-full font-mono text-xs">
            <thead>
              <tr className="border-b border-border bg-elevated text-left">
                <th className="w-6 px-2 py-2" />
                <th className="px-2 py-2 text-text-muted font-semibold">seal_hash</th>
                <th className="px-2 py-2 text-text-muted font-semibold">input_hash</th>
                <th className="px-2 py-2 text-text-muted font-semibold">output_hash</th>
                <th className="px-2 py-2 text-text-muted font-semibold">model</th>
                <th className="px-2 py-2 text-text-muted font-semibold">task</th>
                <th className="px-2 py-2 text-text-muted font-semibold">timestamp</th>
                <th className="px-2 py-2 text-text-muted font-semibold">class</th>
                <th className="px-2 py-2 text-text-muted font-semibold">conf.</th>
                <th className="px-2 py-2 text-text-muted font-semibold">evidence</th>
                <th className="px-2 py-2 text-text-muted font-semibold">content</th>
              </tr>
            </thead>
            <tbody>
              {items.map((seal) => (
                <SealRow
                  key={`${seal.id ?? seal.seal_hash}`}
                  seal={seal}
                  includeContent={includeContent}
                  expanded={seal.id !== null ? Boolean(expanded[seal.id]) : false}
                  onToggle={() => toggleRow(seal.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeRunId && pages > 1 && (
        <div className="flex items-center justify-between font-mono text-[11px] text-text-muted">
          <span>
            Page {page} of {pages} · {total} total
          </span>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={page <= 1 || sealsQuery.isFetching}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              Prev
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={page >= pages || sealsQuery.isFetching}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** Format a Date as the `datetime-local` input's YYYY-MM-DDTHH:mm shape. */
function toDatetimeLocal(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
