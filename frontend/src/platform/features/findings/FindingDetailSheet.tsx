import { Shield } from "@phosphor-icons/react/dist/csr/Shield";
import { ArrowSquareOut } from "@phosphor-icons/react/dist/csr/ArrowSquareOut";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";
import { CheckCircle } from "@phosphor-icons/react/dist/csr/CheckCircle";
import { Lightbulb } from "@phosphor-icons/react/dist/csr/Lightbulb";
import { Wrench } from "@phosphor-icons/react/dist/csr/Wrench";
import { Question } from "@phosphor-icons/react/dist/csr/Question";
import { Tag } from "@phosphor-icons/react/dist/csr/Tag";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { WorkflowActions } from "./WorkflowActions";
import { useFindingDetail, useCveIntel } from "./api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function severityVariant(sev: string | null): "critical" | "high" | "medium" | "low" | "neutral" {
  const s = (sev ?? "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}

function weightColor(weight: "high" | "medium" | "low"): string {
  if (weight === "high") return "text-severity-critical";
  if (weight === "medium") return "text-severity-high";
  return "text-text-muted";
}

function scoreBar(score: number): string {
  // score is 0.0–1.0
  const pct = Math.round(Math.min(Math.max(score, 0), 1) * 100);
  return `${pct}%`;
}

function scoreColor(score: number): string {
  if (score >= 0.8) return "bg-severity-critical";
  if (score >= 0.6) return "bg-severity-high";
  if (score >= 0.4) return "bg-severity-medium";
  return "bg-severity-low";
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="font-mono text-[10px] uppercase tracking-widest text-text-muted mb-2">
      {children}
    </h3>
  );
}

function TextBlock({ text }: { text: string | undefined }) {
  if (!text) return <p className="font-mono text-xs text-text-muted italic">--</p>;
  return <p className="font-mono text-xs text-text leading-relaxed">{text}</p>;
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface FindingDetailSheetProps {
  findingId: number | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * FindingDetailSheet -- full-detail slide-over for a vulnerability finding.
 *
 * Shows CVE description, CVSS breakdown, scoring facts/inference/
 * recommended action, and metadata. Wires to:
 *   GET /vulnerability/findings/{id}   -- scoring detail + details_json
 *   GET /vulnerability/cves/{cve_id}   -- CVE description + CVSS breakdown
 */
export function FindingDetailSheet({ findingId, open, onOpenChange }: FindingDetailSheetProps) {
  const detailQuery = useFindingDetail(open ? findingId : null);
  const finding = detailQuery.data?.data;

  const cveId = finding?.cve_id ?? null;
  const isCve = !!cveId && cveId.startsWith("CVE-");
  const intelQuery = useCveIntel(isCve ? cveId : null);
  const intel = intelQuery.data?.data;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-2xl overflow-y-auto">
        {/* Header */}
        <SheetHeader className="mb-4">
          <SheetTitle className="font-mono text-sm flex items-center gap-2">
            <Shield size={16} weight="duotone" className="text-accent" />
            {finding ? finding.cve_id : "Finding Detail"}
          </SheetTitle>
          <SheetDescription className="font-mono text-xs text-text-muted">
            {finding
              ? `${finding.package} on ${finding.host}`
              : "Loading…"}
          </SheetDescription>
        </SheetHeader>

        {/* Loading */}
        {detailQuery.isLoading && (
          <div className="flex flex-col gap-4">
            <LoadingSkeletonGroup lines={8} />
          </div>
        )}

        {/* Error */}
        {detailQuery.isError && (
          <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
            {(detailQuery.error as Error).message}
          </div>
        )}

        {/* Content */}
        {finding && (
          <div className="flex flex-col gap-5">

            {/* Identity row */}
            <div className="flex flex-wrap items-center gap-2">
              <AilaBadge severity={severityVariant(finding.severity)} size="sm">
                {finding.severity?.toUpperCase() ?? "UNKNOWN"}
              </AilaBadge>
              {finding.is_kev && (
                <AilaBadge severity="critical" size="sm">
                  <Warning size={10} weight="fill" className="inline mr-0.5" />
                  KEV
                </AilaBadge>
              )}
              <span className="font-mono text-xs text-text-muted">
                Score:{" "}
                <span className="text-text font-semibold">
                  {finding.score.toFixed(3)}
                </span>
              </span>
              <span className="font-mono text-xs text-text-muted">
                Status:{" "}
                <span className="text-text">{finding.status}</span>
              </span>
              <span className="font-mono text-xs text-text-muted">
                State:{" "}
                <span className="text-text">{finding.workflow_state}</span>
              </span>
            </div>

            {/* Score bar */}
            <div className="flex items-center gap-2">
              <div className="h-1.5 flex-1 rounded-full bg-surface-2 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${scoreColor(finding.score)}`}
                  style={{ width: scoreBar(finding.score) }}
                />
              </div>
              <span className="font-mono text-[10px] text-text-muted w-8 text-right">
                {Math.round(finding.score * 100)}%
              </span>
            </div>

            {/* Triage workflow actions */}
            <AilaCard variant="default" padding="sm" techBorder glow><WorkflowActions
              findingId={finding.id}
              fallbackState={finding.workflow_state}
            /></AilaCard>

            {/* CVE description */}
            <AilaCard variant="default" padding="sm" techBorder glow><SectionLabel>CVE Description</SectionLabel>
            {intelQuery.isLoading && <LoadingSkeletonGroup lines={3} />}
            {!intelQuery.isLoading && (
              <TextBlock text={intel?.description || (isCve ? undefined : "Advisory-only finding -- no CVE description available.")} />
            )}
            {intel?.nvd_url && (
              <a
                href={intel.nvd_url}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-2 inline-flex items-center gap-1 font-mono text-[10px] text-accent hover:underline"
              >
                NVD <ArrowSquareOut size={10} />
              </a>
            )}</AilaCard>

            {/* CVSS breakdown */}
            {intel?.cvss_breakdown && intel.cvss_breakdown.length > 0 && (
              <AilaCard variant="default" padding="sm" techBorder glow><SectionLabel>
                CVSS {intel.cvss_score !== null ? intel.cvss_score?.toFixed(1) : "--"} · {intel.base_severity ?? "--"}
              </SectionLabel>
              {intel.cvss_vector && (
                <p className="font-mono text-[10px] text-text-muted mb-2 break-all">{intel.cvss_vector}</p>
              )}
              <div className="grid grid-cols-1 gap-1.5">
                {intel.cvss_breakdown.map((m) => (
                  <div key={m.code} className="flex gap-2 items-start">
                    <span className={`font-mono text-[10px] w-5 shrink-0 mt-0.5 ${weightColor(m.weight)}`}>
                      {m.weight === "high" ? "▲" : m.weight === "medium" ? "◆" : "▽"}
                    </span>
                    <div>
                      <span className="font-mono text-xs text-text-muted">{m.metric}: </span>
                      <span className="font-mono text-xs text-text font-medium">{m.value}</span>
                      <p className="font-mono text-[10px] text-text-muted">{m.explanation}</p>
                    </div>
                  </div>
                ))}
              </div>
              {(intel.epss_score !== null || intel.kev_listed) && (
                <div className="mt-2 pt-2 border-t border-border flex flex-wrap gap-3">
                  {intel.epss_score !== null && (
                    <span className="font-mono text-[10px] text-text-muted">
                      EPSS: <span className="text-text">{(intel.epss_score * 100).toFixed(2)}%</span>
                      {intel.epss_percentile !== null && (
                        <span className="text-text-muted"> (p{Math.round(intel.epss_percentile * 100)})</span>
                      )}
                    </span>
                  )}
                  {intel.kev_listed && (
                    <span className="font-mono text-[10px] text-severity-critical">
                      In CISA KEV{intel.kev_date_added ? ` since ${intel.kev_date_added}` : ""}
                    </span>
                  )}
                  {intel.published_at && (
                    <span className="font-mono text-[10px] text-text-muted">
                      Published: {intel.published_at.slice(0, 10)}
                    </span>
                  )}
                </div>
              )}</AilaCard>
            )}

            {/* Package + version */}
            <AilaCard variant="default" padding="sm" techBorder glow><SectionLabel>Package</SectionLabel>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 font-mono text-xs">
              <dt className="text-text-muted">Package</dt>
              <dd className="text-text">{finding.package}</dd>
              <dt className="text-text-muted">Installed</dt>
              <dd className="text-text">{finding.details.installed_version ?? "--"}</dd>
              <dt className="text-text-muted">Fix available</dt>
              <dd className={finding.fixed_version ? "text-severity-low font-medium" : "text-text-muted"}>
                {finding.fixed_version ?? "None published"}
              </dd>
              {finding.details.distribution && (
                <>
                  <dt className="text-text-muted">Distribution</dt>
                  <dd className="text-text">{finding.details.distribution}</dd>
                </>
              )}
            </dl></AilaCard>

            {/* Rationale */}
            <AilaCard variant="default" padding="sm" techBorder glow><SectionLabel>
              <CheckCircle size={11} className="inline mr-1" weight="fill" />
              Rationale
            </SectionLabel>
            <TextBlock text={finding.rationale} /></AilaCard>

            {/* Facts */}
            {finding.details.facts && (
              <AilaCard variant="default" padding="sm" techBorder glow><SectionLabel>
                <Tag size={11} className="inline mr-1" />
                Facts
              </SectionLabel>
              <TextBlock text={finding.details.facts} /></AilaCard>
            )}

            {/* Inference */}
            {finding.details.inference && (
              <AilaCard variant="default" padding="sm" techBorder glow><SectionLabel>
                <Lightbulb size={11} className="inline mr-1" />
                Inference
              </SectionLabel>
              <TextBlock text={finding.details.inference} /></AilaCard>
            )}

            {/* Recommended action */}
            {finding.details.recommended_action && (
              <AilaCard variant="elevated" padding="sm" techBorder glow><SectionLabel>
                <Wrench size={11} className="inline mr-1" />
                Recommended Action
              </SectionLabel>
              <TextBlock text={finding.details.recommended_action} /></AilaCard>
            )}

            {/* Uncertainty */}
            {finding.details.uncertainty && (
              <AilaCard variant="default" padding="sm" techBorder glow><SectionLabel>
                <Question size={11} className="inline mr-1" />
                Uncertainty
              </SectionLabel>
              <TextBlock text={finding.details.uncertainty} /></AilaCard>
            )}

            {/* Vendor info */}
            {(finding.details.vendor_statuses?.length ||
              finding.details.vendor_urgencies?.length ||
              finding.details.vendor_fix_states?.length) ? (
              <AilaCard variant="default" padding="sm" techBorder glow><SectionLabel>Vendor Signals</SectionLabel>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 font-mono text-xs">
                {!!finding.details.vendor_statuses?.length && (
                  <>
                    <dt className="text-text-muted">Status</dt>
                    <dd className="text-text">{finding.details.vendor_statuses.join(", ")}</dd>
                  </>
                )}
                {!!finding.details.vendor_urgencies?.length && (
                  <>
                    <dt className="text-text-muted">Urgency</dt>
                    <dd className="text-text">{finding.details.vendor_urgencies.join(", ")}</dd>
                  </>
                )}
                {!!finding.details.vendor_fix_states?.length && (
                  <>
                    <dt className="text-text-muted">Fix state</dt>
                    <dd className="text-text">{finding.details.vendor_fix_states.join(", ")}</dd>
                  </>
                )}
              </dl></AilaCard>
            ) : null}

            {/* Compliance tags */}
            {finding.compliance_tags.length > 0 && (
              <AilaCard variant="default" padding="sm" techBorder glow><SectionLabel>Compliance Tags</SectionLabel>
              <div className="flex flex-wrap gap-1.5">
                {finding.compliance_tags.map((tag) => (
                  <span
                    key={tag}
                    className="font-mono text-[10px] px-1.5 py-0.5 rounded-[2px] bg-surface-2 text-text-muted border border-border"
                  >
                    {tag}
                  </span>
                ))}
              </div></AilaCard>
            )}

            {/* Metadata footer */}
            <div className="flex flex-wrap gap-4 pt-2 border-t border-border">
              {finding.last_scanned_at && (
                <span className="font-mono text-[10px] text-text-muted">
                  Last scanned: {new Date(finding.last_scanned_at).toLocaleString()}
                </span>
              )}
              {finding.nvd_url && (
                <a
                  href={finding.nvd_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 font-mono text-[10px] text-accent hover:underline"
                >
                  NVD <ArrowSquareOut size={10} />
                </a>
              )}
            </div>

          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
