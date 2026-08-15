import { ArrowSquareOut } from "@phosphor-icons/react/dist/csr/ArrowSquareOut";

import { MonoBadge } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { WorkflowActions } from "./WorkflowActions";
import { EvidenceChainSheet } from "./EvidenceChainSheet";
import { useFindingDetail, useCveIntel } from "./api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function severityTone(sev: string | null | undefined) {
  const s = (sev ?? "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "muted";
}

function weightColor(weight: "high" | "medium" | "low"): string {
  if (weight === "high") return "var(--accent)";
  if (weight === "medium") return "var(--status-warn)";
  return "var(--text-muted)";
}

function scoreColor(score: number): string {
  if (score >= 0.8) return "var(--accent)";
  if (score >= 0.6) return "var(--status-warn)";
  if (score >= 0.4) return "var(--status-info)";
  return "var(--status-ok)";
}

// ---------------------------------------------------------------------------
// Shared styles
// ---------------------------------------------------------------------------

const MONO_BTN: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 11px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  cursor: "pointer",
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
};

const SECTION_LABEL: React.CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 9,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
  color: "var(--text-muted)",
  marginBottom: 8,
};

const KEY_VALUE_ROW: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: 10,
  padding: "6px 0",
  borderBottom: "1px solid var(--border-faint)",
  fontFamily: "var(--font-mono)",
  fontSize: 11,
};

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

  if (!open) return null;

  const title = finding
    ? `finding ${finding.cve_id.toLowerCase()}`
    : "finding detail";
  const subtitle = finding
    ? `${finding.package} on ${finding.host}`
    : "Loading\u2026";

  return (
    <div
      className="fixed"
      style={{ inset: 0, zIndex: 70, pointerEvents: "none" }}
      role="dialog"
      aria-modal="true"
      aria-label="Finding detail"
    >
      {/* backdrop */}
      <div
        role="button"
        tabIndex={-1}
        aria-label="Close finding detail"
        onClick={() => onOpenChange(false)}
        onKeyDown={(e) => { if (e.key === "Escape") onOpenChange(false); }}
        style={{
          position: "absolute",
          inset: 0,
          background: "color-mix(in srgb, black 40%, transparent)",
          pointerEvents: "auto",
        }}
      />

      {/* sheet -- right-anchored WindowPanel */}
      <div
        style={{
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          width: "min(560px, 92vw)",
          overflowY: "auto",
          background: "var(--surface-page)",
          borderLeft: "1px solid var(--border)",
          pointerEvents: "auto",
        }}
      >
        <WindowPanel
          title={title}
          tone={finding ? severityTone(finding.severity) === "critical" ? "accent" : "info" : "muted"}
          actions={
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              aria-label="Close"
              style={{ ...MONO_BTN, height: 20, fontSize: 9, padding: "0 8px" }}
            >
              {"\u2715"} CLOSE
            </button>
          }
          status={subtitle}
        >
          {detailQuery.isLoading && (
            <LoadingSkeletonGroup lines={8} />
          )}

          {detailQuery.isError && (
            <div
              className="font-mono"
              style={{
                border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
                background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
                color: "var(--status-warn)",
                padding: "8px 12px",
                fontSize: 11,
                borderRadius: 3,
              }}
            >
              {(detailQuery.error as Error).message}
            </div>
          )}

          {finding && (
            <div className="flex flex-col" style={{ gap: 18 }}>

              {/* Severity / KEV / status row */}
              <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
                <MonoBadge tone={severityTone(finding.severity)}>
                  {(finding.severity ?? "unknown").toUpperCase()}
                </MonoBadge>
                {finding.is_kev && (
                  <MonoBadge tone="critical" title="Known Exploited">
                    KEV
                  </MonoBadge>
                )}
                <MonoBadge tone="muted">
                  SCORE {finding.score.toFixed(3)}
                </MonoBadge>
                <MonoBadge tone="muted">
                  STATUS {finding.status.toUpperCase()}
                </MonoBadge>
              </div>

              {/* Score bar */}
              <div className="flex items-center" style={{ gap: 8 }}>
                <div
                  style={{
                    flex: 1,
                    height: 4,
                    background: "var(--surface-sunk)",
                    border: "1px solid var(--border-faint)",
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      height: "100%",
                      width: `${Math.round(Math.min(Math.max(finding.score, 0), 1) * 100)}%`,
                      background: scoreColor(finding.score),
                    }}
                  />
                </div>
                <span
                  className="font-mono"
                  style={{ fontSize: 9, color: "var(--text-muted)", width: 34, textAlign: "right" }}
                >
                  {Math.round(finding.score * 100)}%
                </span>
              </div>

              {/* Workflow / triage */}
              <WorkflowActions
                findingId={finding.id}
                fallbackState={finding.workflow_state}
              />

              {/* Evidence chain link */}
              <div>
                <div style={SECTION_LABEL}>Evidence Chain</div>
                <EvidenceChainSheet
                  findingId={finding.id}
                  findingLabel={`${finding.cve_id} on ${finding.host}`}
                />
              </div>

              {/* CVE description */}
              <div>
                <div style={SECTION_LABEL}>CVE Description</div>
                {intelQuery.isLoading && <LoadingSkeletonGroup lines={3} />}
                {!intelQuery.isLoading && (
                  <p
                    className="font-mono"
                    style={{ fontSize: 11, color: "var(--text-primary)", lineHeight: 1.55 }}
                  >
                    {intel?.description ||
                      (isCve
                        ? "\u2014"
                        : "Advisory-only finding -- no CVE description available.")}
                  </p>
                )}
                {intel?.nvd_url && (
                  <a
                    href={intel.nvd_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono uppercase"
                    style={{
                      marginTop: 8,
                      fontSize: 9,
                      letterSpacing: "0.1em",
                      color: "var(--accent)",
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 4,
                    }}
                  >
                    NVD <ArrowSquareOut size={10} />
                  </a>
                )}
              </div>

              {/* CVSS breakdown */}
              {intel?.cvss_breakdown && intel.cvss_breakdown.length > 0 && (
                <div>
                  <div style={SECTION_LABEL}>
                    CVSS {intel.cvss_score !== null ? intel.cvss_score?.toFixed(1) : "--"}{" \u00b7 "}
                    {intel.base_severity ?? "--"}
                  </div>
                  {intel.cvss_vector && (
                    <p
                      className="font-mono"
                      style={{
                        fontSize: 9,
                        color: "var(--text-muted)",
                        marginBottom: 8,
                        wordBreak: "break-all",
                      }}
                    >
                      {intel.cvss_vector}
                    </p>
                  )}
                  <div className="flex flex-col" style={{ gap: 6 }}>
                    {intel.cvss_breakdown.map((m) => (
                      <div key={m.code} className="flex" style={{ gap: 8, alignItems: "flex-start" }}>
                        <span
                          className="font-mono"
                          style={{
                            fontSize: 10,
                            width: 14,
                            color: weightColor(m.weight),
                            marginTop: 2,
                          }}
                        >
                          {m.weight === "high" ? "\u25b2" : m.weight === "medium" ? "\u25c6" : "\u25bd"}
                        </span>
                        <div>
                          <span
                            className="font-mono"
                            style={{ fontSize: 11, color: "var(--text-muted)" }}
                          >
                            {m.metric}:{" "}
                          </span>
                          <span
                            className="font-mono"
                            style={{ fontSize: 11, color: "var(--text-primary)", fontWeight: 500 }}
                          >
                            {m.value}
                          </span>
                          <p
                            className="font-mono"
                            style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}
                          >
                            {m.explanation}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                  {(intel.epss_score !== null || intel.kev_listed) && (
                    <div
                      className="flex flex-wrap"
                      style={{
                        gap: 12,
                        marginTop: 10,
                        paddingTop: 10,
                        borderTop: "1px solid var(--border-faint)",
                      }}
                    >
                      {intel.epss_score !== null && (
                        <span
                          className="font-mono"
                          style={{ fontSize: 10, color: "var(--text-muted)" }}
                        >
                          EPSS:{" "}
                          <span style={{ color: "var(--text-primary)" }}>
                            {(intel.epss_score * 100).toFixed(2)}%
                          </span>
                          {intel.epss_percentile !== null && (
                            <span style={{ color: "var(--text-faint)" }}>
                              {" "}(p{Math.round(intel.epss_percentile * 100)})
                            </span>
                          )}
                        </span>
                      )}
                      {intel.kev_listed && (
                        <span
                          className="font-mono"
                          style={{ fontSize: 10, color: "var(--accent)" }}
                        >
                          In CISA KEV
                          {intel.kev_date_added ? ` since ${intel.kev_date_added}` : ""}
                        </span>
                      )}
                      {intel.published_at && (
                        <span
                          className="font-mono"
                          style={{ fontSize: 10, color: "var(--text-muted)" }}
                        >
                          Published: {intel.published_at.slice(0, 10)}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Package */}
              <div>
                <div style={SECTION_LABEL}>Package</div>
                <div className="flex flex-col">
                  <div style={KEY_VALUE_ROW}>
                    <span style={{ color: "var(--text-muted)" }}>PACKAGE</span>
                    <span style={{ color: "var(--text-primary)", textAlign: "right" }}>
                      {finding.package}
                    </span>
                  </div>
                  <div style={KEY_VALUE_ROW}>
                    <span style={{ color: "var(--text-muted)" }}>INSTALLED</span>
                    <span style={{ color: "var(--text-primary)", textAlign: "right" }}>
                      {finding.details.installed_version ?? "\u2014"}
                    </span>
                  </div>
                  <div style={KEY_VALUE_ROW}>
                    <span style={{ color: "var(--text-muted)" }}>FIX AVAILABLE</span>
                    <span
                      style={{
                        color: finding.fixed_version ? "var(--status-ok)" : "var(--text-faint)",
                        textAlign: "right",
                      }}
                    >
                      {finding.fixed_version ?? "None published"}
                    </span>
                  </div>
                  {finding.details.distribution && (
                    <div style={KEY_VALUE_ROW}>
                      <span style={{ color: "var(--text-muted)" }}>DISTRIBUTION</span>
                      <span style={{ color: "var(--text-primary)", textAlign: "right" }}>
                        {finding.details.distribution}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Rationale */}
              {finding.rationale && (
                <div>
                  <div style={SECTION_LABEL}>Rationale</div>
                  <p
                    className="font-mono"
                    style={{ fontSize: 11, color: "var(--text-primary)", lineHeight: 1.55 }}
                  >
                    {finding.rationale}
                  </p>
                </div>
              )}

              {finding.details.facts && (
                <div>
                  <div style={SECTION_LABEL}>Facts</div>
                  <p
                    className="font-mono"
                    style={{ fontSize: 11, color: "var(--text-primary)", lineHeight: 1.55 }}
                  >
                    {finding.details.facts}
                  </p>
                </div>
              )}

              {finding.details.inference && (
                <div>
                  <div style={SECTION_LABEL}>Inference</div>
                  <p
                    className="font-mono"
                    style={{ fontSize: 11, color: "var(--text-primary)", lineHeight: 1.55 }}
                  >
                    {finding.details.inference}
                  </p>
                </div>
              )}

              {finding.details.recommended_action && (
                <div
                  style={{
                    border: "1px solid color-mix(in srgb, var(--accent) 30%, transparent)",
                    background: "color-mix(in srgb, var(--accent) 6%, transparent)",
                    padding: 12,
                    borderRadius: 3,
                  }}
                >
                  <div style={{ ...SECTION_LABEL, color: "var(--accent)" }}>
                    Recommended Action
                  </div>
                  <p
                    className="font-mono"
                    style={{ fontSize: 11, color: "var(--text-primary)", lineHeight: 1.55 }}
                  >
                    {finding.details.recommended_action}
                  </p>
                </div>
              )}

              {finding.details.uncertainty && (
                <div>
                  <div style={SECTION_LABEL}>Uncertainty</div>
                  <p
                    className="font-mono"
                    style={{ fontSize: 11, color: "var(--text-primary)", lineHeight: 1.55 }}
                  >
                    {finding.details.uncertainty}
                  </p>
                </div>
              )}

              {/* Vendor signals */}
              {(finding.details.vendor_statuses?.length ||
                finding.details.vendor_urgencies?.length ||
                finding.details.vendor_fix_states?.length) ? (
                <div>
                  <div style={SECTION_LABEL}>Vendor Signals</div>
                  <div className="flex flex-col">
                    {!!finding.details.vendor_statuses?.length && (
                      <div style={KEY_VALUE_ROW}>
                        <span style={{ color: "var(--text-muted)" }}>STATUS</span>
                        <span style={{ color: "var(--text-primary)", textAlign: "right" }}>
                          {finding.details.vendor_statuses.join(", ")}
                        </span>
                      </div>
                    )}
                    {!!finding.details.vendor_urgencies?.length && (
                      <div style={KEY_VALUE_ROW}>
                        <span style={{ color: "var(--text-muted)" }}>URGENCY</span>
                        <span style={{ color: "var(--text-primary)", textAlign: "right" }}>
                          {finding.details.vendor_urgencies.join(", ")}
                        </span>
                      </div>
                    )}
                    {!!finding.details.vendor_fix_states?.length && (
                      <div style={KEY_VALUE_ROW}>
                        <span style={{ color: "var(--text-muted)" }}>FIX STATE</span>
                        <span style={{ color: "var(--text-primary)", textAlign: "right" }}>
                          {finding.details.vendor_fix_states.join(", ")}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              ) : null}

              {/* Compliance tags */}
              {finding.compliance_tags.length > 0 && (
                <div>
                  <div style={SECTION_LABEL}>Compliance Tags</div>
                  <div className="flex flex-wrap" style={{ gap: 6 }}>
                    {finding.compliance_tags.map((tag) => (
                      <MonoBadge key={tag} tone="muted">
                        {tag}
                      </MonoBadge>
                    ))}
                  </div>
                </div>
              )}

              {/* Timestamps footer */}
              <div
                className="flex flex-wrap"
                style={{
                  gap: 14,
                  paddingTop: 12,
                  borderTop: "1px solid var(--border-faint)",
                }}
              >
                {finding.last_scanned_at && (
                  <span
                    className="font-mono"
                    style={{ fontSize: 9, color: "var(--text-muted)" }}
                  >
                    LAST SCANNED: {new Date(finding.last_scanned_at).toLocaleString()}
                  </span>
                )}
                {finding.nvd_url && (
                  <a
                    href={finding.nvd_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono uppercase"
                    style={{
                      fontSize: 9,
                      letterSpacing: "0.1em",
                      color: "var(--accent)",
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 4,
                    }}
                  >
                    NVD <ArrowSquareOut size={10} />
                  </a>
                )}
              </div>
            </div>
          )}
        </WindowPanel>
      </div>
    </div>
  );
}
