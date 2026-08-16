import { useState } from "react";
import { useNavigate, useParams } from "react-router";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { SectionHeader, MonoBadge } from "@/components/aila/mock";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

import { DeleteButton } from "../components/DeleteButton";
import { CVSSCalculator } from "../components/CVSSCalculator";
import {
  useDeleteDisclosure,
  usePatchDisclosure,
  usePatchDisclosureSections,
  useRegenerateDisclosureSections,
  useRenderDisclosure,
} from "../mutations";
import { useDisclosure } from "../queries";
import type {
  DisclosureSubmissionStatus,
  VRDisclosureSubmissionSummary,
} from "../types";

// ---------------------------------------------------------------------------
// Reachable-state matrix -- mirrors backend disclosure lifecycle.
// ---------------------------------------------------------------------------
const NEXT_STATES: Record<
  DisclosureSubmissionStatus,
  DisclosureSubmissionStatus[]
> = {
  drafted: ["submitted", "withdrawn"],
  submitted: ["acknowledged", "rejected", "withdrawn"],
  acknowledged: ["triaging", "rejected", "withdrawn"],
  triaging: ["accepted", "rejected", "withdrawn"],
  accepted: ["patched", "withdrawn"],
  rejected: ["closed"],
  patched: ["published", "closed"],
  published: ["closed"],
  closed: [],
  withdrawn: [],
};

const STATUS_TONE: Record<DisclosureSubmissionStatus, string> = {
  drafted: "muted",
  submitted: "info",
  acknowledged: "info",
  triaging: "warn",
  accepted: "ok",
  rejected: "critical",
  patched: "ok",
  published: "ok",
  closed: "muted",
  withdrawn: "muted",
};

// ---------------------------------------------------------------------------
// Local BriefRow -- uppercase mono label above the mono value, border-bottom
// rule (matches mock's project-brief pattern from ProjectDetailPage).
// ---------------------------------------------------------------------------
function BriefRow({
  label,
  children,
}: {
  label: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 3,
        padding: "8px 0",
        borderBottom: "1px solid var(--border-faint)",
      }}
    >
      <span
        className="font-mono uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: 11,
          color: "var(--text-primary)",
          minHeight: 14,
          overflowWrap: "anywhere",
        }}
      >
        {children}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Reusable inline styles (mock CTRL input + action button).
// ---------------------------------------------------------------------------
const CTRL_STYLE: React.CSSProperties = {
  height: 26,
  padding: "0 8px",
  fontSize: 11,
  letterSpacing: "0.04em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

function actionBtnStyle(primary: boolean, disabled = false): React.CSSProperties {
  return {
    height: 28,
    padding: "0 12px",
    fontSize: 10,
    letterSpacing: "0.08em",
    background: primary ? "var(--accent)" : "var(--surface-sunk)",
    border: `1px solid ${primary ? "var(--accent)" : "var(--border-soft)"}`,
    color: primary ? "var(--text-on-accent)" : "var(--text-primary)",
    borderRadius: 3,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.5 : 1,
  };
}

function ghostBtnStyle(disabled = false): React.CSSProperties {
  return {
    height: 26,
    padding: "0 10px",
    fontSize: 10,
    letterSpacing: "0.06em",
    background: "var(--surface-sunk)",
    border: "1px solid var(--border-soft)",
    color: "var(--text-primary)",
    borderRadius: 3,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.5 : 1,
  };
}

const MONO_PRE_STYLE: React.CSSProperties = {
  padding: 12,
  fontSize: 11,
  lineHeight: 1.5,
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  overflow: "auto",
  maxHeight: 400,
  whiteSpace: "pre-wrap",
  margin: 0,
};

// ---------------------------------------------------------------------------
// DisclosureDetailPage
// ---------------------------------------------------------------------------
export function DisclosureDetailPage() {
  const { submissionId } = useParams<{ submissionId: string }>();
  const sid = submissionId ?? "";

  const { data: sub, isLoading } = useDisclosure(sid);
  const patchMut = usePatchDisclosure(sid);
  const renderMut = useRenderDisclosure(sid);
  const deleteMut = useDeleteDisclosure();
  const navigate = useNavigate();

  useUpdatePageHeader({
    title: sub?.track_info?.display_name ?? sub?.track_id,
    subtitle: sub ? `status: ${sub.status}` : undefined,
    status: null,
  });

  if (isLoading || !sub) {
    return (
      <WindowPanel title="disclosure" tone="muted">
        <LoadingSkeleton size="lg" width="full" />
      </WindowPanel>
    );
  }

  const transitions = NEXT_STATES[sub.status] ?? [];
  const statusTone = STATUS_TONE[sub.status] ?? "muted";

  const headerActions = (
    <DeleteButton
      id={sid}
      label={`disclosure to ${sub.track_id}`}
      mutation={deleteMut}
      onDeleted={() => navigate("/vr/disclosures")}
    />
  );

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader
        icon="\u25c8"
        title={sub.track_info?.display_name ?? sub.track_id}
        actions={headerActions}
      />

      {/* Tag row -- kind / poc / severity / embargo / status */}
      <div className="flex" style={{ gap: 8, flexWrap: "wrap" }}>
        <MonoBadge tone="info">kind:{sub.kind}</MonoBadge>
        <MonoBadge tone="info">poc:{sub.poc_tier}</MonoBadge>
        {sub.severity_rating ? (
          <MonoBadge tone="warn">severity:{sub.severity_rating}</MonoBadge>
        ) : null}
        {sub.embargo_until ? (
          <MonoBadge tone="signal">
            embargo:{new Date(sub.embargo_until).toLocaleDateString()}
          </MonoBadge>
        ) : null}
        <MonoBadge tone={statusTone}>status:{sub.status}</MonoBadge>
      </div>

      {/* State transitions */}
      <WindowPanel title="state transitions" tone="accent">
        {transitions.length === 0 ? (
          <p
            className="font-mono"
            style={{
              fontSize: 11,
              color: "var(--text-muted)",
              margin: 0,
              padding: "6px 0",
            }}
          >
            terminal state. no further transitions possible.
          </p>
        ) : (
          <div className="flex" style={{ gap: 8, flexWrap: "wrap" }}>
            {transitions.map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => patchMut.mutate({ status: t })}
                disabled={patchMut.isPending}
                className="font-mono uppercase"
                style={actionBtnStyle(true, patchMut.isPending)}
                aria-label={`Transition to ${t}`}
              >
                {"\u2192 "}{t}
              </button>
            ))}
          </div>
        )}
      </WindowPanel>

      {/* Vendor + bounty */}
      <WindowPanel title="vendor + bounty" tone="info">
        <BriefRow label="vendor reference">
          <input
            type="text"
            defaultValue={sub.vendor_reference ?? ""}
            onBlur={(e) => {
              const v = e.currentTarget.value.trim();
              if (v && v !== sub.vendor_reference) {
                patchMut.mutate({ vendor_reference: v });
              }
            }}
            placeholder="e.g. CVE-2026-NNNN or VRP-XXXX"
            aria-label="Vendor reference"
            style={{ ...CTRL_STYLE, width: "100%" }}
          />
        </BriefRow>
        <BriefRow label="bounty (usd)">
          <input
            type="number"
            defaultValue={sub.bounty_awarded_usd ?? ""}
            onBlur={(e) => {
              const n = parseFloat(e.currentTarget.value);
              if (!Number.isNaN(n) && n !== sub.bounty_awarded_usd) {
                patchMut.mutate({ bounty_awarded_usd: n });
              }
            }}
            placeholder="0"
            aria-label="Bounty awarded (USD)"
            style={{ ...CTRL_STYLE, width: 160 }}
          />
        </BriefRow>
      </WindowPanel>

      {/* Validation errors */}
      {sub.validation_errors.length > 0 && (
        <WindowPanel
          title={`validation errors (${sub.validation_errors.length})`}
          tone="accent"
        >
          <ul
            className="font-mono"
            style={{
              margin: 0,
              padding: 0,
              listStyle: "none",
              display: "flex",
              flexDirection: "column",
              gap: 4,
              fontSize: 11,
              color: "var(--accent)",
            }}
          >
            {sub.validation_errors.map((err, i) => (
              <li key={i}>{"\u00b7 "}{err}</li>
            ))}
          </ul>
        </WindowPanel>
      )}

      {/* Rendered submission body */}
      <WindowPanel
        title="rendered submission body"
        tone="info"
        actions={
          <div className="flex items-center" style={{ gap: 6 }}>
            {renderMut.data?.data.body ? (
              <>
                <button
                  type="button"
                  onClick={() => {
                    void navigator.clipboard?.writeText(
                      renderMut.data!.data.body,
                    );
                  }}
                  className="font-mono uppercase"
                  style={ghostBtnStyle()}
                  title="Copy as Markdown"
                >
                  copy md
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const blob = new Blob(
                      [JSON.stringify(renderMut.data, null, 2)],
                      { type: "application/json" },
                    );
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `advisory_${sub.track_id}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="font-mono uppercase"
                  style={ghostBtnStyle()}
                  title="Download as JSON"
                >
                  json
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const blob = new Blob(
                      [renderMut.data!.data.body],
                      { type: "text/markdown" },
                    );
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `advisory_${sub.track_id}.md`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="font-mono uppercase"
                  style={ghostBtnStyle()}
                  title="Download as Markdown"
                >
                  md
                </button>
                <button
                  type="button"
                  onClick={() => {
                    // MITRE CVE 5.1 JSON skeleton. Full field mapping
                    // requires a backend renderer.
                    const tpl = {
                      dataType: "CVE_RECORD",
                      dataVersion: "5.1",
                      cveMetadata: {
                        cveId:
                          sub.vendor_reference ?? "CVE-PLACEHOLDER",
                        assignerOrgId: "(your org id)",
                        state: "PUBLISHED",
                      },
                      containers: {
                        cna: {
                          title:
                            sub.track_info?.display_name ?? sub.track_id,
                          descriptions: [
                            {
                              lang: "en",
                              value: renderMut.data!.data.body,
                            },
                          ],
                        },
                      },
                    };
                    const blob = new Blob(
                      [JSON.stringify(tpl, null, 2)],
                      { type: "application/json" },
                    );
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `mitre_cve_${sub.track_id}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="font-mono uppercase"
                  style={ghostBtnStyle()}
                  title="Download as MITRE CVE 5.1 JSON skeleton"
                >
                  mitre
                </button>
                <button
                  type="button"
                  onClick={() => window.print()}
                  className="font-mono uppercase"
                  style={ghostBtnStyle()}
                  title="Browser print dialog -- Save as PDF"
                >
                  pdf
                </button>
              </>
            ) : null}
            <button
              type="button"
              onClick={() => renderMut.mutate()}
              disabled={renderMut.isPending}
              className="font-mono uppercase"
              style={actionBtnStyle(true, renderMut.isPending)}
            >
              {renderMut.isPending ? "rendering\u2026" : "re-render"}
            </button>
          </div>
        }
      >
        {renderMut.data ? (
          <pre className="font-mono" style={MONO_PRE_STYLE}>
            {renderMut.data.data.body}
          </pre>
        ) : (
          <p
            className="font-mono"
            style={{
              fontSize: 11,
              color: "var(--text-muted)",
              margin: 0,
              lineHeight: 1.5,
            }}
          >
            body is rendered + stored on every status / poc-tier / embargo
            change. click{" "}
            <span style={{ color: "var(--accent)" }}>re-render</span> to
            refresh after editing the underlying finding.
          </p>
        )}
      </WindowPanel>

      {/* CVSS v3.1 calculator */}
      <WindowPanel title="cvss v3.1 score" tone="warn">
        <p
          className="font-mono"
          style={{
            fontSize: 11,
            color: "var(--text-muted)",
            margin: "0 0 10px",
            lineHeight: 1.5,
          }}
        >
          pick one value per metric. vector + base score recompute live.
          persisting the score back to the submission is backend pending --
          copy the vector string into the advisory body for now.
        </p>
        <CVSSCalculator />
      </WindowPanel>

      {/* Track metadata */}
      {sub.track_info ? (
        <WindowPanel title="track metadata" tone="muted">
          <BriefRow label="program url">
            {sub.track_info.program_url ?? "--"}
          </BriefRow>
          <BriefRow label="severity schema">
            {sub.track_info.severity_schema}
          </BriefRow>
          <BriefRow label="required artifacts">
            {sub.track_info.required_artifacts.join(", ") || "--"}
          </BriefRow>
          <BriefRow label="accepted poc tiers">
            {sub.track_info.accepted_poc_tiers.join(", ")}
          </BriefRow>
          <BriefRow label="notes">{sub.track_info.notes || "--"}</BriefRow>
        </WindowPanel>
      ) : null}

      {/* Structured advisory editor (sections) */}
      <DisclosureSectionsEditor submission={sub} />

      {/* Disclosure timeline */}
      <WindowPanel title="disclosure timeline" tone="info">
        <TimelineRow
          time={sub.created_at}
          label="drafted"
          note="submission record created"
        />
        {sub.status !== "drafted" ? (
          <TimelineRow
            time={sub.updated_at}
            label={sub.status}
            note={`status now: ${sub.status}`}
          />
        ) : null}
        {sub.embargo_until ? (
          <TimelineRow
            time={sub.embargo_until}
            label="embargo until"
            note="public disclosure permitted on / after this date"
          />
        ) : null}
        {sub.bounty_awarded_usd != null && sub.bounty_awarded_usd > 0 ? (
          <TimelineRow
            time={sub.updated_at}
            label="bounty"
            note={`$${sub.bounty_awarded_usd.toLocaleString()} awarded`}
          />
        ) : null}
        <p
          className="font-mono"
          style={{
            marginTop: 10,
            padding: 8,
            fontSize: 10,
            color: "var(--text-faint)",
            background: "var(--surface-sunk)",
            border: "1px dashed var(--border-soft)",
            borderRadius: 3,
            lineHeight: 1.5,
          }}
        >
          per-transition rows (who advanced status / when / why) require a
          vrdisclosuretransitionrecord on the backend. currently only
          first + most-recent transitions render.
        </p>
      </WindowPanel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TimelineRow -- one bordered mono row inside the timeline panel.
// ---------------------------------------------------------------------------
function TimelineRow({
  time,
  label,
  note,
}: {
  time?: string | null;
  label: string;
  note?: string;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 10,
        padding: "8px 10px",
        borderBottom: "1px solid var(--border-faint)",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          display: "inline-block",
          width: 7,
          height: 7,
          borderRadius: 2,
          background: "var(--accent)",
          marginTop: 6,
          flex: "0 0 auto",
        }}
      />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          className="flex items-baseline font-mono"
          style={{ gap: 10, flexWrap: "wrap" }}
        >
          <span
            className="uppercase"
            style={{
              fontSize: 10,
              letterSpacing: "0.08em",
              color: "var(--text-primary)",
            }}
          >
            {label}
          </span>
          <span
            style={{
              fontSize: 10,
              color: "var(--text-faint)",
              letterSpacing: "0.04em",
            }}
          >
            {time ? new Date(time).toLocaleString() : "--"}
          </span>
        </div>
        {note ? (
          <p
            className="font-mono"
            style={{
              margin: "3px 0 0",
              fontSize: 10,
              color: "var(--text-muted)",
              letterSpacing: "0.02em",
            }}
          >
            {note}
          </p>
        ) : null}
      </div>
    </div>
  );
}

const SECTION_ORDER = [
  { key: "summary", label: "Summary" },
  { key: "technical_details", label: "Technical details" },
  { key: "reproduction", label: "Reproduction" },
  { key: "patches", label: "Patches" },
  { key: "references", label: "References" },
] as const;

// ---------------------------------------------------------------------------
// DisclosureSectionsEditor -- structured advisory editor. Sections backed by
// POST /disclosures/{id}/sections + regenerate-from-finding.
// ---------------------------------------------------------------------------
function DisclosureSectionsEditor({
  submission,
}: {
  submission: VRDisclosureSubmissionSummary;
}) {
  const initial = submission.sections ?? {};
  const [draft, setDraft] = useState<Record<string, string>>({
    summary: initial.summary ?? "",
    technical_details: initial.technical_details ?? "",
    reproduction: initial.reproduction ?? "",
    patches: initial.patches ?? "",
    references: initial.references ?? "",
  });
  const patchMut = usePatchDisclosureSections(submission.id);
  const regenMut = useRegenerateDisclosureSections(submission.id);
  const regeneratedAt = submission.regenerated_from_finding_at;

  const editorActions = (
    <div className="flex items-center" style={{ gap: 6 }}>
      <button
        type="button"
        disabled={regenMut.isPending}
        onClick={() => {
          if (
            window.confirm(
              "Regenerating REPLACES every section with text derived "
                + "from the finding (advisory + PoC). Operator edits above "
                + "will be lost. Continue?",
            )
          ) {
            regenMut.mutate(undefined, {
              onSuccess: (res) => {
                const fresh = res.data.sections ?? {};
                setDraft({
                  summary: fresh.summary ?? "",
                  technical_details: fresh.technical_details ?? "",
                  reproduction: fresh.reproduction ?? "",
                  patches: fresh.patches ?? "",
                  references: fresh.references ?? "",
                });
              },
            });
          }
        }}
        className="font-mono uppercase"
        style={ghostBtnStyle(regenMut.isPending)}
      >
        {regenMut.isPending ? "regenerating\u2026" : "regenerate"}
      </button>
      <button
        type="button"
        disabled={patchMut.isPending}
        onClick={() => patchMut.mutate(draft)}
        className="font-mono uppercase"
        style={actionBtnStyle(true, patchMut.isPending)}
      >
        {patchMut.isPending ? "saving\u2026" : "save sections"}
      </button>
    </div>
  );

  const regenNote = regeneratedAt
    ? `last regenerated ${new Date(regeneratedAt).toLocaleString()}`
    : "never regenerated";

  return (
    <WindowPanel
      title="structured advisory editor"
      tone="accent"
      actions={editorActions}
    >
      <p
        className="font-mono"
        style={{
          fontSize: 10,
          color: "var(--text-faint)",
          margin: "0 0 12px",
          letterSpacing: "0.02em",
        }}
      >
        save replaces the body; regenerate refills every section from the
        finding ({regenNote}).
      </p>
      <div className="flex flex-col" style={{ gap: 12 }}>
        {SECTION_ORDER.map(({ key, label }) => (
          <div key={key} className="flex flex-col" style={{ gap: 4 }}>
            <label
              htmlFor={`section-${key}`}
              className="font-mono uppercase"
              style={{
                fontSize: 9,
                letterSpacing: "0.14em",
                color: "var(--text-faint)",
              }}
            >
              {label}
            </label>
            <textarea
              id={`section-${key}`}
              value={draft[key] ?? ""}
              onChange={(e) =>
                setDraft({ ...draft, [key]: e.target.value })
              }
              rows={key === "summary" || key === "references" ? 3 : 6}
              className="font-mono"
              style={{
                width: "100%",
                padding: 8,
                fontSize: 11,
                lineHeight: 1.5,
                color: "var(--text-primary)",
                background: "var(--surface-sunk)",
                border: "1px solid var(--border-soft)",
                borderRadius: 3,
                resize: "vertical",
              }}
            />
          </div>
        ))}
      </div>
    </WindowPanel>
  );
}
