import { useState } from "react";

import { useNavigate, useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

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
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

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

  if (isLoading || !sub) return <LoadingSkeleton size="lg" width="full" />;

  const transitions = NEXT_STATES[sub.status] ?? [];

  return (
    <div className="space-y-4">
      <div className="sticky top-0 z-10 bg-base/95 backdrop-blur-sm border-b border-border-default -mx-4 px-4 py-2 flex items-start justify-between gap-3 flex-wrap">
        <DeleteButton
          id={sid}
          label={`disclosure to ${sub.track_id}`}
          mutation={deleteMut}
          onDeleted={() => navigate("/vr/disclosures")}
        />
      </div>

      <div className="flex gap-2 flex-wrap">
        <AilaBadge severity="info" size="sm">
          kind:{sub.kind}
        </AilaBadge>
        <AilaBadge severity="info" size="sm">
          poc:{sub.poc_tier}
        </AilaBadge>
        {sub.severity_rating && (
          <AilaBadge severity="medium" size="sm">
            severity:{sub.severity_rating}
          </AilaBadge>
        )}
        {sub.embargo_until && (
          <AilaBadge severity="info" size="sm">
            embargo:{new Date(sub.embargo_until).toLocaleDateString()}
          </AilaBadge>
        )}
      </div>

      {/* State transitions */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        State transitions
      </h2>
      {transitions.length === 0 ? (
        <p className="text-xs text-text-muted">
          Terminal state. No further transitions possible.
        </p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {transitions.map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => patchMut.mutate({ status: t })}
              disabled={patchMut.isPending}
              className="px-3 py-1.5 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50"
            >
              → {t}
            </button>
          ))}
        </div>
      )}</AilaCard>

      {/* Vendor reference + bounty */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        Vendor + bounty
      </h2>
      <div className="space-y-2 text-sm">
        <div>
          <span className="text-text-muted">Vendor reference: </span>
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
            className="ml-2 px-2 py-1 text-xs font-mono rounded-md bg-surface border border-border-default"
          />
        </div>
        <div>
          <span className="text-text-muted">Bounty (USD): </span>
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
            className="ml-2 px-2 py-1 w-32 text-xs font-mono rounded-md bg-surface border border-border-default"
          />
        </div>
      </div></AilaCard>

      {/* Validation errors */}
      {sub.validation_errors.length > 0 && (
        <AilaCard className="border-border-danger" techBorder glow><h2 className="text-sm font-semibold text-text-danger mb-2">
          Validation errors ({sub.validation_errors.length})
        </h2>
        <ul className="text-xs space-y-1">
          {sub.validation_errors.map((err, i) => (
            <li key={i} className="text-text-danger">
              · {err}
            </li>
          ))}
        </ul></AilaCard>
      )}

      {/* Re-render */}
      <AilaCard  techBorder glow><div className="flex items-center justify-between mb-2 flex-wrap gap-2">
        <h2 className="text-sm font-semibold text-foreground">
          Rendered submission body
        </h2>
        <div className="flex items-center gap-1">
          {renderMut.data?.data.body && (
            <>
              <button
                type="button"
                onClick={() => {
                  void navigator.clipboard?.writeText(
                    renderMut.data!.data.body,
                  );
                }}
                className="text-xs px-2 py-1 rounded bg-surface border border-border-default hover:bg-surface-hover"
                title="Copy as Markdown"
              >
                Copy MD
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
                className="text-xs px-2 py-1 rounded bg-surface border border-border-default hover:bg-surface-hover"
                title="Download as JSON (machine-readable)"
              >
                Download JSON
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
                className="text-xs px-2 py-1 rounded bg-surface border border-border-default hover:bg-surface-hover"
                title="Download as Markdown (for emails)"
              >
                Download MD
              </button>
              <button
                type="button"
                onClick={() => {
                  // MITRE CVE 5.x JSON template — minimal shell.
                  // Full per-field mapping requires a backend renderer
                  // (track_id + finding_id → CVE JSON 5.x).
                  const tpl = {
                    dataType: "CVE_RECORD",
                    dataVersion: "5.1",
                    cveMetadata: {
                      cveId:
                        sub.vendor_reference ??
                        "CVE-PLACEHOLDER",
                      assignerOrgId: "(your org id)",
                      state: "PUBLISHED",
                    },
                    containers: {
                      cna: {
                        title: sub.track_info?.display_name ?? sub.track_id,
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
                className="text-xs px-2 py-1 rounded bg-surface border border-border-default hover:bg-surface-hover"
                title="Download as MITRE CVE 5.1 JSON skeleton"
              >
                MITRE template
              </button>
              <button
                type="button"
                onClick={() => {
                  // Browser print dialog → 'Save as PDF'. Operator
                  // gets a real PDF without us shipping a PDF
                  // generator. The print stylesheet on PageFrame
                  // already strips chrome.
                  window.print();
                }}
                className="text-xs px-2 py-1 rounded bg-surface border border-border-default hover:bg-surface-hover"
                title="Use browser 'Save as PDF' from the print dialog"
              >
                PDF (print)
              </button>
            </>
          )}
          <button
            type="button"
            onClick={() => renderMut.mutate()}
            disabled={renderMut.isPending}
            className="text-xs px-3 py-1 rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50"
          >
            {renderMut.isPending ? "Rendering…" : "Re-render"}
          </button>
        </div>
      </div>
      {renderMut.data ? (
        <pre className="text-xs font-mono text-foreground whitespace-pre-wrap overflow-x-auto bg-surface p-3 rounded-md max-h-96 overflow-y-auto">
          {renderMut.data.data.body}
        </pre>
      ) : (
        <p className="text-xs text-text-muted">
          Body is rendered + stored on every status / poc-tier / embargo
          change. Click <strong>Re-render</strong> to refresh after editing
          the underlying finding.
        </p>
      )}</AilaCard>

      {/* CVSS calculator — interactive scoring per 08_FRONTEND_UX.md §1.8.2 */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        CVSS v3.1 score
      </h2>
      <p className="text-xs text-text-muted mb-3">
        Pick one value per metric. Vector + base score recompute live.
        Persisting the score back to the submission is{" "}
        <em>backend pending</em> — copy the vector string into the
        advisory body for now.
      </p>
      <CVSSCalculator /></AilaCard>

      {/* Track info */}
      {sub.track_info && (
        <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
          Track metadata
        </h2>
        <dl className="grid grid-cols-2 gap-2 text-xs">
          <div>
            <dt className="text-text-muted">Program URL</dt>
            <dd className="font-mono">
              {sub.track_info.program_url ?? "—"}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted">Severity schema</dt>
            <dd className="font-mono">{sub.track_info.severity_schema}</dd>
          </div>
          <div className="col-span-2">
            <dt className="text-text-muted">Required artifacts</dt>
            <dd className="font-mono">
              {sub.track_info.required_artifacts.join(", ") || "—"}
            </dd>
          </div>
          <div className="col-span-2">
            <dt className="text-text-muted">Accepted PoC tiers</dt>
            <dd className="font-mono">
              {sub.track_info.accepted_poc_tiers.join(", ")}
            </dd>
          </div>
          <div className="col-span-2">
            <dt className="text-text-muted">Notes</dt>
            <dd className="text-text-muted">{sub.track_info.notes}</dd>
          </div>
        </dl></AilaCard>
      )}
      {/* Structured advisory editor (§1.8) — sections backed by
          POST /disclosures/{id}/sections + regenerate-from-finding. */}
      <DisclosureSectionsEditor submission={sub} />

      {/* Disclosure timeline thread (§1.8). Spec calls for a vertical
          thread of state transitions with timestamps. v0.5 surfaces
          what the contract exposes: drafted → submitted (= created_at)
          → current_status (= updated_at) plus embargo + bounty events.
          A real per-event log requires VRDisclosureTransitionRecord. */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        Disclosure timeline
      </h2>
      <ol className="space-y-2 text-xs">
        <TimelineRow
          time={sub.created_at}
          label="drafted"
          note="submission record created"
        />
        {sub.status !== "drafted" && (
          <TimelineRow
            time={sub.updated_at}
            label={sub.status}
            note={`status now: ${sub.status}`}
          />
        )}
        {sub.embargo_until && (
          <TimelineRow
            time={sub.embargo_until}
            label="embargo until"
            note="public disclosure permitted on / after this date"
          />
        )}
        {sub.bounty_awarded_usd != null && sub.bounty_awarded_usd > 0 && (
          <TimelineRow
            time={sub.updated_at}
            label="bounty"
            note={`$${sub.bounty_awarded_usd.toLocaleString()} awarded`}
          />
        )}
      </ol>
      <div className="mt-2 border border-dashed border-border-default rounded p-2 bg-surface/40 text-3xs text-text-muted">
        Per-transition rows (who advanced status / when / why) require a
        VRDisclosureTransitionRecord on the backend. Currently only
        first + most-recent transitions render.
      </div></AilaCard>
    </div>
  );
}

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
    <li className="flex items-start gap-2 border border-border-default rounded px-2 py-1.5">
      <span className="w-2 h-2 rounded-full bg-accent mt-1.5 flex-shrink-0" />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-foreground">{label}</span>
          <span className="text-text-muted">
            {time ? new Date(time).toLocaleString() : "—"}
          </span>
        </div>
        {note && <p className="text-text-muted text-3xs mt-0.5">{note}</p>}
      </div>
    </li>
  );
}

const SECTION_ORDER = [
  { key: "summary", label: "Summary" },
  { key: "technical_details", label: "Technical details" },
  { key: "reproduction", label: "Reproduction" },
  { key: "patches", label: "Patches" },
  { key: "references", label: "References" },
] as const;

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

  return (
    <AilaCard  techBorder glow><div className="flex items-center justify-between mb-2 gap-2 flex-wrap">
      <div>
        <h2 className="text-sm font-semibold text-foreground">
          Structured advisory editor
        </h2>
        <p className="text-3xs text-text-muted mt-0.5">
          Save replaces the body; Regenerate refills every section
          from the finding ({regeneratedAt
            ? `last regenerated ${new Date(regeneratedAt).toLocaleString()}`
            : "never regenerated"}).
        </p>
      </div>
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={regenMut.isPending}
          onClick={() => {
            if (window.confirm(
              "Regenerating REPLACES every section with text derived "
              + "from the finding (advisory + PoC). Operator edits "
              + "above will be lost. Continue?",
            )) {
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
          className="px-3 py-1.5 text-xs font-medium rounded bg-surface border border-border-default hover:bg-surface-hover disabled:opacity-40"
        >
          {regenMut.isPending ? "Regenerating…" : "Regenerate from finding"}
        </button>
        <button
          type="button"
          disabled={patchMut.isPending}
          onClick={() => patchMut.mutate(draft)}
          className="px-3 py-1.5 text-xs font-medium rounded bg-accent text-white hover:bg-accent/90 disabled:opacity-40"
        >
          {patchMut.isPending ? "Saving…" : "Save sections"}
        </button>
      </div>
    </div>
    <div className="space-y-3">
      {SECTION_ORDER.map(({ key, label }) => (
        <div key={key}>
          <label
            htmlFor={`section-${key}`}
            className="block text-xs font-mono text-text-muted mb-1"
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
            className="w-full px-2 py-1.5 text-sm font-mono rounded bg-surface border border-border-default"
          />
        </div>
      ))}
    </div></AilaCard>
  );
}
