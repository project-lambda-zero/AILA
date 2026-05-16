import { useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { usePatchDisclosure, useRenderDisclosure } from "../mutations";
import { useDisclosure } from "../queries";
import type { DisclosureSubmissionStatus } from "../types";

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

  if (isLoading || !sub) return <LoadingSkeleton size="lg" width="full" />;

  const transitions = NEXT_STATES[sub.status] ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold font-mono text-foreground">
          {sub.track_info?.display_name ?? sub.track_id}
        </h1>
        <p className="text-sm text-text-muted mt-1 font-mono">
          finding:{sub.finding_id} · workspace:{sub.workspace_id} · status:
          {sub.status}
        </p>
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
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
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
        )}
      </AilaCard>

      {/* Vendor reference + bounty */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
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
        </div>
      </AilaCard>

      {/* Validation errors */}
      {sub.validation_errors.length > 0 && (
        <AilaCard className="border-border-danger">
          <h2 className="text-sm font-semibold text-text-danger mb-2">
            Validation errors ({sub.validation_errors.length})
          </h2>
          <ul className="text-xs space-y-1">
            {sub.validation_errors.map((err, i) => (
              <li key={i} className="text-text-danger">
                · {err}
              </li>
            ))}
          </ul>
        </AilaCard>
      )}

      {/* Re-render */}
      <AilaCard>
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-sm font-semibold text-foreground">
            Rendered submission body
          </h2>
          <button
            type="button"
            onClick={() => renderMut.mutate()}
            disabled={renderMut.isPending}
            className="text-xs px-3 py-1 rounded-md bg-surface border border-border-default hover:bg-surface-hover disabled:opacity-50"
          >
            {renderMut.isPending ? "Rendering…" : "Re-render"}
          </button>
        </div>
        {renderMut.data ? (
          <pre className="text-xs font-mono text-foreground whitespace-pre-wrap overflow-x-auto bg-surface p-3 rounded-md">
            {renderMut.data.data.body}
          </pre>
        ) : (
          <p className="text-xs text-text-muted">
            Body is rendered + stored on every status / poc-tier / embargo
            change. Click <strong>Re-render</strong> to refresh after editing
            the underlying finding.
          </p>
        )}
      </AilaCard>

      {/* Track info */}
      {sub.track_info && (
        <AilaCard>
          <h2 className="text-sm font-semibold text-foreground mb-2">
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
          </dl>
        </AilaCard>
      )}
    </div>
  );
}
