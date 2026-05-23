import { useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import { useDeleteDisclosure } from "../mutations";
import { useDisclosures, useDisclosureTracks } from "../queries";
import type { DisclosureSubmissionStatus } from "../types";

const STATUS_COLOR: Record<
  DisclosureSubmissionStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  drafted: "info",
  submitted: "medium",
  acknowledged: "medium",
  triaging: "medium",
  accepted: "low",
  rejected: "high",
  patched: "low",
  published: "low",
  closed: "info",
  withdrawn: "high",
};

const STATUSES: DisclosureSubmissionStatus[] = [
  "drafted", "submitted", "acknowledged", "triaging", "accepted",
  "rejected", "patched", "published", "closed", "withdrawn",
];

export function DisclosuresPage() {
  const navigate = useNavigate();
  const { data: tracksData } = useDisclosureTracks();
  const tracks = tracksData ?? [];
  const deleteMut = useDeleteDisclosure();

  const [trackFilter, setTrackFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<DisclosureSubmissionStatus | "">("");

  const { data: result, isLoading, isError } = useDisclosures({
    trackId: trackFilter || undefined,
    status: statusFilter || undefined,
  });
  const rows = result?.data ?? [];

  return (
    <div className="space-y-4">

      <AilaCard  techBorder glow><div className="flex items-center gap-2 flex-wrap">
        <label className="text-sm text-text-muted">Track:</label>
        <select
          value={trackFilter}
          onChange={(e) => setTrackFilter(e.target.value)}
          className="px-3 py-1.5 text-sm font-mono rounded-md bg-surface border border-border-default"
        >
          <option value="">— all —</option>
          {tracks.map((t) => (
            <option key={t.track_id} value={t.track_id}>
              {t.display_name} ({t.kind})
            </option>
          ))}
        </select>
      
        <label className="text-sm text-text-muted ml-2">Status:</label>
        <select
          value={statusFilter}
          onChange={(e) =>
            setStatusFilter(e.target.value as DisclosureSubmissionStatus | "")
          }
          className="px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default"
        >
          <option value="">— all —</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      
        <span className="text-xs text-text-muted ml-auto">
          {rows.length} submission{rows.length === 1 ? "" : "s"}
        </span>
      </div></AilaCard>

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Failed to load disclosures.</p></AilaCard>
      )}

      {!isLoading && !isError && rows.length === 0 && (
        <AilaCard  techBorder glow><p className="text-center py-6 text-text-muted">
          No disclosure submissions. Create one via POST /vr/disclosures
          referencing a finding_id.
        </p></AilaCard>
      )}

      {!isLoading && !isError && rows.length > 0 && (
        <AilaCard className="overflow-x-auto p-0" techBorder glow><table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
              <th className="px-4 py-2 font-semibold">Track</th>
              <th className="px-4 py-2 font-semibold">Status</th>
              <th className="px-4 py-2 font-semibold">PoC tier</th>
              <th className="px-4 py-2 font-semibold">Severity</th>
              <th className="px-4 py-2 font-semibold">Embargo until</th>
              <th className="px-4 py-2 font-semibold">Vendor ref</th>
              <th className="px-4 py-2 font-semibold text-right">Bounty</th>
              <th className="px-2 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr
                key={r.id}
                onClick={() => navigate(`/vr/disclosures/${r.id}`)}
                className="border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors"
              >
                <td className="px-4 py-2 font-mono text-xs text-foreground">
                  {r.track_info?.display_name ?? r.track_id}
                </td>
                <td className="px-4 py-2">
                  <AilaBadge severity={STATUS_COLOR[r.status]} size="sm">
                    {r.status}
                  </AilaBadge>
                </td>
                <td className="px-4 py-2 font-mono text-xs">{r.poc_tier}</td>
                <td className="px-4 py-2 text-xs">
                  {r.severity_rating ?? "—"}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  {r.embargo_until
                    ? new Date(r.embargo_until).toLocaleDateString()
                    : "—"}
                </td>
                <td className="px-4 py-2 font-mono text-xs">
                  {r.vendor_reference ?? "—"}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-right">
                  {r.bounty_awarded_usd != null
                    ? `$${r.bounty_awarded_usd.toLocaleString()}`
                    : "—"}
                </td>
                <td className="px-2 py-2 text-right">
                  <DeleteButton
                    id={r.id}
                    label={`disclosure to ${r.track_id}`}
                    mutation={deleteMut}
                    compact
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table></AilaCard>
      )}
    </div>
  );
}
