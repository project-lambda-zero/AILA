import { useMemo, useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import { useCreateDisclosure, useDeleteDisclosure } from "../mutations";
import {
  useDisclosures,
  useDisclosureTracks,
  useInvestigations,
  useWorkspaces,
} from "../queries";
import type {
  ArtifactTier,
  DisclosureSubmissionStatus,
} from "../types";

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

const POC_TIERS: { value: ArtifactTier; label: string }[] = [
  { value: "working_poc",   label: "Working PoC" },
  { value: "sanitized_poc", label: "Sanitized PoC" },
  { value: "no_poc",        label: "No PoC" },
];

export function DisclosuresPage() {
  const navigate = useNavigate();
  const { data: tracksData } = useDisclosureTracks();
  const tracks = tracksData ?? [];
  const { data: workspacesData } = useWorkspaces();
  const workspaces = workspacesData?.data ?? [];
  // Pull a wide window of investigations so the chooser has enough rows
  // without paginating; tune later if the team's catalogue exceeds 200.
  const { data: investigationsData } = useInvestigations({ limit: 200 });
  const investigations = investigationsData?.data ?? [];
  const createMut = useCreateDisclosure();
  const deleteMut = useDeleteDisclosure();

  const [trackFilter, setTrackFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<DisclosureSubmissionStatus | "">("");

  // ── Create-form state ────────────────────────────────────────────
  // Anchor is now an investigation, not a raw finding UUID. The
  // service resolves the chosen investigation's single linked finding,
  // or auto-creates a stub finding when none exists. Multi-finding
  // investigations error out so the operator goes to the finding
  // detail page and disambiguates there.
  const [showForm, setShowForm] = useState(false);
  const [formInvestigationId, setFormInvestigationId] = useState("");
  const [formTrackId, setFormTrackId]         = useState("");
  const [formWorkspaceId, setFormWorkspaceId] = useState("");
  const [formPocTier, setFormPocTier]         = useState<ArtifactTier | "">("");
  const [formSeverity, setFormSeverity]       = useState("");
  const [formEmbargo, setFormEmbargo]         = useState("");
  const [formNotes, setFormNotes]             = useState("");

  const selectedInvestigation = useMemo(
    () => investigations.find((i) => i.id === formInvestigationId) || null,
    [investigations, formInvestigationId],
  );

  /** Short hint shown under the investigation picker so the operator
   *  knows what the service will do with this investigation: bind to
   *  the existing finding, auto-create a stub, or reject. */
  const findingHint = useMemo(() => {
    if (!selectedInvestigation) return null;
    const n = selectedInvestigation.linked_finding_ids?.length ?? 0;
    if (n === 1) {
      return {
        tone: "ok" as const,
        text: "Will bind to the investigation's single linked finding.",
      };
    }
    if (n === 0) {
      return {
        tone: "warn" as const,
        text:
          "Investigation has no linked finding yet. The service will " +
          "auto-create a stub finding so the disclosure has something " +
          "to bind to; enrich it later in FindingDetailPage.",
      };
    }
    return {
      tone: "danger" as const,
      text:
        `Investigation has ${n} linked findings. The service can't pick ` +
        `one for you; open the finding detail page and create the ` +
        `disclosure from there.`,
    };
  }, [selectedInvestigation]);

  const trackIdValid     = formTrackId.trim().length > 0;
  const workspaceIdSet   = formWorkspaceId.trim().length > 0;
  const investigationOk  = !!selectedInvestigation &&
    (selectedInvestigation.linked_finding_ids?.length ?? 0) <= 1;
  const canSubmit =
    investigationOk && trackIdValid && workspaceIdSet && !createMut.isPending;

  const resetForm = () => {
    setFormInvestigationId("");
    setFormTrackId("");
    setFormWorkspaceId("");
    setFormPocTier("");
    setFormSeverity("");
    setFormEmbargo("");
    setFormNotes("");
  };

  const submitCreate = () => {
    const embargoNum = formEmbargo.trim()
      ? Number.parseInt(formEmbargo.trim(), 10)
      : undefined;
    createMut.mutate(
      {
        investigation_id: formInvestigationId,
        track_id:         formTrackId.trim(),
        workspace_id:     formWorkspaceId.trim(),
        poc_tier:         formPocTier || undefined,
        severity_rating:
          formSeverity.trim() ? formSeverity.trim() : undefined,
        embargo_days_override:
          Number.isFinite(embargoNum) ? embargoNum : undefined,
        notes: formNotes.trim() ? formNotes.trim() : undefined,
      },
      {
        onSuccess: () => {
          setShowForm(false);
          resetForm();
        },
      },
    );
  };

  /** Auto-fill workspace when picking an investigation so the operator
   *  only adjusts the field when they explicitly want a different
   *  workspace; investigations carry their own workspace_id. */
  const pickInvestigation = (id: string) => {
    setFormInvestigationId(id);
    const inv = investigations.find((i) => i.id === id);
    if (inv?.workspace_id) {
      setFormWorkspaceId(inv.workspace_id);
    }
  };

  const { data: result, isLoading, isError } = useDisclosures({
    trackId: trackFilter || undefined,
    status: statusFilter || undefined,
  });
  const rows = result?.data ?? [];

  return (
    <div className="space-y-4">
      {/* CTA bar — toggles the inline create form below. */}
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => setShowForm((v) => !v)}
          className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors"
        >
          {showForm ? "Cancel" : "New Disclosure"}
        </button>
      </div>

      {showForm && (
        <AilaCard techBorder glow>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Create disclosure submission
          </h2>
          <p className="text-xs text-text-muted mb-3">
            Pick the investigation whose finding you want to disclose. The
            service resolves the investigation's single linked finding,
            or auto-creates a stub if none exists. Pick the disclosure
            track and a workspace; optional fields refine the embargo,
            severity, and PoC tier the track will use during submission.
          </p>
          <div className="space-y-2">
            <select
              value={formInvestigationId}
              onChange={(e) => pickInvestigation(e.target.value)}
              aria-label="Investigation"
              className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
            >
              <option value="">— pick an investigation —</option>
              {investigations.map((inv) => {
                const linkCount = inv.linked_finding_ids?.length ?? 0;
                const linkSuffix =
                  linkCount === 1
                    ? " · 1 finding"
                    : linkCount > 1
                      ? ` · ${linkCount} findings`
                      : " · no finding yet";
                return (
                  <option key={inv.id} value={inv.id}>
                    {inv.title} ({inv.kind} · {inv.status}){linkSuffix}
                  </option>
                );
              })}
            </select>
            {findingHint && (
              <p
                className={
                  findingHint.tone === "danger"
                    ? "text-xs text-text-danger"
                    : findingHint.tone === "warn"
                      ? "text-xs text-text-warning"
                      : "text-xs text-text-muted"
                }
              >
                {findingHint.text}
              </p>
            )}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <select
                value={formTrackId}
                onChange={(e) => setFormTrackId(e.target.value)}
                aria-label="Disclosure track"
                className="px-3 py-2 text-sm rounded-md bg-surface border border-border-default"
              >
                <option value="">— pick a track —</option>
                {tracks.map((t) => (
                  <option key={t.track_id} value={t.track_id}>
                    {t.display_name} ({t.kind})
                  </option>
                ))}
              </select>
              <select
                value={formWorkspaceId}
                onChange={(e) => setFormWorkspaceId(e.target.value)}
                aria-label="Workspace"
                className="px-3 py-2 text-sm rounded-md bg-surface border border-border-default"
              >
                <option value="">— pick a workspace —</option>
                {workspaces.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <select
                value={formPocTier}
                onChange={(e) =>
                  setFormPocTier(e.target.value as ArtifactTier | "")
                }
                aria-label="Proof-of-concept tier"
                className="px-3 py-2 text-sm rounded-md bg-surface border border-border-default"
              >
                <option value="">— PoC tier (auto) —</option>
                {POC_TIERS.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
              <input
                type="text"
                value={formSeverity}
                onChange={(e) => setFormSeverity(e.target.value)}
                placeholder="Severity rating (e.g. CVSS 8.1)"
                aria-label="Severity rating"
                className="px-3 py-2 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
              />
              <input
                type="number"
                min={0}
                value={formEmbargo}
                onChange={(e) => setFormEmbargo(e.target.value)}
                placeholder="Embargo days override"
                aria-label="Embargo days override"
                className="px-3 py-2 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
              />
            </div>
            <textarea
              value={formNotes}
              onChange={(e) => setFormNotes(e.target.value)}
              placeholder="Notes (optional)"
              rows={2}
              aria-label="Notes"
              className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
            />
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={!canSubmit}
                onClick={submitCreate}
                className="ml-auto px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors disabled:opacity-50"
              >
                {createMut.isPending ? "Creating…" : "Create"}
              </button>
            </div>
          </div>
        </AilaCard>
      )}

      <AilaCard  techBorder glow><div className="flex items-center gap-2 flex-wrap">
        <label className="text-sm text-text-muted">Track:</label>
        <select
          value={trackFilter}
          onChange={(e) => setTrackFilter(e.target.value)}
          aria-label="Filter by track"
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
          aria-label="Filter by status"
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
          No disclosure submissions yet. Click <b>New Disclosure</b> above to
          file one against a finding.
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
