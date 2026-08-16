import { useMemo, useState } from "react";
import { useNavigate } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  DataGrid,
  MonoBadge,
  SectionHeader,
} from "@/components/aila/mock";

import { DeleteButton } from "../components/DeleteButton";
import { useCreateDisclosure, useDeleteDisclosure } from "../mutations";
import {
  useDisclosures,
  useDisclosureTracks,
  useInvestigations,
  useWorkspaces,
} from "../queries";
import { useVRListInvalidation } from "../hooks/useVRListInvalidation";
import type {
  ArtifactTier,
  DisclosureSubmissionStatus,
  VRDisclosureSubmissionSummary,
} from "../types";

// Status -> MonoBadge tone. Preserves the prior status vocabulary
// (drafted/submitted/... rejected/withdrawn) but expressed in the mock
// tone keys (info/medium/ok/high).
const STATUS_TONE: Record<DisclosureSubmissionStatus, string> = {
  drafted: "info",
  submitted: "medium",
  acknowledged: "medium",
  triaging: "medium",
  accepted: "ok",
  rejected: "high",
  patched: "ok",
  published: "ok",
  closed: "info",
  withdrawn: "high",
};

const STATUSES: DisclosureSubmissionStatus[] = [
  "drafted",
  "submitted",
  "acknowledged",
  "triaging",
  "accepted",
  "rejected",
  "patched",
  "published",
  "closed",
  "withdrawn",
];

const POC_TIERS: { value: ArtifactTier; label: string }[] = [
  { value: "working_poc", label: "Working PoC" },
  { value: "sanitized_poc", label: "Sanitized PoC" },
  { value: "no_poc", label: "No PoC" },
];

// Mock chrome for raw form controls -- matches sibling filter shelves.
const CTRL: React.CSSProperties = {
  height: 26,
  fontSize: 10.5,
  padding: "0 8px",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
  letterSpacing: "0.04em",
  outline: "none",
  fontFamily: "var(--font-mono)",
};

export function DisclosuresPage() {
  const navigate = useNavigate();
  useVRListInvalidation("disclosures");
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
  const [statusFilter, setStatusFilter] = useState<
    DisclosureSubmissionStatus | ""
  >("");

  // ── Create-form state ────────────────────────────────────────────
  // Anchor is now an investigation, not a raw finding UUID. The
  // service resolves the chosen investigation's single linked finding,
  // or auto-creates a stub finding when none exists. Multi-finding
  // investigations error out so the operator goes to the finding
  // detail page and disambiguates there.
  const [showForm, setShowForm] = useState(false);
  const [formInvestigationId, setFormInvestigationId] = useState("");
  const [formTrackId, setFormTrackId] = useState("");
  const [formWorkspaceId, setFormWorkspaceId] = useState("");
  const [formPocTier, setFormPocTier] = useState<ArtifactTier | "">("");
  const [formSeverity, setFormSeverity] = useState("");
  const [formEmbargo, setFormEmbargo] = useState("");
  const [formNotes, setFormNotes] = useState("");

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
        text: "will bind to the investigation's single linked finding.",
      };
    }
    if (n === 0) {
      return {
        tone: "warn" as const,
        text:
          "investigation has no linked finding yet. the service will " +
          "auto-create a stub finding so the disclosure has something " +
          "to bind to; enrich it later in FindingDetailPage.",
      };
    }
    return {
      tone: "danger" as const,
      text:
        `investigation has ${n} linked findings. the service can't pick ` +
        `one for you; open the finding detail page and create the ` +
        `disclosure from there.`,
    };
  }, [selectedInvestigation]);

  const trackIdValid = formTrackId.trim().length > 0;
  const workspaceIdSet = formWorkspaceId.trim().length > 0;
  const investigationOk =
    !!selectedInvestigation &&
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
        track_id: formTrackId.trim(),
        workspace_id: formWorkspaceId.trim(),
        poc_tier: formPocTier || undefined,
        severity_rating: formSeverity.trim() ? formSeverity.trim() : undefined,
        embargo_days_override: Number.isFinite(embargoNum)
          ? embargoNum
          : undefined,
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

  // /vr/disclosures has no `q` server-side param -- quick-filter runs
  // client-side over track / vendor_reference / severity / poc_tier /
  // status text.
  const [query, setQuery] = useState("");

  const { data: result, isLoading, isError } = useDisclosures({
    trackId: trackFilter || undefined,
    status: statusFilter || undefined,
  });
  const rows = result?.data ?? [];

  const filteredRows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((r) => {
      const trackLabel = r.track_info?.display_name ?? r.track_id;
      return (
        trackLabel.toLowerCase().includes(needle) ||
        r.status.toLowerCase().includes(needle) ||
        r.poc_tier.toLowerCase().includes(needle) ||
        (r.severity_rating ?? "").toLowerCase().includes(needle) ||
        (r.vendor_reference ?? "").toLowerCase().includes(needle)
      );
    });
  }, [rows, query]);

  // ─── Header actions: + new disclosure ───
  const headerActions = (
    <button
      type="button"
      onClick={() => setShowForm((v) => !v)}
      className="font-mono uppercase"
      style={{
        height: 28,
        padding: "0 12px",
        fontSize: 10,
        letterSpacing: "0.08em",
        background: showForm ? "var(--surface-sunk)" : "var(--accent)",
        border:
          "1px solid " +
          (showForm ? "var(--border-soft)" : "var(--accent)"),
        color: showForm ? "var(--text-primary)" : "var(--text-on-accent)",
        borderRadius: 3,
        cursor: "pointer",
      }}
    >
      {showForm ? "cancel" : "+ new disclosure"}
    </button>
  );

  // ─── Create form ───
  const hintColor =
    findingHint?.tone === "danger"
      ? "var(--accent)"
      : findingHint?.tone === "warn"
        ? "var(--status-warn)"
        : "var(--text-muted)";

  const createFormPanel = showForm ? (
    <WindowPanel title="new disclosure" tone="accent">
      <div className="flex flex-col" style={{ gap: 10 }}>
        <p
          className="font-mono"
          style={{
            fontSize: 10.5,
            color: "var(--text-muted)",
            letterSpacing: "0.02em",
            lineHeight: 1.5,
          }}
        >
          pick the investigation whose finding you want to disclose. the
          service resolves the investigation's single linked finding, or
          auto-creates a stub if none exists. pick the disclosure track and
          a workspace; optional fields refine the embargo, severity, and
          PoC tier the track will use during submission.
        </p>
        <select
          value={formInvestigationId}
          onChange={(e) => pickInvestigation(e.target.value)}
          aria-label="Investigation"
          className="font-mono w-full"
          style={{ ...CTRL, height: 30, fontSize: 11 }}
        >
          <option value="">-- pick an investigation --</option>
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
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: hintColor,
              letterSpacing: "0.02em",
            }}
          >
            {findingHint.text}
          </p>
        )}
        <div
          className="grid"
          style={{ gridTemplateColumns: "1fr 1fr", gap: 8 }}
        >
          <select
            value={formTrackId}
            onChange={(e) => setFormTrackId(e.target.value)}
            aria-label="Disclosure track"
            className="font-mono uppercase"
            style={{ ...CTRL, height: 30, fontSize: 11 }}
          >
            <option value="">-- pick a track --</option>
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
            className="font-mono uppercase"
            style={{ ...CTRL, height: 30, fontSize: 11 }}
          >
            <option value="">-- pick a workspace --</option>
            {workspaces.map((w) => (
              <option key={w.id} value={w.id}>
                {w.name}
              </option>
            ))}
          </select>
        </div>
        <div
          className="grid"
          style={{ gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}
        >
          <select
            value={formPocTier}
            onChange={(e) =>
              setFormPocTier(e.target.value as ArtifactTier | "")
            }
            aria-label="Proof-of-concept tier"
            className="font-mono uppercase"
            style={{ ...CTRL, height: 30, fontSize: 11 }}
          >
            <option value="">-- PoC tier (auto) --</option>
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
            placeholder="severity rating (e.g. CVSS 8.1)"
            aria-label="Severity rating"
            className="font-mono"
            style={{ ...CTRL, height: 30, fontSize: 11 }}
          />
          <input
            type="number"
            min={0}
            value={formEmbargo}
            onChange={(e) => setFormEmbargo(e.target.value)}
            placeholder="embargo days override"
            aria-label="Embargo days override"
            className="font-mono"
            style={{ ...CTRL, height: 30, fontSize: 11 }}
          />
        </div>
        <textarea
          value={formNotes}
          onChange={(e) => setFormNotes(e.target.value)}
          placeholder="notes (optional)"
          rows={2}
          aria-label="Notes"
          className="font-mono w-full"
          style={{
            ...CTRL,
            height: "auto",
            padding: "8px 10px",
            fontSize: 11,
            resize: "vertical",
          }}
        />
        <div className="flex items-center" style={{ gap: 8 }}>
          <button
            type="button"
            disabled={!canSubmit}
            onClick={submitCreate}
            className="font-mono uppercase"
            style={{
              marginLeft: "auto",
              height: 28,
              padding: "0 14px",
              fontSize: 10,
              letterSpacing: "0.08em",
              background: "var(--accent)",
              border: "1px solid var(--accent)",
              color: "var(--text-on-accent)",
              borderRadius: 3,
              cursor: canSubmit ? "pointer" : "not-allowed",
              opacity: canSubmit ? 1 : 0.5,
            }}
          >
            {createMut.isPending ? "creating…" : "create"}
          </button>
        </div>
      </div>
    </WindowPanel>
  ) : null;

  // ─── Filter shelf ───
  const filterShelf = (
    <WindowPanel title="filters" tone="muted">
      <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter (track / vendor / severity)…"
          aria-label="Filter disclosures"
          className="font-mono"
          style={{ ...CTRL, width: 260 }}
        />
        <select
          value={trackFilter}
          onChange={(e) => setTrackFilter(e.target.value)}
          aria-label="Filter by track"
          className="font-mono uppercase"
          style={CTRL}
        >
          <option value="">all tracks</option>
          {tracks.map((t) => (
            <option key={t.track_id} value={t.track_id}>
              {t.display_name} ({t.kind})
            </option>
          ))}
        </select>
        <select
          value={statusFilter}
          onChange={(e) =>
            setStatusFilter(
              e.target.value as DisclosureSubmissionStatus | "",
            )
          }
          aria-label="Filter by status"
          className="font-mono uppercase"
          style={CTRL}
        >
          <option value="">all status</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <span style={{ flex: 1 }} />
        <span
          className="font-mono"
          style={{
            fontSize: 10,
            color: "var(--text-faint)",
            letterSpacing: "0.06em",
          }}
        >
          {query.trim()
            ? `${filteredRows.length} of ${rows.length}`
            : `${rows.length}`}
          {" "}submission{rows.length === 1 ? "" : "s"}
        </span>
      </div>
    </WindowPanel>
  );

  // ─── Table ───
  const columns: {
    label: string;
    width: string;
    align?: "left" | "right" | "center";
  }[] = [
    { label: "track", width: "1fr" },
    { label: "status", width: "110px" },
    { label: "poc tier", width: "120px" },
    { label: "severity", width: "110px" },
    { label: "embargo until", width: "130px" },
    { label: "vendor ref", width: "130px" },
    { label: "bounty", width: "90px", align: "right" },
    { label: "", width: "40px", align: "center" },
  ];

  function renderCells(r: VRDisclosureSubmissionSummary): React.ReactNode[] {
    const trackLabel = r.track_info?.display_name ?? r.track_id;
    return [
      <span
        className="font-mono"
        title={trackLabel}
        style={{
          fontSize: 11.5,
          color: "var(--text-primary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
      >
        {trackLabel}
      </span>,
      <MonoBadge tone={STATUS_TONE[r.status]}>{r.status}</MonoBadge>,
      <span
        className="font-mono"
        style={{ fontSize: 10.5, color: "var(--text-muted)" }}
      >
        {r.poc_tier}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 10.5, color: "var(--text-primary)" }}
      >
        {r.severity_rating ?? "--"}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 10, color: "var(--text-faint)" }}
      >
        {r.embargo_until
          ? new Date(r.embargo_until).toLocaleDateString()
          : "--"}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 10.5, color: "var(--text-muted)" }}
      >
        {r.vendor_reference ?? "--"}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-primary)" }}
      >
        {r.bounty_awarded_usd != null
          ? `$${r.bounty_awarded_usd.toLocaleString()}`
          : "--"}
      </span>,
      <span onClick={(e) => e.stopPropagation()}>
        <DeleteButton
          id={r.id}
          label={`disclosure to ${r.track_id}`}
          mutation={deleteMut}
          compact
        />
      </span>,
    ];
  }

  const tableActions = (
    <span
      className="font-mono"
      style={{
        fontSize: 10,
        letterSpacing: "0.06em",
        color: "var(--text-faint)",
      }}
    >
      {filteredRows.length}
      <span style={{ opacity: 0.5 }}> / {rows.length}</span>
    </span>
  );

  let tableBody: React.ReactNode;
  if (isLoading) {
    tableBody = (
      <div style={{ padding: 12 }}>
        <LoadingSkeleton size="lg" width="full" />
      </div>
    );
  } else if (isError) {
    tableBody = (
      <div
        className="font-mono"
        style={{
          padding: 24,
          textAlign: "center",
          color: "var(--accent)",
          fontSize: 11,
          letterSpacing: "0.06em",
        }}
      >
        failed to load disclosures.
      </div>
    );
  } else {
    tableBody = (
      <DataGrid
        columns={columns}
        rows={filteredRows}
        renderCells={renderCells}
        getKey={(r) => r.id}
        onRowClick={(r) => navigate(`/vr/disclosures/${r.id}`)}
        empty={
          <div
            className="font-mono"
            style={{
              padding: 34,
              textAlign: "center",
              fontSize: 11.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            {query.trim() || trackFilter || statusFilter
              ? "no submissions match the current filters."
              : "no disclosure submissions yet -- file one from the header."}
          </div>
        }
      />
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader
        icon="◈"
        title="Disclosures"
        actions={headerActions}
      />
      {createFormPanel}
      {filterShelf}
      <WindowPanel
        title="results"
        tone="accent"
        actions={tableActions}
        flush
      >
        {tableBody}
      </WindowPanel>
    </div>
  );
}
