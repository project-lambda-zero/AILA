import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useQueryClient } from "@tanstack/react-query";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  MonoBadge,
  SectionHeader,
} from "@/components/aila/mock";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

import { CVSSBadge, CVSSBreakdown, CWEBadge } from "../components/CVSSBadge";
import { AdjudicationBanner } from "../components/AdjudicationBanner";
import { ObligationChecklist } from "../components/ObligationChecklist";
import { FindingConnectedCard } from "../components/FindingConnectedCard";
import { useDraftPoc } from "../mutations";
import { useVRFinding, useVRFindingById } from "../queries";
import type { DisclosureStatus } from "../types";

// Disclosure tone mapping -- MonoBadge tone key vocabulary.
const DISCLOSURE_TONE: Record<DisclosureStatus, string> = {
  undisclosed: "warn",
  reported: "info",
  acknowledged: "info",
  patch_pending: "info",
  patched: "ok",
  public: "ok",
};

/** Finding Detail page -- 10-section layout from 08_FRONTEND_UX.md §1.6.
 *
 *  Sections:
 *    1. Root cause
 *    2. Vulnerable function
 *    3. CVSS breakdown (8-metric table + colored badge)
 *    4. CWE badge
 *    5. PoC code (mono block + copy + download + open-in-editor)
 *    6. ASAN report (monospaced, scrollable)
 *    7. Crash signature (hash prefix + normalized frames)
 *    8. Exploitability verdict + rationale
 *    9. Disclosure status + inline editor
 *   10. Advisory preview
 *
 *  Several spec'd fields (cvss_vector, cvss_source, cwe_id, exploitability_
 *  verdict, exploitability_rationale) do not exist on the backend VRFinding
 *  contract yet. Sections render their headers with "backend pending"
 *  placeholders so the surface is honest about what's wired. */
export function FindingDetailPage() {
  // Two routes resolve into this page:
  //   /vr/projects/:projectId/findings/:findingId  → projectId set
  //   /vr/findings/:findingId                       → projectId empty
  // Findings without a project (e.g. stubs auto-created by the
  // disclosure-from-investigation flow) reach the page only via the
  // second route.
  const { projectId = "", findingId = "" } = useParams<{
    projectId: string;
    findingId: string;
  }>();
  const navigate = useNavigate();
  const scopedQuery = useVRFinding(projectId, findingId);
  const globalQuery = useVRFindingById(projectId ? "" : findingId);
  const { data: finding, isLoading, isError } = projectId
    ? scopedQuery
    : globalQuery;

  const draftMut = useDraftPoc();
  const queryClient = useQueryClient();
  // Wall-clock timestamp of the last draft-poc submission. Non-null
  // means "poll aggressively until the writer's poc lands, or 3 minutes
  // elapse". Cleared when the poc.code differs from what we saw at
  // dispatch time (writer finished) or after the timeout.
  const [draftInFlightAt, setDraftInFlightAt] = useState<number | null>(null);
  // Snapshot of poc.code at the moment the operator hit Draft. Compared
  // against the live query result to detect that the writer's overwrite
  // has landed.
  const preDraftPocRef = useRef<string>("");
  const currentPocCode = finding?.poc?.code ?? "";
  useEffect(() => {
    if (draftInFlightAt == null) return;
    if (currentPocCode && currentPocCode !== preDraftPocRef.current) {
      setDraftInFlightAt(null);
      return;
    }
    // Bail after 3 minutes — the writer normally lands in 30-120s;
    // beyond that assume the task failed silently and stop polling.
    if (Date.now() - draftInFlightAt > 180_000) {
      setDraftInFlightAt(null);
      return;
    }
    const invalidateKey: readonly unknown[] = projectId
      ? ["vr", "finding", projectId, findingId]
      : ["vr", "finding-by-id", findingId];
    const t = setTimeout(() => {
      queryClient.invalidateQueries({ queryKey: invalidateKey });
    }, 8000);
    return () => clearTimeout(t);
  }, [draftInFlightAt, currentPocCode, projectId, findingId, queryClient]);

  // Fallback title chain: vulnerable_function (real triage),
  // root_cause's first line (audit-derived findings often carry a
  // narrative-only root cause), then the placeholder.
  const titleFallback = (() => {
    if (!finding) return undefined;
    if (finding.vulnerable_function) return finding.vulnerable_function;
    const firstLine = (finding.root_cause || "").split("\n")[0].trim();
    return firstLine.slice(0, 140) || "(unknown function)";
  })();

  useUpdatePageHeader({
    title: titleFallback,
    subtitle: undefined,
    status: null,
  });

  if (isLoading) {
    return (
      <div style={{ padding: 12 }}>
        <LoadingSkeleton size="lg" width="full" />
      </div>
    );
  }
  if (isError || !finding) {
    return (
      <div className="flex flex-col" style={{ gap: 14 }}>
        <SectionHeader icon="◈" title="finding" />
        <div
          className="font-mono"
          style={{
            padding: 24,
            textAlign: "center",
            fontSize: 11,
            color: "var(--accent)",
            border: "1px solid var(--accent)",
            background: "var(--surface-sunk)",
            borderRadius: 3,
            letterSpacing: "0.06em",
          }}
        >
          failed to load finding.
        </div>
      </div>
    );
  }

  // Backend doesn't carry these yet -- render section headers so the
  // shape is visible, with placeholder text matching spec vocabulary.
  type WithOptional = typeof finding & {
    cvss_score?: number | null;
    cvss_vector?: string | null;
    cvss_source?: string | null;
    cwe_id?: string | null;
    cwe_name?: string | null;
    exploitability_verdict?: string | null;
    exploitability_rationale?: string | null;
  };
  const f = finding as WithOptional;

  const pocFileName = f.assigned_cve_id
    ? `poc_${f.assigned_cve_id.replace(/[^A-Za-z0-9_-]/g, "_")}.${
        f.poc?.language === "python" ? "py" : "c"
      }`
    : `poc.${f.poc?.language === "python" ? "py" : "c"}`;

  function downloadPoC() {
    if (!f.poc?.code) return;
    const blob = new Blob([f.poc.code], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = pocFileName;
    a.click();
    URL.revokeObjectURL(url);
  }

  const headerActions = (
    <button
      type="button"
      onClick={() => navigate(-1)}
      className="font-mono uppercase"
      style={{
        height: 28,
        padding: "0 12px",
        fontSize: 10,
        letterSpacing: "0.08em",
        background: "var(--surface-sunk)",
        border: "1px solid var(--border-soft)",
        color: "var(--text-primary)",
        borderRadius: 3,
        cursor: "pointer",
      }}
    >
      ← back
    </button>
  );

  const pocActions = (
    <div className="flex flex-wrap items-center" style={{ gap: 6 }}>
      <button
        type="button"
        disabled={draftMut.isPending || draftInFlightAt != null}
        onClick={() => {
          preDraftPocRef.current = currentPocCode;
          draftMut.mutate(
            { findingId },
            { onSuccess: () => setDraftInFlightAt(Date.now()) },
          );
        }}
        title={
          f.poc?.code
            ? "Re-draft the PoC — overwrites the existing poc.code."
            : "Enqueue the PoC writer (run_vr_draft_poc). Result lands on this finding's poc.code in ~30-120s."
        }
        className="font-mono uppercase"
        style={{
          height: 24,
          padding: "0 10px",
          fontSize: 9.5,
          letterSpacing: "0.08em",
          background: "var(--accent)",
          border: "1px solid var(--accent)",
          color: "var(--text-on-accent)",
          borderRadius: 3,
          cursor:
            draftMut.isPending || draftInFlightAt != null
              ? "not-allowed"
              : "pointer",
          opacity:
            draftMut.isPending || draftInFlightAt != null ? 0.6 : 1,
        }}
      >
        {draftInFlightAt != null
          ? "drafting…"
          : draftMut.isPending
            ? "queuing…"
            : f.poc?.code
              ? "re-draft"
              : "draft"}
      </button>
      {f.poc?.code ? (
        <>
          <button
            type="button"
            onClick={() => {
              void navigator.clipboard?.writeText(f.poc?.code ?? "");
            }}
            className="font-mono uppercase"
            style={SECONDARY_BTN}
          >
            copy
          </button>
          <button
            type="button"
            onClick={downloadPoC}
            title={`download ${pocFileName}`}
            className="font-mono uppercase"
            style={SECONDARY_BTN}
          >
            download
          </button>
          {projectId ? (
            <Link
              to={`/vr/projects/${projectId}/findings/${findingId}/exploit`}
              className="font-mono uppercase"
              style={{
                ...SECONDARY_BTN,
                background: "var(--accent)",
                border: "1px solid var(--accent)",
                color: "var(--text-on-accent)",
                textDecoration: "none",
                display: "inline-flex",
                alignItems: "center",
              }}
            >
              open editor →
            </Link>
          ) : null}
        </>
      ) : null}
    </div>
  );

  const pocPanelTitle = f.poc
    ? `poc (${f.poc.language}) · vuln ${f.poc.crashes_vulnerable}/5 · patched ${f.poc.crashes_patched}/1`
    : "poc";

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader
        icon="◈"
        title={titleFallback || "finding"}
        actions={headerActions}
      />

      {/* Status / classification chip row */}
      <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
        <MonoBadge tone={DISCLOSURE_TONE[f.disclosure_status] ?? "muted"}>
          {f.disclosure_status}
        </MonoBadge>
        {f.crash_type ? <MonoBadge tone="warn">{f.crash_type}</MonoBadge> : null}
        {f.assigned_cve_id ? (
          <a
            href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.assigned_cve_id)}`}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono uppercase"
            style={{
              fontSize: 9.5,
              letterSpacing: "0.1em",
              padding: "3px 8px",
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              color: "var(--accent)",
              borderRadius: 2,
              textDecoration: "none",
            }}
          >
            {f.assigned_cve_id} ↗
          </a>
        ) : null}
        <CVSSBadge
          score={f.cvss_score}
          vector={f.cvss_vector}
          source={f.cvss_source}
        />
        <CWEBadge cweId={f.cwe_id} name={f.cwe_name} />
      </div>

      {/* Adjudication banner (§Topic 8) -- synthesised from finding state.
          A real adjudication record (verdict + hedge phrases detected +
          unmet obligations) is backend pending. */}
      <AdjudicationBanner
        result={{
          verdict:
            f.poc?.crashes_vulnerable === 5 && f.poc?.crashes_patched === 0
              ? "accepted"
              : f.poc?.crashes_vulnerable && f.poc.crashes_vulnerable >= 3
                ? "downgraded"
                : "blocked",
          reason:
            f.poc?.crashes_vulnerable === 5 && f.poc?.crashes_patched === 0
              ? "PoC reliability 5/5 on vulnerable + clean on patched."
              : f.poc?.crashes_vulnerable === 0
                ? "PoC fails to reproduce -- submission blocked until reliability ≥ 3/5."
                : "PoC reproduces but flaky -- operator review required.",
        }}
      />

      {/* Connected -- project, advisory, CVE, disclosure submissions
          derived from the finding + its disclosure lookup. */}
      <FindingConnectedCard finding={finding} />

      {/* 1 -- Root cause */}
      <WindowPanel title="root cause" tone="info">
        {f.root_cause ? (
          <p
            className="font-mono"
            style={{
              fontSize: 11.5,
              lineHeight: 1.55,
              color: "var(--text-primary)",
              whiteSpace: "pre-wrap",
            }}
          >
            {f.root_cause}
          </p>
        ) : (
          <BriefRow label="root cause">not yet recorded.</BriefRow>
        )}
      </WindowPanel>

      {/* 2 -- Vulnerable function */}
      <WindowPanel title="vulnerable function" tone="muted">
        <p
          className="font-mono"
          style={{
            fontSize: 12,
            color: "var(--text-primary)",
            letterSpacing: "0.02em",
          }}
        >
          {f.vulnerable_function || "--"}
        </p>
        <p
          className="font-mono"
          style={{
            marginTop: 6,
            fontSize: 9.5,
            color: "var(--text-faint)",
            letterSpacing: "0.06em",
          }}
        >
          decompiled source rendering pending — open the function in ida on the
          research workstation to view pseudocode.
        </p>
      </WindowPanel>

      {/* 3 -- CVSS breakdown */}
      <WindowPanel title="cvss v3.1 breakdown" tone="accent">
        {f.cvss_vector ? (
          <CVSSBreakdown
            vector={f.cvss_vector}
            score={f.cvss_score}
            source={f.cvss_source ?? null}
          />
        ) : (
          <PendingBackend
            field="cvss_score / cvss_vector / cvss_source on VRFinding"
            hint="The agent computes CVSS in the advisory state but the contract doesn't expose it yet. Display will populate once the contract carries the vector string."
          />
        )}
      </WindowPanel>

      {/* 4 -- CWE */}
      <WindowPanel title="cwe classification" tone="muted">
        {f.cwe_id ? (
          <CWEBadge cweId={f.cwe_id} name={f.cwe_name} />
        ) : (
          <PendingBackend
            field="cwe_id / cwe_name on VRFinding"
            hint="Spec calls for CWE classification in the advisory state. Backend wiring pending."
          />
        )}
      </WindowPanel>

      {/* 5 -- PoC */}
      <WindowPanel title={pocPanelTitle} tone="accent" actions={pocActions}>
        {f.poc?.code ? (
          <pre
            className="font-mono"
            style={{
              margin: 0,
              padding: 12,
              fontSize: 11,
              lineHeight: 1.5,
              color: "var(--text-primary)",
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              borderRadius: 3,
              overflow: "auto",
              maxHeight: 480,
              whiteSpace: "pre",
            }}
          >
            {f.poc.code}
          </pre>
        ) : draftInFlightAt != null ? (
          <p
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            writer running… polling for the new poc every 8s (auto-stops after
            3 min). the poc block populates when run_vr_draft_poc finishes.
          </p>
        ) : (
          <p
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            no poc yet.
          </p>
        )}
      </WindowPanel>

      {/* 6 -- ASAN report */}
      <WindowPanel title="asan report" tone="muted">
        {f.poc?.asan_report ? (
          <pre
            className="font-mono"
            style={{
              margin: 0,
              padding: 12,
              fontSize: 10.5,
              lineHeight: 1.5,
              color: "var(--text-primary)",
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              borderRadius: 3,
              overflow: "auto",
              maxHeight: 384,
              whiteSpace: "pre",
            }}
          >
            {f.poc.asan_report}
          </pre>
        ) : (
          <p
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            no asan output captured (poc may not have run with sanitizers).
          </p>
        )}
      </WindowPanel>

      {/* 7 -- Crash signature */}
      <WindowPanel title="crash signature" tone="info">
        {f.crash_signature ? (
          <div className="flex flex-col" style={{ gap: 8 }}>
            <BriefRow label="hash">
              {f.crash_signature.signature_hash.slice(0, 16)}…
            </BriefRow>
            <BriefRow label="crash type">
              {f.crash_signature.crash_type}
            </BriefRow>
            <BriefRow label="normalized frames">
              <ol
                className="font-mono"
                style={{
                  margin: 0,
                  paddingLeft: 20,
                  listStyle: "decimal",
                  fontSize: 11,
                  lineHeight: 1.6,
                  color: "var(--text-primary)",
                }}
              >
                {f.crash_signature.frames.slice(0, 5).map((frame, i) => (
                  <li key={i}>{frame}</li>
                ))}
              </ol>
            </BriefRow>
          </div>
        ) : (
          <p
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            no signature recorded.
          </p>
        )}
      </WindowPanel>

      {/* 8 -- Exploitability */}
      <WindowPanel title="exploitability assessment" tone="accent">
        {f.exploitability_verdict || f.exploitability_rationale ? (
          <div className="flex flex-col" style={{ gap: 8 }}>
            <MonoBadge tone="critical">
              verdict: {f.exploitability_verdict ?? "--"}
            </MonoBadge>
            {f.exploitability_rationale ? (
              <p
                className="font-mono"
                style={{
                  fontSize: 11.5,
                  lineHeight: 1.55,
                  color: "var(--text-primary)",
                  whiteSpace: "pre-wrap",
                }}
              >
                {f.exploitability_rationale}
              </p>
            ) : null}
          </div>
        ) : (
          <PendingBackend
            field="exploitability_verdict / exploitability_rationale on VRFinding"
            hint="Spec calls for primitive type + preconditions + mitigation defeats. Backend wiring pending -- currently only crash_type is exposed."
          />
        )}
      </WindowPanel>

      {/* 9 -- Disclosure */}
      <WindowPanel title="disclosure" tone="info">
        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: 6,
          }}
        >
          <BriefRow label="status">
            <MonoBadge tone={DISCLOSURE_TONE[f.disclosure_status] ?? "muted"}>
              {f.disclosure_status}
            </MonoBadge>
          </BriefRow>
          <BriefRow label="vendor contact">
            {f.vendor_contact ?? "--"}
          </BriefRow>
          <BriefRow label="assigned cve">
            {f.assigned_cve_id ?? "--"}
          </BriefRow>
          <BriefRow label="patch version">
            {f.patch_version ?? "--"}
          </BriefRow>
          <BriefRow label="reported at">
            {f.reported_at ? new Date(f.reported_at).toLocaleString() : "--"}
          </BriefRow>
          <BriefRow label="embargo until">
            {f.embargo_until
              ? new Date(f.embargo_until).toLocaleString()
              : "--"}
          </BriefRow>
        </div>
        <p
          className="font-mono"
          style={{
            marginTop: 10,
            fontSize: 9.5,
            color: "var(--text-faint)",
            letterSpacing: "0.06em",
          }}
        >
          inline editing of these fields ships in the advisory editor (tier 2).
          for now use{" "}
          <code style={{ color: "var(--text-muted)" }}>
            PATCH /vr/projects/{projectId}/findings/{findingId}/disclosure
          </code>
          .
        </p>
      </WindowPanel>

      {/* 10 -- Advisory */}
      <WindowPanel title="advisory" tone="muted">
        {f.advisory_id ? (
          <Link
            to={`/vr/disclosures/${f.advisory_id}`}
            className="font-mono uppercase"
            style={{
              fontSize: 10.5,
              letterSpacing: "0.08em",
              color: "var(--accent)",
              textDecoration: "none",
            }}
          >
            open advisory →
          </Link>
        ) : (
          <p
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            no advisory drafted yet. the engine produces one once the finding
            reaches the advisory state.
          </p>
        )}
      </WindowPanel>

      {/* Obligations -- fully gated on backend */}
      <WindowPanel title="evidence obligations" tone="muted">
        <ObligationChecklist
          obligations={[]}
          emptyHint="No obligation API yet -- see Tier 2 of docs/prior design notes."
        />
      </WindowPanel>
    </div>
  );
}

// ─── Local helpers ──────────────────────────────────────────────────

const SECONDARY_BTN: React.CSSProperties = {
  height: 24,
  padding: "0 10px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
  cursor: "pointer",
};

/** Uppercase mono label above value with a soft bottom rule -- mirrors
 *  ProjectDetailPage.BriefRow so brief-shape sections stay consistent. */
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

/** Placeholder block for advisory-state fields the backend contract
 *  doesn't yet expose (cvss_vector, cwe, exploitability_*). */
function PendingBackend({
  field,
  hint,
}: {
  field: string;
  hint: string;
}) {
  return (
    <div
      style={{
        padding: 10,
        background: "var(--surface-sunk)",
        border: "1px dashed var(--border-soft)",
        borderRadius: 3,
      }}
    >
      <MonoBadge tone="info">backend pending</MonoBadge>
      <p
        className="font-mono"
        style={{
          marginTop: 6,
          fontSize: 10,
          color: "var(--text-muted)",
          letterSpacing: "0.04em",
        }}
      >
        missing field: <code style={{ color: "var(--text-primary)" }}>{field}</code>
      </p>
      <p
        className="font-mono"
        style={{
          marginTop: 4,
          fontSize: 10,
          color: "var(--text-faint)",
          letterSpacing: "0.04em",
        }}
      >
        {hint}
      </p>
    </div>
  );
}
