import { Link, useNavigate, useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { CVSSBadge, CWEBadge } from "../components/CVSSBadge";
import { CVSSBreakdown } from "../components/CVSSBadge";
import { AdjudicationBanner } from "../components/AdjudicationBanner";
import { ObligationChecklist } from "../components/ObligationChecklist";
import { SyntaxHighlighter } from "../components/SyntaxHighlighter";
import { useVRFinding } from "../queries";
import type { DisclosureStatus } from "../types";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

const disclosureColor: Record<
  DisclosureStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  undisclosed: "high",
  reported: "medium",
  acknowledged: "medium",
  patch_pending: "medium",
  patched: "low",
  public: "low",
};

/** Finding Detail page — 10-section layout from 08_FRONTEND_UX.md §1.6 /
 *  VR_FRONTEND_UX_DISCUSSION.md Topic 4.
 *
 *  Sections:
 *    1. Root cause
 *    2. Vulnerable function
 *    3. CVSS breakdown (8-metric table + colored badge)
 *    4. CWE badge
 *    5. PoC code (syntax highlight + copy + download)
 *    6. ASAN report (monospaced, scrollable)
 *    7. Crash signature (hash prefix + normalized frames)
 *    8. Exploitability verdict + rationale
 *    9. Disclosure status + inline editor (current backend supports
 *       PATCH /vr/projects/:id/findings/:id/disclosure)
 *   10. Advisory preview (renders advisory_id link to Disclosures page)
 *
 *  Several spec'd fields (cvss_vector, cvss_source, cwe_id, exploitability_
 *  verdict, exploitability_rationale) do not exist on the backend VRFinding
 *  contract yet. Sections render their headers with "backend pending"
 *  placeholders so the surface is honest about what's wired. */
export function FindingDetailPage() {
  const { projectId = "", findingId = "" } = useParams<{
    projectId: string;
    findingId: string;
  }>();
  const navigate = useNavigate();
  const { data: finding, isLoading, isError } = useVRFinding(projectId, findingId);

  useUpdatePageHeader({
    title: finding?.vulnerable_function || (finding ? '(unknown function)' : undefined),
    subtitle: undefined,
    status: null,
  });

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;
  if (isError || !finding) {
    return (
      <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Failed to load finding.</p></AilaCard>
    );
  }

  // Backend doesn't carry these yet — render section headers so the
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

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <AilaBadge severity={disclosureColor[f.disclosure_status]} size="sm">
            {f.disclosure_status}
          </AilaBadge>
          {f.crash_type && (
            <AilaBadge severity="high" size="sm">
              {f.crash_type}
            </AilaBadge>
          )}
          {f.assigned_cve_id && (
            <a
              href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.assigned_cve_id)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-mono text-accent hover:underline px-2 py-0.5"
            >
              {f.assigned_cve_id} ↗
            </a>
          )}
          <CVSSBadge
            score={f.cvss_score}
            vector={f.cvss_vector}
            source={f.cvss_source}
          />
          <CWEBadge cweId={f.cwe_id} name={f.cwe_name} />
        </div>
      </div>

      {/* Adjudication banner (§Topic 8) — synthesised from finding state.
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
                ? "PoC fails to reproduce — submission blocked until reliability ≥ 3/5."
                : "PoC reproduces but flaky — operator review required.",
        }}
      />

      {/* 1 — Root cause */}
      <AilaCard  techBorder glow><Section title="Root cause" />
      {f.root_cause ? (
        <p className="text-sm text-foreground whitespace-pre-wrap leading-relaxed">
          {f.root_cause}
        </p>
      ) : (
        <p className="text-xs text-text-muted">Not yet recorded.</p>
      )}</AilaCard>

      {/* 2 — Vulnerable function */}
      <AilaCard  techBorder glow><Section title="Vulnerable function" />
      <p className="font-mono text-sm text-foreground">
        {f.vulnerable_function || "—"}
      </p>
      <p className="text-3xs text-text-muted mt-1">
        Decompiled source rendering pending — open the function in IDA on the
        research workstation to view pseudocode.
      </p></AilaCard>

      {/* 3 — CVSS breakdown */}
      <AilaCard  techBorder glow><Section title="CVSS v3.1 breakdown" />
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
      )}</AilaCard>

      {/* 4 — CWE */}
      <AilaCard  techBorder glow><Section title="CWE classification" />
      {f.cwe_id ? (
        <CWEBadge cweId={f.cwe_id} name={f.cwe_name} />
      ) : (
        <PendingBackend
          field="cwe_id / cwe_name on VRFinding"
          hint="Spec calls for CWE classification in the advisory state. Backend wiring pending."
        />
      )}</AilaCard>

      {/* 5 — PoC */}
      <AilaCard  techBorder glow><Section
        title={
          f.poc
            ? `PoC (${f.poc.language}) — vulnerable: ${f.poc.crashes_vulnerable}/5  patched: ${f.poc.crashes_patched}/1`
            : "PoC"
        }
        actions={
          f.poc?.code && (
            <div className="flex gap-1">
              <button
                type="button"
                onClick={() => {
                  void navigator.clipboard?.writeText(f.poc?.code ?? "");
                }}
                className="px-2 py-0.5 text-3xs font-mono rounded bg-surface border border-border-default hover:bg-surface-hover"
              >
                Copy
              </button>
              <button
                type="button"
                onClick={downloadPoC}
                className="px-2 py-0.5 text-3xs font-mono rounded bg-surface border border-border-default hover:bg-surface-hover"
                title={`Download ${pocFileName}`}
              >
                Download
              </button>
              <Link
                to={`/vr/projects/${projectId}/findings/${findingId}/exploit`}
                className="px-2 py-0.5 text-3xs font-mono rounded bg-accent text-white hover:bg-accent/90"
              >
                Open in editor →
              </Link>
            </div>
          )
        }
      />
      {f.poc?.code ? (
        <SyntaxHighlighter
          code={f.poc.code}
          language={f.poc.language ?? "python"}
        />
      ) : (
        <p className="text-xs text-text-muted">No PoC yet.</p>
      )}</AilaCard>

      {/* 6 — ASAN report */}
      <AilaCard  techBorder glow><Section title="ASAN report" />
      {f.poc?.asan_report ? (
        <pre className="text-2xs font-mono p-3 rounded bg-surface border border-border-default overflow-x-auto whitespace-pre max-h-96 overflow-y-auto">
          {f.poc.asan_report}
        </pre>
      ) : (
        <p className="text-xs text-text-muted">
          No ASAN output captured (PoC may not have run with sanitizers).
        </p>
      )}</AilaCard>

      {/* 7 — Crash signature */}
      <AilaCard  techBorder glow><Section title="Crash signature" />
      {f.crash_signature ? (
        <div className="text-xs font-mono space-y-2">
          <div>
            <span className="text-text-muted">hash:</span>{" "}
            <span className="text-foreground">
              {f.crash_signature.signature_hash.slice(0, 16)}…
            </span>
          </div>
          <div>
            <span className="text-text-muted">crash_type:</span>{" "}
            <span className="text-foreground">
              {f.crash_signature.crash_type}
            </span>
          </div>
          <div>
            <span className="text-text-muted">normalized frames:</span>
            <ol className="ml-4 mt-1 list-decimal text-text-muted">
              {f.crash_signature.frames.slice(0, 5).map((frame, i) => (
                <li key={i} className="text-foreground">
                  {frame}
                </li>
              ))}
            </ol>
          </div>
        </div>
      ) : (
        <p className="text-xs text-text-muted">No signature recorded.</p>
      )}</AilaCard>

      {/* 8 — Exploitability */}
      <AilaCard  techBorder glow><Section title="Exploitability assessment" />
      {f.exploitability_verdict || f.exploitability_rationale ? (
        <div className="space-y-2">
          <AilaBadge severity="critical" size="sm">
            verdict: {f.exploitability_verdict ?? "—"}
          </AilaBadge>
          {f.exploitability_rationale && (
            <p className="text-sm text-foreground whitespace-pre-wrap">
              {f.exploitability_rationale}
            </p>
          )}
        </div>
      ) : (
        <PendingBackend
          field="exploitability_verdict / exploitability_rationale on VRFinding"
          hint="Spec calls for primitive type + preconditions + mitigation defeats. Backend wiring pending — currently only crash_type is exposed."
        />
      )}</AilaCard>

      {/* 9 — Disclosure */}
      <AilaCard  techBorder glow><Section title="Disclosure" />
      <dl className="grid grid-cols-2 gap-3 text-xs font-mono">
        <div>
          <dt className="text-text-muted">Status</dt>
          <dd>
            <AilaBadge
              severity={disclosureColor[f.disclosure_status]}
              size="sm"
            >
              {f.disclosure_status}
            </AilaBadge>
          </dd>
        </div>
        <div>
          <dt className="text-text-muted">Vendor contact</dt>
          <dd className="text-foreground">{f.vendor_contact ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-text-muted">Assigned CVE</dt>
          <dd className="text-foreground">{f.assigned_cve_id ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-text-muted">Patch version</dt>
          <dd className="text-foreground">{f.patch_version ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-text-muted">Reported at</dt>
          <dd className="text-foreground">
            {f.reported_at ? new Date(f.reported_at).toLocaleString() : "—"}
          </dd>
        </div>
        <div>
          <dt className="text-text-muted">Embargo until</dt>
          <dd className="text-foreground">
            {f.embargo_until ? new Date(f.embargo_until).toLocaleString() : "—"}
          </dd>
        </div>
      </dl>
      <p className="text-3xs text-text-muted mt-3">
        Inline editing of these fields ships in the Advisory Editor (Tier 2).
        For now use PATCH{" "}
        <code>/vr/projects/{projectId}/findings/{findingId}/disclosure</code>.
      </p></AilaCard>

      {/* 10 — Advisory */}
      <AilaCard  techBorder glow><Section title="Advisory" />
      {f.advisory_id ? (
        <Link
          to={`/vr/disclosures/${f.advisory_id}`}
          className="text-sm text-accent hover:underline"
        >
          Open advisory →
        </Link>
      ) : (
        <p className="text-xs text-text-muted">
          No advisory drafted yet. The engine produces one once the finding
          reaches the advisory state.
        </p>
      )}</AilaCard>

      {/* Obligations — fully gated on backend */}
      <AilaCard  techBorder glow><Section title="Evidence obligations" />
      <ObligationChecklist
        obligations={[]}
        emptyHint="No obligation API yet — see Tier 2 of docs/VR_FRONTEND_GAP_AUDIT.md."
      /></AilaCard>

      <p className="text-3xs text-text-muted text-center">
        <button
          type="button"
          onClick={() => navigate(-1)}
          className="hover:underline"
        >
          ← back
        </button>
      </p>
    </div>
  );
}

function Section({
  title,
  actions,
}: {
  title: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-2 mb-2">
      <h2 className="text-sm font-semibold text-foreground">{title}</h2>
      {actions}
    </div>
  );
}

function PendingBackend({
  field,
  hint,
}: {
  field: string;
  hint: string;
}) {
  return (
    <div className="border border-dashed border-border-default rounded p-2 bg-surface/40">
      <AilaBadge severity="info" size="sm">
        backend pending
      </AilaBadge>
      <p className="text-3xs font-mono text-text-muted mt-1">
        Missing field: <code>{field}</code>
      </p>
      <p className="text-3xs text-text-muted mt-1">{hint}</p>
    </div>
  );
}
