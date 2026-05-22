import { Link, useParams } from "react-router";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { HexView } from "../components/HexView";
import { useFuzzCrash } from "../queries";
import type { CrashTriageVerdict } from "../types";

const VERDICT_COLOR: Record<
  CrashTriageVerdict,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  untriaged: "info",
  security_relevant: "critical",
  likely_harmless: "low",
  duplicate: "info",
  needs_manual_review: "medium",
};

/** Stack trace renderer that makes each frame clickable.
 *
 *  Parses lines like "#0  func+0x14 at libfoo.so+0x4c (/path/source.c:42)"
 *  and renders the function name as a button. On click, fires a custom
 *  event so the surrounding page (or future search palette) can resolve
 *  the function in the relevant target. For v0.5 we don't have a
 *  global function index — the click navigates to the campaign target's
 *  Functions-of-interest tab and seeds a hash filter. */
function ClickableStackTrace({
  raw,
}: {
  raw: string;
  campaignId?: string;
}) {
  const lines = raw.split("\n");
  return (
    <pre className="text-xs font-mono text-foreground whitespace-pre-wrap overflow-x-auto bg-surface p-3 rounded-md max-h-96 overflow-y-auto leading-relaxed">
      {lines.map((line, i) => {
        // Match `func_name(...)` or `func_name+0x` or `func_name at` —
        // the function name precedes either ( or + or whitespace.
        const m = line.match(/(\b[A-Za-z_][A-Za-z0-9_:.@$]*)/);
        if (!m) return <div key={i}>{line || "\u00a0"}</div>;
        const fn = m[1];
        const before = line.slice(0, m.index ?? 0);
        const after = line.slice((m.index ?? 0) + fn.length);
        return (
          <div key={i}>
            <span className="text-text-muted">{before}</span>
            <button
              type="button"
              title={`Locate ${fn} in this target's Functions-of-interest tab`}
              onClick={() => {
                // Future: navigate to /vr/targets/:id?tab=functions&fn=… —
                // not wired because crash row doesn't carry target_id and the
                // campaign→target lookup is an extra fetch. v0.6 work.
                window.dispatchEvent(
                  new CustomEvent("vr-stack-frame-click", { detail: { fn } }),
                );
              }}
              className="text-accent hover:underline cursor-pointer"
            >
              {fn}
            </button>
            <span className="text-foreground">{after}</span>
          </div>
        );
      })}
    </pre>
  );
}

export function FuzzCrashDetailPage() {
  const { crashId } = useParams<{ crashId: string }>();
  const cid = crashId ?? "";
  const { data: crash, isLoading } = useFuzzCrash(cid);

  if (isLoading || !crash) return <LoadingSkeleton size="lg" width="full" />;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold font-mono text-foreground">
          {crash.crash_type ?? "Crash"}{" "}
          <span className="text-text-muted text-sm">
            (stack {crash.stack_hash.slice(0, 12)}…)
          </span>
        </h1>
        <p className="text-sm text-text-muted mt-1">
          <Link to={`/vr/fuzz/campaigns/${crash.campaign_id}`} className="hover:underline">
            in fuzz campaign →
          </Link>
        </p>
      </div>

      <div className="flex gap-2 flex-wrap">
        <AilaBadge severity={VERDICT_COLOR[crash.triage_verdict]} size="sm">
          {crash.triage_verdict}
        </AilaBadge>
        <AilaBadge severity="medium" size="sm">
          severity: {crash.severity}
        </AilaBadge>
        {crash.crash_type && (
          <AilaBadge severity="info" size="sm">
            type: {crash.crash_type}
          </AilaBadge>
        )}
        {crash.duplicate_of_crash_id && (
          <Link to={`/vr/fuzz/crashes/${crash.duplicate_of_crash_id}`}>
            <AilaBadge severity="info" size="sm">
              duplicate of earlier crash →
            </AilaBadge>
          </Link>
        )}
        {crash.promoted_to_finding_id && (
          <AilaBadge severity="low" size="sm">
            promoted to finding
          </AilaBadge>
        )}
      </div>

      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        Triage
      </h2>
      <dl className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <dt className="text-text-muted text-xs">Stack hash</dt>
          <dd className="font-mono text-xs">{crash.stack_hash}</dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Triage reason</dt>
          <dd className="text-xs">{crash.triage_reason ?? "—"}</dd>
        </div>
        <div className="col-span-2">
          <dt className="text-text-muted text-xs">Signature</dt>
          <dd className="font-mono text-xs">
            {crash.crash_signature ?? "—"}
          </dd>
        </div>
      </dl></AilaCard>

      {/* Triage chain — narrative of turns that touched this crash.
          Per 08_FRONTEND_UX.md §1.6 / §2.4. The reasoning engine writes
          turn→crash references on each triage step; this section walks
          them in order. Backend reference table is pending. */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        Triage chain
      </h2>
      <ol className="space-y-2 text-xs">
        <li className="border border-border-default rounded px-3 py-2">
          <div className="flex items-center gap-2 flex-wrap">
            <AilaBadge severity="info" size="sm">
              step 1
            </AilaBadge>
            <span className="font-mono text-foreground">
              crash_register
            </span>
            <span className="text-text-muted">
              bucket created (stack hash matched) on{" "}
              {crash.discovered_at
                ? new Date(crash.discovered_at).toLocaleString()
                : "—"}
            </span>
          </div>
        </li>
        {crash.triage_verdict !== "untriaged" && (
          <li className="border border-border-default rounded px-3 py-2">
            <div className="flex items-center gap-2 flex-wrap">
              <AilaBadge severity="info" size="sm">
                step 2
              </AilaBadge>
              <span className="font-mono text-foreground">
                crash_triage
              </span>
              <span className="text-text-muted">
                verdict: <strong>{crash.triage_verdict}</strong>
              </span>
              {crash.triage_reason && (
                <span className="text-text-muted">
                  — {crash.triage_reason}
                </span>
              )}
            </div>
          </li>
        )}
        {crash.promoted_to_finding_id && (
          <li className="border border-border-default rounded px-3 py-2">
            <div className="flex items-center gap-2 flex-wrap">
              <AilaBadge severity="low" size="sm">
                step 3
              </AilaBadge>
              <span className="font-mono text-foreground">
                promote_to_finding
              </span>
              <span className="text-text-muted">
                exploitability confirmed
              </span>
            </div>
          </li>
        )}
      </ol>
      <div className="mt-2 border border-dashed border-border-default rounded p-2 bg-surface/40">
        <AilaBadge severity="info" size="sm">
          backend pending
        </AilaBadge>
        <p className="text-[10px] text-text-muted mt-1">
          Spec §2.4 calls for per-turn reasoning rows (decompile_function,
          data_flow_trace, hypothesis_create, exploitability_assess) with
          jump-to-turn links. Wiring requires a crash → reasoning-turn
          join table.
        </p>
      </div></AilaCard>

      {/* LLM one-line summary (§1.6) — derived from the structured
          report; placeholder when not present. */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        LLM summary
      </h2>
      {crash.triage_reason ? (
        <p className="text-sm text-foreground">{crash.triage_reason}</p>
      ) : (
        <p className="text-xs text-text-muted">
          One-line summary populates after the engine runs crash_triage.
          For now showing raw stack trace below.
        </p>
      )}</AilaCard>

      {/* Minimised input — hex view (§1.6). Backend exposes a path
          (and size); the bytes themselves require a future
          GET /vr/fuzz/crashes/{id}/reproducer endpoint. */}
      <AilaCard  techBorder glow><div className="flex items-center justify-between gap-2 mb-2 flex-wrap">
        <h2 className="text-sm font-semibold text-foreground">
          Minimised input
        </h2>
        <button
          type="button"
          disabled
          title="Re-run reproducer on workstation — backend pending"
          className="text-xs px-2 py-1 rounded bg-accent text-white opacity-50 cursor-not-allowed"
        >
          Re-run (pending)
        </button>
      </div>
      <dl className="grid grid-cols-2 gap-3 text-sm mb-3">
        <div>
          <dt className="text-text-muted text-xs">Path on worker host</dt>
          <dd className="font-mono text-xs break-all">
            {crash.reproducer_path ?? "—"}
          </dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Size</dt>
          <dd className="font-mono text-xs">
            {crash.reproducer_size_bytes != null
              ? `${crash.reproducer_size_bytes.toLocaleString()} bytes`
              : "—"}
          </dd>
        </div>
      </dl>
      <HexView data={null} filename={crash.reproducer_path?.split(/[\\/]/).pop() ?? null} /></AilaCard>

      {/* Stack trace — clickable frames per §1.6. Each frame jumps to
          the target's functions-of-interest tab scrolled to that
          function. Frame click is a no-op when no target_id is known. */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        Stack trace
      </h2>
      {crash.stack_trace ? (
        <ClickableStackTrace
          raw={crash.stack_trace}
          campaignId={crash.campaign_id}
        />
      ) : (
        <p className="text-xs text-text-muted">No stack trace provided.</p>
      )}</AilaCard>

      {/* Linked artefacts (§1.6 step 6) */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        Linked artefacts
      </h2>
      <ul className="text-xs space-y-1">
        {crash.campaign_id && (
          <li>
            <Link
              to={`/vr/fuzz/campaigns/${crash.campaign_id}`}
              className="font-mono text-accent hover:underline"
            >
              ← campaign that found this crash
            </Link>
          </li>
        )}
        {crash.duplicate_of_crash_id && (
          <li>
            <Link
              to={`/vr/fuzz/crashes/${crash.duplicate_of_crash_id}`}
              className="font-mono text-accent hover:underline"
            >
              duplicate-of: earlier crash →
            </Link>
          </li>
        )}
        {crash.promoted_to_finding_id && (
          <li className="text-text-muted">
            promoted to finding: {crash.promoted_to_finding_id.slice(0, 12)}…
          </li>
        )}
        {!crash.duplicate_of_crash_id && !crash.promoted_to_finding_id && (
          <li className="text-text-muted">No cross-references yet.</li>
        )}
      </ul></AilaCard>

      {Object.keys(crash.extra).length > 0 && (
        <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
          Extra fields
        </h2>
        <pre className="text-xs font-mono text-text-muted whitespace-pre-wrap">
          {JSON.stringify(crash.extra, null, 2)}
        </pre></AilaCard>
      )}
    </div>
  );
}
