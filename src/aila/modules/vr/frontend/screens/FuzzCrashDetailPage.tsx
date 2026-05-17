import { Link, useParams } from "react-router";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

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

      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
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
        </dl>
      </AilaCard>

      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
          Reproducer
        </h2>
        <dl className="grid grid-cols-2 gap-3 text-sm">
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
      </AilaCard>

      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
          Stack trace
        </h2>
        {crash.stack_trace ? (
          <pre className="text-xs font-mono text-foreground whitespace-pre-wrap overflow-x-auto bg-surface p-3 rounded-md">
            {crash.stack_trace}
          </pre>
        ) : (
          <p className="text-xs text-text-muted">No stack trace provided.</p>
        )}
      </AilaCard>

      {Object.keys(crash.extra).length > 0 && (
        <AilaCard>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Extra fields
          </h2>
          <pre className="text-xs font-mono text-text-muted whitespace-pre-wrap">
            {JSON.stringify(crash.extra, null, 2)}
          </pre>
        </AilaCard>
      )}
    </div>
  );
}
