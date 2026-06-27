import { useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";

import {
  useAcceptFuzzProposal,
  useRejectFuzzProposal,
} from "../mutations";
import {
  useFuzzProposals,
  type VRFuzzCampaignProposalSummary,
} from "../queries";
import { SyntaxHighlighter } from "./SyntaxHighlighter";

/**
 * Operator-facing queue of fuzz campaign proposals for one
 * investigation. Each pending proposal renders with rationale,
 * suggested config, the full harness source the agent authored,
 * the build command, seed corpus listing, and an Accept / Reject
 * pair. Accept opens an expanded form so the operator can override
 * engine / strategy / workstation if they want; default just runs
 * the agent's suggestion + auto-launches.
 */
export function FuzzProposalsPanel({
  investigationId,
  live = true,
}: {
  investigationId: string;
  /** Forwarded to `useFuzzProposals` -- false stops the 8s polling
   *  on paused / completed / failed investigations. The parent
   *  page derives this from `isInvestigationLive(inv?.status)`. */
  live?: boolean;
}) {
  const { data, isLoading } = useFuzzProposals({
    investigationId,
    status: "pending",
    live,
  });
  const proposals: VRFuzzCampaignProposalSummary[] = data?.data ?? [];

  return (
    <AilaCard  techBorder glow><div className="flex items-center justify-between mb-2 gap-2 flex-wrap">
      <div>
        <h2 className="text-sm font-semibold text-foreground">
          Fuzz proposals
        </h2>
        <p className="text-3xs text-text-muted mt-0.5">
          Agent-authored -- operator decides. Accept ships the harness,
          builds it on the workstation, and launches the fuzzer.
        </p>
      </div>
      <span className="text-3xs text-text-muted font-mono">
        {proposals.length} pending
      </span>
    </div>
    {isLoading ? (
      <p className="text-xs text-text-muted">Loading…</p>
    ) : proposals.length === 0 ? (
      <EmptyState
        title="No pending fuzz proposals"
        description="The reasoning agent emits these when audit narrows to a question it can only settle with runtime evidence."
      />
    ) : (
      <ul className="space-y-3">
        {proposals.map((p) => (
          <li key={p.id}>
            <FuzzProposalCard proposal={p} />
          </li>
        ))}
      </ul>
    )}</AilaCard>
  );
}

function FuzzProposalCard({ proposal }: { proposal: VRFuzzCampaignProposalSummary }) {
  const acceptMut = useAcceptFuzzProposal(proposal.id);
  const rejectMut = useRejectFuzzProposal(proposal.id);
  const [expanded, setExpanded] = useState(false);
  const [showHarness, setShowHarness] = useState(false);
  const [overrideEngine, setOverrideEngine] = useState<string>("");
  const [overrideDuration, setOverrideDuration] = useState<string>("");
  const [autoLaunch, setAutoLaunch] = useState(true);

  const harnessLang = proposal.harness_language ?? "c";
  const seedCount = proposal.seed_corpus?.length ?? 0;
  const hasHarness = !!proposal.harness_source;
  const hasBuild = !!proposal.harness_build_command;
  const hasDict = !!proposal.dictionary_content;
  const ready = hasHarness && hasBuild;
  const descriptorKey =
    (proposal.target_descriptor?.["harness"] as string | undefined)
    ?? (proposal.target_descriptor?.["function"] as string | undefined)
    ?? (proposal.target_descriptor?.["function_name"] as string | undefined)
    ?? "--";
  const confidenceSeverity =
    proposal.confidence === "exact"
      ? "low"
      : proposal.confidence === "strong"
        ? "info"
        : proposal.confidence === "medium"
          ? "medium"
          : "high";

  return (
    <div className="border border-border-default rounded p-3 bg-surface/40 space-y-2">
      <div className="flex items-start justify-between gap-2 flex-wrap">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1 flex-wrap mb-1">
            <span className="font-mono text-sm text-foreground">
              {proposal.profile}
            </span>
            <span className="text-3xs text-text-muted">→</span>
            <span className="font-mono text-xs text-foreground">
              {descriptorKey}
            </span>
            <AilaBadge severity={confidenceSeverity} size="sm">
              {proposal.confidence}
            </AilaBadge>
            {ready ? (
              <AilaBadge severity="low" size="sm">
                ready to launch
              </AilaBadge>
            ) : (
              <AilaBadge severity="medium" size="sm">
                missing harness
              </AilaBadge>
            )}
          </div>
          <p className="text-xs text-text-muted">{proposal.rationale || "(no rationale)"}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={!ready || acceptMut.isPending}
            onClick={() => acceptMut.mutate({ auto_launch: autoLaunch })}
            title={
              ready
                ? "Run the prepared harness build + create campaign + auto-launch"
                : "Proposal is missing harness_source or harness_build_command -- agent must complete the prep"
            }
            className="px-3 py-1.5 text-xs font-medium rounded bg-green-600 text-white hover:bg-green-500 disabled:opacity-40"
          >
            {acceptMut.isPending ? "Accepting…" : "Accept"}
          </button>
          <button
            type="button"
            disabled={rejectMut.isPending}
            onClick={() => {
              const reason = window.prompt(
                "Reject reason (recorded for the audit trail):",
                "operator declined",
              );
              if (!reason) return;
              rejectMut.mutate({ decision_reason: reason });
            }}
            className="px-3 py-1.5 text-xs font-medium rounded bg-surface border border-border-default hover:bg-surface-hover disabled:opacity-40"
          >
            Reject
          </button>
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="text-3xs text-accent hover:underline"
          >
            {expanded ? "▾ collapse" : "▸ overrides"}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-3xs font-mono text-text-muted">
        <div>
          <div className="text-text-muted">engine</div>
          <div className="text-foreground">{proposal.suggested_engine_id ?? "--"}</div>
        </div>
        <div>
          <div className="text-text-muted">strategy</div>
          <div className="text-foreground">{proposal.suggested_strategy_id ?? "--"}</div>
        </div>
        <div>
          <div className="text-text-muted">duration</div>
          <div className="text-foreground">
            {proposal.suggested_duration_hours
              ? `${proposal.suggested_duration_hours}h`
              : "--"}
          </div>
        </div>
        <div>
          <div className="text-text-muted">seeds / dict</div>
          <div className="text-foreground">
            {seedCount} {hasDict ? "+ dict" : ""}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="space-y-2 pt-2 border-t border-border-default">
          <div className="flex items-center gap-2 flex-wrap text-xs">
            <label className="flex items-center gap-1">
              <span className="text-text-muted">engine override:</span>
              <input
                type="text"
                value={overrideEngine}
                onChange={(e) => setOverrideEngine(e.target.value)}
                placeholder={proposal.suggested_engine_id ?? "default"}
                className="px-2 py-1 rounded bg-surface border border-border-default font-mono w-32"
              />
            </label>
            <label className="flex items-center gap-1">
              <span className="text-text-muted">duration_hours:</span>
              <input
                type="number"
                value={overrideDuration}
                onChange={(e) => setOverrideDuration(e.target.value)}
                placeholder={String(proposal.suggested_duration_hours ?? "")}
                className="px-2 py-1 rounded bg-surface border border-border-default font-mono w-20"
              />
            </label>
            <label className="flex items-center gap-1">
              <input
                type="checkbox"
                checked={autoLaunch}
                onChange={(e) => setAutoLaunch(e.target.checked)}
              />
              <span>auto-launch after build</span>
            </label>
            <button
              type="button"
              disabled={!ready || acceptMut.isPending}
              onClick={() =>
                acceptMut.mutate({
                  engine_id: overrideEngine || undefined,
                  duration_hours: overrideDuration
                    ? parseInt(overrideDuration, 10)
                    : undefined,
                  auto_launch: autoLaunch,
                })
              }
              className="px-2 py-1 text-xs font-medium rounded bg-accent text-white hover:bg-accent/90 disabled:opacity-40"
            >
              Accept with overrides
            </button>
          </div>
          <button
            type="button"
            onClick={() => setShowHarness((v) => !v)}
            className="text-3xs text-accent hover:underline"
          >
            {showHarness ? "▾ hide harness" : "▸ show harness + build + seeds"}
          </button>
          {showHarness && (
            <div className="space-y-2">
              {hasHarness ? (
                <div>
                  <p className="text-3xs text-text-muted mb-1">
                    Harness ({harnessLang})
                  </p>
                  <SyntaxHighlighter
                    code={proposal.harness_source ?? ""}
                    language={harnessLang}
                  />
                </div>
              ) : (
                <p className="text-3xs text-amber-500 font-mono">
                  Agent did not author a harness -- proposal cannot be
                  accepted until harness_source is filled.
                </p>
              )}
              {hasBuild && (
                <div>
                  <p className="text-3xs text-text-muted mb-1">
                    Build command
                  </p>
                  <pre className="text-xs font-mono p-2 rounded bg-surface border border-border-default overflow-x-auto">
                    {proposal.harness_build_command}
                  </pre>
                </div>
              )}
              {seedCount > 0 && (
                <div>
                  <p className="text-3xs text-text-muted mb-1">
                    Seed corpus ({seedCount})
                  </p>
                  <ul className="text-3xs font-mono space-y-0.5">
                    {proposal.seed_corpus.map((s) => (
                      <li
                        key={s.filename}
                        className="flex items-center gap-2"
                      >
                        <span className="text-foreground">{s.filename}</span>
                        <span className="text-text-muted">
                          ({Math.round((s.content_base64.length * 3) / 4)} B)
                        </span>
                        {s.notes && (
                          <span className="text-text-muted">-- {s.notes}</span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {hasDict && (
                <div>
                  <p className="text-3xs text-text-muted mb-1">
                    Dictionary
                  </p>
                  <pre className="text-xs font-mono p-2 rounded bg-surface border border-border-default overflow-x-auto max-h-32">
                    {proposal.dictionary_content}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
