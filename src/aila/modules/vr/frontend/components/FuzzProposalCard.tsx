import { useState, type CSSProperties } from "react";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { MonoBadge } from "@/components/aila/mock";

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
    <WindowPanel
      title="fuzz proposals"
      tone="muted"
      actions={
        <span
          className="font-mono uppercase"
          style={{
            fontSize: 9,
            letterSpacing: "0.08em",
            color: "var(--text-muted)",
          }}
        >
          {proposals.length} pending
        </span>
      }
    >
      <h2 className="sr-only">Fuzz proposals</h2>
      <p
        className="font-mono"
        style={{
          fontSize: 10.5,
          lineHeight: 1.55,
          color: "var(--text-muted)",
          marginBottom: 10,
        }}
      >
        Agent-authored -- operator decides. Accept ships the harness,
        builds it on the workstation, and launches the fuzzer.
      </p>
      {isLoading ? (
        <ul
          className="flex flex-col"
          style={{ gap: 10 }}
          aria-busy="true"
          aria-label="Loading fuzz proposals"
        >
          {[0, 1, 2].map((i) => (
            <li
              key={i}
              className="flex flex-col"
              style={{
                gap: 6,
                padding: 12,
                border: "1px solid var(--border-soft)",
                borderRadius: 3,
                background: "var(--surface-sunk)",
              }}
            >
              <LoadingSkeleton size="sm" width="third" />
              <LoadingSkeleton size="sm" width="full" />
              <LoadingSkeleton size="sm" width="half" />
            </li>
          ))}
        </ul>
      ) : proposals.length === 0 ? (
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
          no pending fuzz proposals -- the researcher emits these when
          audit narrows to a question only runtime evidence can settle.
        </div>
      ) : (
        <ul className="flex flex-col" style={{ gap: 10 }}>
          {proposals.map((p) => (
            <li key={p.id}>
              <FuzzProposalCard proposal={p} />
            </li>
          ))}
        </ul>
      )}
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Shared mock control styles
// ---------------------------------------------------------------------------
const CTRL: CSSProperties = {
  height: 26,
  padding: "0 8px",
  fontSize: 10,
  letterSpacing: "0.06em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

interface MonoButtonProps {
  onClick: () => void;
  disabled?: boolean;
  title?: string;
  variant?: "primary" | "default" | "ghost";
  children: React.ReactNode;
  type?: "button" | "submit";
}

function MonoButton({
  onClick,
  disabled,
  title,
  variant = "default",
  children,
  type = "button",
}: MonoButtonProps) {
  const primary = variant === "primary";
  const ghost = variant === "ghost";
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="font-mono uppercase"
      style={{
        height: 26,
        padding: "0 11px",
        fontSize: 10,
        letterSpacing: "0.08em",
        background: ghost
          ? "transparent"
          : primary
            ? "var(--accent)"
            : "var(--surface-sunk)",
        border: ghost
          ? "1px solid transparent"
          : `1px solid ${primary ? "var(--accent)" : "var(--border-soft)"}`,
        color: primary
          ? "var(--text-on-accent)"
          : ghost
            ? "var(--accent)"
            : "var(--text-primary)",
        borderRadius: 3,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
      }}
    >
      {children}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Confidence -> MonoBadge tone (pass-through map per the mock language).
//   exact  -> low   -> ok
//   strong -> info  -> info
//   medium -> medium -> medium
//   *      -> high  -> high
// ---------------------------------------------------------------------------
function confidenceTone(confidence: string | null | undefined): string {
  if (confidence === "exact") return "ok";
  if (confidence === "strong") return "info";
  if (confidence === "medium") return "medium";
  return "high";
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

  const cTone = confidenceTone(proposal.confidence);

  return (
    <div
      className="flex flex-col"
      style={{
        gap: 10,
        padding: 12,
        border: "1px solid var(--border-soft)",
        background: "var(--surface-card)",
        borderRadius: 3,
      }}
    >
      <div
        className="flex flex-wrap items-start"
        style={{ gap: 8, justifyContent: "space-between" }}
      >
        <div className="flex-1 min-w-0">
          <div
            className="flex flex-wrap items-center"
            style={{ gap: 6, marginBottom: 6 }}
          >
            <span
              className="font-mono"
              style={{
                fontSize: 12,
                color: "var(--text-primary)",
                letterSpacing: "0.02em",
              }}
            >
              {proposal.profile}
            </span>
            <span
              className="font-mono"
              style={{ fontSize: 10, color: "var(--text-faint)" }}
              aria-hidden="true"
            >
              →
            </span>
            <span
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-primary)" }}
            >
              {descriptorKey}
            </span>
            <MonoBadge tone={cTone}>{proposal.confidence}</MonoBadge>
            {ready ? (
              <MonoBadge tone="ok">ready to launch</MonoBadge>
            ) : (
              <MonoBadge tone="medium">missing harness</MonoBadge>
            )}
          </div>
          <p
            style={{
              fontSize: 12,
              lineHeight: 1.5,
              color: "var(--text-muted)",
              margin: 0,
            }}
          >
            {proposal.rationale || "(no rationale)"}
          </p>
        </div>
        <div className="flex items-center" style={{ gap: 6 }}>
          <MonoButton
            variant="primary"
            disabled={!ready || acceptMut.isPending}
            onClick={() => acceptMut.mutate({ auto_launch: autoLaunch })}
            title={
              ready
                ? "Run the prepared harness build + create campaign + auto-launch"
                : "Proposal is missing harness_source or harness_build_command -- agent must complete the prep"
            }
          >
            {acceptMut.isPending ? "accepting…" : "accept"}
          </MonoButton>
          <MonoButton
            disabled={rejectMut.isPending}
            onClick={() => {
              const reason = window.prompt(
                "Reject reason (recorded for the audit trail):",
                "operator declined",
              );
              if (!reason) return;
              rejectMut.mutate({ decision_reason: reason });
            }}
          >
            reject
          </MonoButton>
          <MonoButton
            variant="ghost"
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? "▾ collapse" : "▸ overrides"}
          </MonoButton>
        </div>
      </div>

      <div
        className="grid font-mono"
        style={{
          gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
          gap: 8,
          fontSize: 10,
          letterSpacing: "0.04em",
        }}
      >
        <BriefCell label="engine" value={proposal.suggested_engine_id ?? "--"} />
        <BriefCell
          label="strategy"
          value={proposal.suggested_strategy_id ?? "--"}
        />
        <BriefCell
          label="duration"
          value={
            proposal.suggested_duration_hours
              ? `${proposal.suggested_duration_hours}h`
              : "--"
          }
        />
        <BriefCell
          label="seeds / dict"
          value={`${seedCount}${hasDict ? " + dict" : ""}`}
        />
      </div>

      {expanded && (
        <div
          className="flex flex-col"
          style={{
            gap: 10,
            paddingTop: 10,
            borderTop: "1px solid var(--border-soft)",
          }}
        >
          <div
            className="flex flex-wrap items-center"
            style={{ gap: 8 }}
          >
            <label
              className="flex items-center font-mono uppercase"
              style={{
                gap: 6,
                fontSize: 10,
                letterSpacing: "0.06em",
                color: "var(--text-muted)",
              }}
            >
              <span>engine override</span>
              <input
                type="text"
                value={overrideEngine}
                onChange={(e) => setOverrideEngine(e.target.value)}
                placeholder={proposal.suggested_engine_id ?? "default"}
                className="font-mono"
                style={{ ...CTRL, width: 140 }}
              />
            </label>
            <label
              className="flex items-center font-mono uppercase"
              style={{
                gap: 6,
                fontSize: 10,
                letterSpacing: "0.06em",
                color: "var(--text-muted)",
              }}
            >
              <span>duration hours</span>
              <input
                type="number"
                value={overrideDuration}
                onChange={(e) => setOverrideDuration(e.target.value)}
                placeholder={String(proposal.suggested_duration_hours ?? "")}
                className="font-mono"
                style={{ ...CTRL, width: 80 }}
              />
            </label>
            <fieldset
              className="p-0 m-0 min-w-0"
              style={{ border: 0 }}
            >
              <legend className="sr-only">Fuzz proposal overrides</legend>
              <label
                className="flex items-center font-mono uppercase"
                style={{
                  gap: 6,
                  fontSize: 10,
                  letterSpacing: "0.06em",
                  color: "var(--text-muted)",
                }}
              >
                <input
                  type="checkbox"
                  checked={autoLaunch}
                  onChange={(e) => setAutoLaunch(e.target.checked)}
                  style={{ accentColor: "var(--accent)" }}
                />
                <span>auto-launch after build</span>
              </label>
            </fieldset>
            <MonoButton
              variant="primary"
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
            >
              accept with overrides
            </MonoButton>
          </div>
          <MonoButton
            variant="ghost"
            onClick={() => setShowHarness((v) => !v)}
          >
            {showHarness ? "▾ hide harness" : "▸ show harness + build + seeds"}
          </MonoButton>
          {showHarness && (
            <div className="flex flex-col" style={{ gap: 10 }}>
              {hasHarness ? (
                <div className="flex flex-col" style={{ gap: 4 }}>
                  <FieldLabel>harness ({harnessLang})</FieldLabel>
                  <SyntaxHighlighter
                    code={proposal.harness_source ?? ""}
                    language={harnessLang}
                  />
                </div>
              ) : (
                <p
                  className="font-mono"
                  style={{
                    fontSize: 10.5,
                    color: "var(--status-warn)",
                    margin: 0,
                  }}
                >
                  agent did not author a harness -- proposal cannot be
                  accepted until harness_source is filled.
                </p>
              )}
              {hasBuild && (
                <div className="flex flex-col" style={{ gap: 4 }}>
                  <FieldLabel>build command</FieldLabel>
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
                      whiteSpace: "pre",
                    }}
                  >
                    {proposal.harness_build_command}
                  </pre>
                </div>
              )}
              {seedCount > 0 && (
                <div className="flex flex-col" style={{ gap: 4 }}>
                  <FieldLabel>seed corpus ({seedCount})</FieldLabel>
                  <ul
                    className="font-mono flex flex-col"
                    style={{
                      gap: 2,
                      fontSize: 10.5,
                      padding: "8px 12px",
                      background: "var(--surface-sunk)",
                      border: "1px solid var(--border-soft)",
                      borderRadius: 3,
                      margin: 0,
                      listStyle: "none",
                    }}
                  >
                    {proposal.seed_corpus.map((s) => (
                      <li
                        key={s.filename}
                        className="flex items-center"
                        style={{ gap: 8 }}
                      >
                        <span style={{ color: "var(--text-primary)" }}>
                          {s.filename}
                        </span>
                        <span style={{ color: "var(--text-muted)" }}>
                          ({Math.round((s.content_base64.length * 3) / 4)} B)
                        </span>
                        {s.notes && (
                          <span style={{ color: "var(--text-muted)" }}>
                            -- {s.notes}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {hasDict && (
                <div className="flex flex-col" style={{ gap: 4 }}>
                  <FieldLabel>dictionary</FieldLabel>
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
                      maxHeight: 160,
                      whiteSpace: "pre",
                    }}
                  >
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

// ---------------------------------------------------------------------------
// Local presentational helpers
// ---------------------------------------------------------------------------
function BriefCell({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col" style={{ gap: 2 }}>
      <span
        className="font-mono uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.08em",
          color: "var(--text-faint)",
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-primary)" }}
      >
        {value}
      </span>
    </div>
  );
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span
      className="font-mono uppercase"
      style={{
        fontSize: 9,
        letterSpacing: "0.08em",
        color: "var(--text-faint)",
      }}
    >
      {children}
    </span>
  );
}
