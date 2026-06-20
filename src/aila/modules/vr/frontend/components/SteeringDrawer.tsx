import { useEffect, useState } from "react";
import { createPortal } from "react-dom";

import { AilaBadge } from "@/components/aila/AilaBadge";

import {
  usePauseInvestigation,
  useResumeInvestigation,
  useSendOperatorMessage,
} from "../mutations";
import type { InvestigationStatus, OperatorIntent } from "../types";

/** Operator Steering Drawer (08_FRONTEND_UX.md §1.12).
 *
 *  Right-side overlay drawer with accordion sections. Designed as a
 *  modifier on top of whatever page the operator is on (investigation
 *  detail / target detail / project dashboard).
 *
 *  Six sections are spec'd:
 *    1. Pause / resume the loop        — WIRED
 *    2. Inject context                  — WIRED (POST send_operator_message)
 *    3. Pin / unpin strategy            — backend pending
 *    4. Confirm / disprove hypothesis   — backend pending (no hypothesis API)
 *    5. Close obligation manually       — backend pending (no obligation API)
 *    6. Steer the next action           — backend pending
 *
 *  Sections without a backend yet are rendered as "coming next" cards
 *  so the operator sees the full design but doesn't get confused by a
 *  half-wired button. Backend wiring is tracked in
export function SteeringDrawer({
  open,
  onClose,
  investigationId,
  status,
}: {
  open: boolean;
  onClose: () => void;
  investigationId: string;
  status: InvestigationStatus;
}) {
  const pauseMut = usePauseInvestigation(investigationId);
  const resumeMut = useResumeInvestigation(investigationId);
  const sendMut = useSendOperatorMessage(investigationId);

  const [openSection, setOpenSection] = useState<string>("inject");
  const [contextText, setContextText] = useState("");
  const [contextIntent, setContextIntent] = useState<OperatorIntent>("steering");

  // ESC closes
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;

  return createPortal(
    <div className="fixed inset-0 z-50 flex">
      {/* Scrim */}
      <button
        type="button"
        aria-label="Close steering drawer"
        onClick={onClose}
        className="flex-1 bg-black/40 backdrop-blur-sm"
      />
      {/* Drawer */}
      <aside className="w-full h-full bg-base border-l border-border-default overflow-y-auto" style={{ maxWidth: 480 }}>
        <header className="sticky top-0 z-10 px-4 py-3 bg-base border-b border-border-default flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold font-mono text-foreground">
              Steering
            </h2>
            <p className="text-3xs text-text-muted mt-0.5">
              Modify what the engine sees next turn. All edits are audit-logged.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-text-muted hover:text-foreground text-xl leading-none"
            aria-label="Close drawer"
          >
            ✕
          </button>
        </header>

        <div className="p-3 space-y-2">
          {/* Section 1: Pause / Resume */}
          <Section
            id="pause"
            label="1. Pause / resume the loop"
            severity={
              status === "running"
                ? "medium"
                : status === "paused"
                  ? "info"
                  : "low"
            }
            statusText={status}
            open={openSection === "pause"}
            onToggle={() =>
              setOpenSection((s) => (s === "pause" ? "" : "pause"))
            }
          >
            <p className="text-xs text-text-muted mb-2">
              In-flight turn finishes; no new turn fires until resume.
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => pauseMut.mutate()}
                disabled={status !== "running" || pauseMut.isPending}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border-default hover:bg-surface-hover disabled:opacity-40"
              >
                {pauseMut.isPending ? "Pausing…" : "Pause"}
              </button>
              <button
                type="button"
                onClick={() => resumeMut.mutate()}
                // fix §54 — `isResuming` includes a 2s post-success hold
                // so the button stays in the "Resuming…" state until the
                // worker has plausibly picked the task up. Status is
                // checked against 'paused' OR the in-flight hold, since
                // the cache still reads 'paused' during the 2s window.
                disabled={
                  (status !== "paused" && !resumeMut.isResuming) ||
                  resumeMut.isResuming
                }
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-40"
              >
                {resumeMut.isResuming ? "Resuming…" : "Resume"}
              </button>
            </div>
          </Section>

          {/* Section 2: Inject context */}
          <Section
            id="inject"
            label="2. Inject context"
            severity="info"
            statusText="ready"
            open={openSection === "inject"}
            onToggle={() =>
              setOpenSection((s) => (s === "inject" ? "" : "inject"))
            }
          >
            <p className="text-xs text-text-muted mb-2">
              Text becomes a section in the engine's next prompt verbatim.
              Pick an intent so the engine knows how to weight it.
            </p>
            <textarea
              value={contextText}
              onChange={(e) => setContextText(e.target.value)}
              placeholder="e.g. 'try the JSPI base address path' or 'H4 is wrong — the leak is not reliable.'"
              rows={4}
              aria-label="Steering context"
              className="w-full px-2 py-1.5 text-xs font-mono rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
            />
            <div className="flex items-center gap-2 mt-2">
              <select
                value={contextIntent}
                onChange={(e) =>
                  setContextIntent(e.target.value as OperatorIntent)
                }
                aria-label="Context intent"
                className="px-2 py-1 text-xs font-mono rounded-md bg-surface border border-border-default"
              >
                <option value="steering">steering</option>
                <option value="correction">correction</option>
                <option value="dismissal">dismissal</option>
                <option value="question">question</option>
                <option value="outcome_selection">outcome_selection</option>
                <option value="branch_command">branch_command</option>
              </select>
              <button
                type="button"
                disabled={!contextText.trim() || sendMut.isPending}
                onClick={() =>
                  sendMut.mutate(
                    {
                      text: contextText.trim(),
                      explicit_intent: contextIntent,
                    },
                    {
                      onSuccess: () => setContextText(""),
                    },
                  )
                }
                className="ml-auto px-3 py-1 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-40"
              >
                {sendMut.isPending ? "Sending…" : "Inject"}
              </button>
            </div>
          </Section>

          {/* Sections 3-6: spec'd but backend pending */}
          <ComingSection
            id="pin"
            label="3. Pin / unpin strategy"
            description="Force the next N turns to use a specific strategy family (reverse_engineering, fuzzing_setup, crash_triage, exploit_development, …). Bypasses the router; logged loudly."
          />
          <ComingSection
            id="hypothesis"
            label="4. Confirm / disprove hypothesis"
            description="Attach operator-evidence to a hypothesis. Overrides LLM-derived weights but gets a yellow audit flag."
          />
          <ComingSection
            id="obligation"
            label="5. Close obligation manually"
            description="For obligations the LLM can't satisfy (e.g. 'human confirmation that this is in scope'). Same audit-flag rules as hypothesis override."
          />
          <ComingSection
            id="steer"
            label="6. Steer the next action"
            description="Force the next turn to be a specific action with parameters. Most invasive — only use when the LLM is stuck. Logged with reasoning."
          />
        </div>
      </aside>
    </div>,
    document.body,
  );
}

function Section({
  id,
  label,
  severity,
  statusText,
  open,
  onToggle,
  children,
}: {
  id: string;
  label: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  statusText: string;
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="border border-border-default rounded-md overflow-hidden">
      <button
        type="button"
        onClick={onToggle}
        className="w-full px-3 py-2 flex items-center justify-between gap-2 hover:bg-surface-hover transition-colors"
        aria-expanded={open}
        aria-controls={`steering-${id}`}
      >
        <span className="text-xs font-semibold text-foreground">{label}</span>
        <AilaBadge severity={severity} size="sm">
          {statusText}
        </AilaBadge>
      </button>
      {open && (
        <div
          id={`steering-${id}`}
          className="px-3 pb-3 border-t border-border-default"
        >
          {children}
        </div>
      )}
    </div>
  );
}

function ComingSection({
  id,
  label,
  description,
}: {
  id: string;
  label: string;
  description: string;
}) {
  return (
    <div className="border border-dashed border-border-default rounded-md px-3 py-2 opacity-70">
      <div className="flex items-center justify-between gap-2 mb-1">
        <span className="text-xs font-semibold text-text-muted">{label}</span>
        <AilaBadge severity="info" size="sm">
          backend pending
        </AilaBadge>
      </div>
      <p className="text-3xs text-text-muted leading-relaxed" id={`coming-${id}`}>
        {description}
      </p>
    </div>
  );
}
