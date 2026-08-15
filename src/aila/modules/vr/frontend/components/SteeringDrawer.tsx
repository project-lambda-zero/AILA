import { useEffect, useState } from "react";
import { createPortal } from "react-dom";

import { MonoBadge, Segmented } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

import {
  usePauseInvestigation,
  useResumeInvestigation,
  useSendOperatorMessage,
} from "../mutations";
import type { InvestigationStatus, OperatorIntent } from "../types";

/** Operator Steering Drawer -- right-side overlay in the mock design
 *  language. Hatched title bar chrome + WindowPanel-based accordion
 *  sections. Sections without a backend yet render as "backend pending"
 *  panels so the operator sees the full shape but can't fire dead
 *  buttons. */
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
        className="flex-1"
        style={{
          background: "color-mix(in srgb, var(--surface-sunk) 55%, transparent)",
          backdropFilter: "blur(2px)",
        }}
      />
      {/* Drawer */}
      <aside
        className="h-full flex flex-col"
        style={{
          width: "100%",
          maxWidth: 480,
          background: "var(--surface-page)",
          borderLeft: "1px solid var(--border)",
        }}
        role="dialog"
        aria-label="Steering drawer"
      >
        {/* Hatched title bar */}
        <div
          className="flex items-center flex-none font-mono uppercase"
          style={{
            height: "var(--panel-title-h)",
            padding: "0 10px",
            gap: 8,
            background: "var(--surface-chrome)",
            backgroundImage: "var(--hatch)",
            borderBottom: "1px solid var(--border)",
            fontSize: 10,
            letterSpacing: "0.14em",
            color: "var(--text-muted)",
          }}
        >
          <span
            aria-hidden
            style={{
              width: 10,
              height: 10,
              background: "var(--accent)",
              boxShadow: "0 0 6px var(--accent)",
            }}
          />
          <span>STEERING</span>
          <span style={{ flex: 1 }} />
          <button
            type="button"
            onClick={onClose}
            aria-label="Close drawer"
            className="font-mono inline-flex items-center justify-center"
            style={{
              width: 20,
              height: 20,
              color: "var(--text-muted)",
              background: "transparent",
              border: "1px solid var(--border-faint)",
              fontSize: 11,
              cursor: "pointer",
            }}
          >
            {"\u2715"}
          </button>
        </div>

        {/* Body */}
        <div
          className="flex-1 overflow-y-auto flex flex-col"
          style={{ padding: 10, gap: 8 }}
        >
          <p
            className="font-mono"
            style={{
              fontSize: 10,
              color: "var(--text-muted)",
              letterSpacing: "0.02em",
              margin: 0,
            }}
          >
            Modify what the engine sees next turn. All edits are audit-logged.
          </p>

          {/* 1. Pause / resume */}
          <Section
            id="pause"
            label="pause / resume the loop"
            statusText={status}
            statusTone={
              status === "running" ? "warn" : status === "paused" ? "info" : "muted"
            }
            open={openSection === "pause"}
            onToggle={() => setOpenSection((s) => (s === "pause" ? "" : "pause"))}
          >
            <p className="font-mono" style={sectionCopy}>
              In-flight turn finishes; no new turn fires until resume.
            </p>
            <div className="flex" style={{ gap: 6 }}>
              <MonoButton
                onClick={() => pauseMut.mutate()}
                disabled={status !== "running" || pauseMut.isPending}
              >
                {pauseMut.isPending ? "Pausing\u2026" : "Pause"}
              </MonoButton>
              <MonoButton
                accent
                onClick={() => resumeMut.mutate()}
                disabled={
                  (status !== "paused" && !resumeMut.isResuming) || resumeMut.isResuming
                }
              >
                {resumeMut.isResuming ? "Resuming\u2026" : "Resume"}
              </MonoButton>
            </div>
          </Section>

          {/* 2. Inject context */}
          <Section
            id="inject"
            label="inject context"
            statusText="ready"
            statusTone="info"
            open={openSection === "inject"}
            onToggle={() => setOpenSection((s) => (s === "inject" ? "" : "inject"))}
          >
            <p className="font-mono" style={sectionCopy}>
              Text becomes a section in the engine's next prompt verbatim.
              Pick an intent so the engine knows how to weight it.
            </p>
            <textarea
              value={contextText}
              onChange={(e) => setContextText(e.target.value)}
              placeholder="e.g. 'try the JSPI base address path' or 'H4 is wrong — the leak is not reliable.'"
              rows={5}
              aria-label="Steering context"
              className="w-full font-mono"
              style={{
                background: "var(--surface-sunk)",
                border: "1px solid var(--border-soft)",
                color: "var(--text-primary)",
                padding: "6px 8px",
                fontSize: 10.5,
                lineHeight: 1.4,
                outline: "none",
                resize: "vertical",
              }}
            />
            <div
              className="flex items-center"
              style={{ gap: 6, marginTop: 6, flexWrap: "wrap" }}
            >
              <Segmented<OperatorIntent>
                options={[
                  { value: "steering", label: "steering" },
                  { value: "correction", label: "correction" },
                  { value: "dismissal", label: "dismissal" },
                  { value: "question", label: "question" },
                  { value: "outcome_selection", label: "outcome" },
                  { value: "branch_command", label: "branch" },
                ]}
                value={contextIntent}
                onChange={setContextIntent}
              />
              <span style={{ flex: 1 }} />
              <MonoButton
                accent
                disabled={!contextText.trim() || sendMut.isPending}
                onClick={() =>
                  sendMut.mutate(
                    { text: contextText.trim(), explicit_intent: contextIntent },
                    { onSuccess: () => setContextText("") },
                  )
                }
              >
                {sendMut.isPending ? "Sending\u2026" : "Inject"}
              </MonoButton>
            </div>
          </Section>

          {/* 3-6: backend pending */}
          <ComingSection
            id="pin"
            label="pin / unpin strategy"
            description="Force the next N turns to use a specific strategy family. Bypasses the router; logged loudly."
          />
          <ComingSection
            id="hypothesis"
            label="confirm / disprove hypothesis"
            description="Attach operator-evidence to a hypothesis. Overrides LLM-derived weights but gets a yellow audit flag."
          />
          <ComingSection
            id="obligation"
            label="close obligation manually"
            description="For obligations the LLM can't satisfy. Same audit-flag rules as hypothesis override."
          />
          <ComingSection
            id="steer"
            label="steer the next action"
            description="Force the next turn to be a specific action with parameters. Most invasive — only when the LLM is stuck."
          />
        </div>
      </aside>
    </div>,
    document.body,
  );
}

const sectionCopy: React.CSSProperties = {
  fontSize: 10,
  lineHeight: 1.5,
  color: "var(--text-muted)",
  margin: "0 0 6px 0",
};

function MonoButton({
  accent = false,
  disabled = false,
  onClick,
  children,
}: {
  accent?: boolean;
  disabled?: boolean;
  onClick?: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="font-mono uppercase"
      style={{
        padding: "0 10px",
        height: 24,
        fontSize: 10,
        letterSpacing: "0.12em",
        background: accent ? "var(--accent)" : "var(--surface-card)",
        color: accent ? "var(--text-on-accent)" : "var(--text-primary)",
        border: `1px solid ${accent ? "var(--accent)" : "var(--border)"}`,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
      }}
    >
      {children}
    </button>
  );
}

function Section({
  id,
  label,
  statusText,
  statusTone,
  open,
  onToggle,
  children,
}: {
  id: string;
  label: string;
  statusText: string;
  statusTone: "accent" | "ok" | "info" | "warn" | "muted";
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  return (
    <WindowPanel
      title={
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={open}
          aria-controls={`steering-${id}`}
          className="font-mono uppercase inline-flex items-center"
          style={{
            gap: 6,
            background: "transparent",
            border: "none",
            color: "inherit",
            padding: 0,
            cursor: "pointer",
            fontSize: "inherit",
            letterSpacing: "inherit",
          }}
        >
          <span aria-hidden style={{ width: 8, textAlign: "center" }}>
            {open ? "▾" : "▸"}
          </span>
          <span>{label}</span>
        </button>
      }
      actions={<MonoBadge tone={statusTone}>{statusText}</MonoBadge>}
      tone={statusTone}
    >
      {open ? (
        <div id={`steering-${id}`} className="flex flex-col" style={{ gap: 6 }}>
          {children}
        </div>
      ) : null}
    </WindowPanel>
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
    <WindowPanel
      title={label}
      actions={<MonoBadge tone="muted">PENDING BACKEND</MonoBadge>}
      tone="muted"
    >
      <p
        id={`coming-${id}`}
        className="font-mono"
        style={{
          fontSize: 10,
          lineHeight: 1.5,
          color: "var(--text-muted)",
          margin: 0,
        }}
      >
        {description}
      </p>
    </WindowPanel>
  );
}
