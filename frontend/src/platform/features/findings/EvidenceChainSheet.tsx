import { useState } from "react";
import { TreeStructure } from "@phosphor-icons/react/dist/csr/TreeStructure";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { EvidenceChainGraph } from "./EvidenceChainGraph";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface EvidenceChainSheetProps {
  findingId: number;
  findingLabel?: string;
}

// ---------------------------------------------------------------------------
// Shared trigger button style
// ---------------------------------------------------------------------------

const MONO_BTN: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 11px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  cursor: "pointer",
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * EvidenceChainSheet -- slide-over panel with the ReactFlow evidence graph (UX-05).
 *
 * Renders a "Show Evidence Chain" trigger button. When clicked, opens a
 * right-anchored sheet containing the EvidenceChainGraph for the given
 * finding ID.
 */
export function EvidenceChainSheet({ findingId, findingLabel }: EvidenceChainSheetProps) {
  const [open, setOpen] = useState(false);
  const subtitle = findingLabel
    ? `Provenance graph for: ${findingLabel}`
    : `Finding #${findingId} -- scan \u2192 advisory \u2192 score \u2192 triage`;

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        title="Show evidence provenance chain"
        style={MONO_BTN}
      >
        <TreeStructure size={12} />
        EVIDENCE CHAIN
      </button>

      {open && (
        <div
          className="fixed"
          style={{ inset: 0, zIndex: 75, pointerEvents: "none" }}
          role="dialog"
          aria-modal="true"
          aria-label="Evidence chain"
        >
          <div
            role="button"
            tabIndex={-1}
            aria-label="Close evidence chain"
            onClick={() => setOpen(false)}
            onKeyDown={(e) => { if (e.key === "Escape") setOpen(false); }}
            style={{
              position: "absolute",
              inset: 0,
              background: "color-mix(in srgb, black 40%, transparent)",
              pointerEvents: "auto",
            }}
          />
          <div
            style={{
              position: "fixed",
              top: 0,
              right: 0,
              bottom: 0,
              width: "min(720px, 96vw)",
              overflowY: "auto",
              background: "var(--surface-page)",
              borderLeft: "1px solid var(--border)",
              pointerEvents: "auto",
            }}
          >
            <WindowPanel
              title="evidence chain"
              tone="info"
              status={subtitle}
              actions={
                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  aria-label="Close"
                  style={{ ...MONO_BTN, height: 20, fontSize: 9, padding: "0 8px" }}
                >
                  {"\u2715"} CLOSE
                </button>
              }
            >
              <EvidenceChainGraph findingId={findingId} />
            </WindowPanel>
          </div>
        </div>
      )}
    </>
  );
}
