import * as React from "react";

export interface EditModeToggleProps {
  editMode: boolean;
  onToggle: () => void;
}

/**
 * EditModeToggle -- mock-styled lock/unlock toggle for dashboard edit mode
 * (D-02). Renders as a single mono button in the SectionHeader action
 * cluster. Active state (editing) fills the button with `--accent`.
 */
export function EditModeToggle({ editMode, onToggle }: EditModeToggleProps) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-label="Toggle dashboard edit mode"
      aria-pressed={editMode}
      data-testid="dashboard-edit-toggle"
      style={{
        height: 26,
        padding: "0 12px",
        borderRadius: 3,
        fontFamily: "var(--font-mono)",
        fontSize: 9.5,
        letterSpacing: "0.1em",
        textTransform: "uppercase",
        border: `1px solid ${editMode ? "var(--accent)" : "var(--border-soft)"}`,
        background: editMode ? "var(--accent)" : "var(--surface-sunk)",
        color: editMode ? "var(--text-on-accent)" : "var(--text-primary)",
        cursor: "pointer",
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
      }}
    >
      <span aria-hidden="true" style={{ fontSize: 10 }}>
        {editMode ? "\u25A0" : "\u25CB"}
      </span>
      {editMode ? "editing" : "locked"}
    </button>
  );
}
