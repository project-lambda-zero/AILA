import { useState } from "react";

export interface NoteFieldProps {
  value: string | null;
  onChange: (value: string) => void;
}

const TOGGLE_CLS =
  "text-xs text-text-muted cursor-pointer hover:text-accent transition-colors";

export function NoteField({ value, onChange }: NoteFieldProps) {
  const [expanded, setExpanded] = useState(Boolean(value));

  function toggle() {
    setExpanded((prev) => !prev);
  }

  return (
    <div className="mt-3">
      {!expanded && (
        <button
          className={TOGGLE_CLS}
          type="button"
          onClick={toggle}
        >
          {value ? "Edit note" : "Add note"}
        </button>
      )}
      {expanded && (
        <div className="mt-2">
          <textarea
            aria-label="Note for this question"
            className="w-full p-2 rounded-md border border-border bg-surface text-text text-sm resize-y"
            style={{ minHeight: 60 }}
            value={value ?? ""}
            onChange={(e) => onChange(e.target.value)}
            placeholder="Add a note for this question…"
            rows={3}
          />
          <button
            className={TOGGLE_CLS}
            type="button"
            onClick={toggle}
          >
            Collapse
          </button>
        </div>
      )}
    </div>
  );
}
