/** Step 3 editors for the scheduled-report wizard: one valid email per chip. */

import { useRef, useState } from "react";
import type { ChangeEvent, JSX, KeyboardEvent } from "react";

import { css } from "../../css";
import { helpText, inputStyleRaw } from "../../wizards";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function RecipientsEditor({
  recipients,
  onChange,
}: {
  recipients: string[];
  onChange: (recipients: string[]) => void;
}): JSX.Element {
  const [draft, setDraft] = useState<string>("");
  const [invalid, setInvalid] = useState<boolean>(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const add = (): void => {
    const v = draft.trim();
    if (v === "") return;
    if (!EMAIL_RE.test(v)) {
      setInvalid(true);
      inputRef.current?.focus();
      return;
    }
    onChange([...recipients, v]);
    setDraft("");
    setInvalid(false);
  };

  return (
    <div style={css("display:flex;flex-direction:column;gap:10px;")}>
      <p style={helpText}>
        {"recipients receive the generated report on every fire. each address must be a valid email; invalid entries stay in the input."}
      </p>
      <div style={css("display:flex;gap:6px;align-items:center;")}>
        <input
          ref={inputRef}
          style={css(inputStyleRaw + "flex:1;min-width:0;")}
          value={draft}
          placeholder="ops@example.com"
          onChange={(e: ChangeEvent<HTMLInputElement>): void => {
            setDraft(e.target.value);
            if (invalid) setInvalid(false);
          }}
          onKeyDown={(e: KeyboardEvent<HTMLInputElement>): void => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <button
          type="button"
          onClick={add}
          style={css(
            "padding:0 12px;height:32px;border:1px solid var(--accent);background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
          )}
        >
          add
        </button>
      </div>
      {invalid ? (
        <span style={css("font-size:11px;color:var(--status-warn);")}>{"not a valid email"}</span>
      ) : null}
      {recipients.length > 0 ? (
        <div style={css("display:flex;flex-wrap:wrap;gap:6px;")}>
          {recipients.map((r) => (
            <span
              key={r}
              style={css(
                "display:inline-flex;align-items:center;gap:6px;padding:2px 4px 2px 8px;border:1px solid var(--border-soft);border-radius:2px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);background:var(--surface-sunk);",
              )}
            >
              {r}
              <button
                type="button"
                aria-label={`remove ${r}`}
                onClick={(): void => onChange(recipients.filter((x) => x !== r))}
                style={css(
                  "padding:0 4px;border:none;background:transparent;color:var(--text-faint);font-family:var(--font-mono);font-size:11px;cursor:pointer;line-height:1;",
                )}
              >
                {"\u2715"}
              </button>
            </span>
          ))}
        </div>
      ) : null}
      <span style={helpText}>{"recipients receive the generated report on every fire."}</span>
    </div>
  );
}
