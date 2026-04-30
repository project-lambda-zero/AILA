export interface BinaryToggleInputProps {
  value: string | null; // "yes" | "no" | null
  onChange: (value: string) => void;
}

const BASE_BTN =
  "flex-1 px-5 py-2.5 rounded-full border border-border bg-transparent text-text-muted font-sans text-sm cursor-pointer transition-colors hover:bg-elevated hover:text-text";

export function BinaryToggleInput({ value, onChange }: BinaryToggleInputProps) {
  const yesActive = value === "yes";
  const noActive = value === "no";

  return (
    <div className="flex gap-2 mt-2" role="group" aria-label="Yes or No">
      <button
        type="button"
        className={[
          BASE_BTN,
          yesActive
            ? "bg-accent border-accent text-badge-text font-semibold"
            : "",
        ]
          .filter(Boolean)
          .join(" ")}
        aria-pressed={yesActive}
        onClick={() => onChange("yes")}
      >
        Yes
      </button>
      <button
        type="button"
        className={[
          BASE_BTN,
          noActive
            ? "bg-critical/15 border-critical text-critical font-semibold"
            : "",
        ]
          .filter(Boolean)
          .join(" ")}
        aria-pressed={noActive}
        onClick={() => onChange("no")}
      >
        No
      </button>
    </div>
  );
}
