import type { QuestionOptionResponse } from "../../types";

export interface MaturityTierInputProps {
  options: QuestionOptionResponse[]; // exactly 4, value "0"|"1"|"2"|"3"
  value: string | null; // selected tier value or null
  onChange: (value: string) => void;
  name: string;
}

export function MaturityTierInput({ options, value, onChange, name }: MaturityTierInputProps) {
  const sortedOptions = [...options].sort((a, b) => a.display_order - b.display_order);
  const selectedOption = value !== null ? sortedOptions.find((o) => o.value === value) : undefined;

  return (
    <div
      className="flex flex-col gap-3 mt-2"
      role="group"
      aria-label={`Maturity tier for ${name}`}
    >
      <div className="flex gap-1.5">
        {sortedOptions.map((option) => {
          const isActive = option.value === value;
          return (
            <button
              key={option.value}
              type="button"
              className={[
                "flex-1 flex flex-col items-center gap-1 p-2 rounded-[var(--radius-md)] border bg-transparent cursor-pointer transition-colors",
                isActive ? "border-accent bg-accent-muted" : "border-border",
              ]
                .filter(Boolean)
                .join(" ")}
              aria-pressed={isActive}
              onClick={() => onChange(option.value)}
              aria-label={`Level ${option.value}: ${option.label}`}
            >
              <span
                className={`font-mono text-lg ${isActive ? "text-accent" : "text-text-muted"}`}
              >
                {option.value}
              </span>
              <span
                className={`font-sans text-[10px] text-center ${isActive ? "text-accent" : "text-text-muted"}`}
              >
                {option.label}
              </span>
            </button>
          );
        })}
      </div>

      <div className="p-2.5 rounded-[var(--radius-md)] bg-elevated border border-border text-sm text-text-muted">
        {selectedOption ? (
          <>
            <div className="font-mono text-[10px] text-accent uppercase tracking-wider mb-1">
              Level {selectedOption.value}: {selectedOption.label}
            </div>
            {selectedOption.description && <p>{selectedOption.description}</p>}
          </>
        ) : (
          <p className="text-sm text-text-muted italic">
            Select a maturity level to see its description.
          </p>
        )}
      </div>
    </div>
  );
}
