import type { QuestionOptionResponse } from "../../types";

export interface RadioCardInputProps {
  options: QuestionOptionResponse[];
  value: string | null;
  onChange: (value: string) => void;
  name: string;
}

export function RadioCardInput({ options, value, onChange, name }: RadioCardInputProps) {
  const sorted = [...options].sort((a, b) => a.display_order - b.display_order);

  return (
    <div
      className="flex flex-col gap-2 mt-2"
      role="radiogroup"
      aria-labelledby={`${name}-label`}
    >
      {sorted.map((option) => {
        const isSelected = option.value === value;
        return (
          <label
            key={option.value}
            className={[
              "flex items-start gap-3 p-3 rounded-md border bg-transparent cursor-pointer transition-colors hover:bg-elevated",
              isSelected ? "border-accent bg-accent-muted" : "border-border",
            ]
              .filter(Boolean)
              .join(" ")}
          >
            <input
              className="sr-only"
              type="radio"
              name={name}
              value={option.value}
              checked={isSelected}
              onChange={() => onChange(option.value)}
            />
            <span className="font-sans text-sm text-text">{option.label}</span>
            {option.description && (
              <span className="text-xs text-text-muted mt-0.5">{option.description}</span>
            )}
          </label>
        );
      })}
    </div>
  );
}
