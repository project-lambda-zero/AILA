import type { QuestionOptionResponse } from "../../types";

export interface SelectInputProps {
  options: QuestionOptionResponse[];
  value: string | null;
  onChange: (value: string) => void;
  id?: string;
}

export function SelectInput({ options, value, onChange, id }: SelectInputProps) {
  const sorted = [...options].sort((a, b) => a.display_order - b.display_order);

  return (
    <select
      id={id}
      className="w-full p-2.5 rounded-md border border-border bg-surface text-text font-sans text-sm appearance-none cursor-pointer"
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value)}
    >
      <option value="" disabled>
        Select…
      </option>
      {sorted.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}
