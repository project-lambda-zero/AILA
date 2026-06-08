export interface TextInputProps {
  value: string;
  onChange: (value: string) => void;
  maxLength?: number;
  multiline?: boolean;
  id?: string;
}

const INPUT_CLS =
  "w-full p-2.5 rounded-md border border-border bg-surface text-text font-sans text-sm resize-y";
const COUNT_CLS =
  "absolute bottom-2 right-3 font-mono text-3xs text-text-muted";

export function TextInput({ value, onChange, maxLength, multiline, id }: TextInputProps) {
  if (multiline) {
    return (
      <div className="relative mt-2">
        <textarea
          id={id}
          className={INPUT_CLS}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          maxLength={maxLength}
          rows={4}
        />
        {maxLength !== undefined && (
          <span className={COUNT_CLS} aria-live="polite">
            {value.length}/{maxLength}
          </span>
        )}
      </div>
    );
  }

  return (
    <div className="relative mt-2">
      <input
        id={id}
        className={INPUT_CLS}
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        maxLength={maxLength}
      />
      {maxLength !== undefined && (
        <span className={COUNT_CLS} aria-live="polite">
          {value.length}/{maxLength}
        </span>
      )}
    </div>
  );
}
