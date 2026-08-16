import { useCallback, useState, type CSSProperties } from "react";

/**
 * Drag-drop file uploader for binary target artifacts
 * (08_FRONTEND_UX.md §1.2 promise -- wizard step 1 + TargetDetailPage).
 *
 * Renders a mock-language bordered dashed drop zone. Accepts files via
 * drag-drop OR a regular file picker button. On selection it surfaces
 * the picked file to the parent (`onFile`) -- the parent decides whether
 * to upload immediately (TargetDetailPage) or stash the filename and
 * upload after project create (Wizard).
 *
 * The dropzone itself does no uploading and holds no transient state
 * beyond `dragging`. Upload progress + errors are the parent's
 * concern.
 */
export function UploadDropzone({
  onFile,
  accept,
  disabled,
  hint,
}: {
  onFile: (file: File) => void;
  accept?: string;
  disabled?: boolean;
  hint?: string;
}) {
  const [dragging, setDragging] = useState(false);

  const handleDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      event.stopPropagation();
      setDragging(false);
      if (disabled) return;
      const file = event.dataTransfer.files?.[0];
      if (file) onFile(file);
    },
    [disabled, onFile],
  );

  const handlePick = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (file) onFile(file);
      event.target.value = "";
    },
    [onFile],
  );

  const borderColor = disabled
    ? "var(--border-faint)"
    : dragging
      ? "var(--accent)"
      : "var(--border-soft)";
  const background = disabled
    ? "var(--surface-sunk)"
    : dragging
      ? "var(--surface-hover)"
      : "var(--surface-sunk)";

  const outerStyle: CSSProperties = {
    border: `1px dashed ${borderColor}`,
    background,
    padding: 18,
    textAlign: "center",
    borderRadius: 3,
    opacity: disabled ? 0.5 : 1,
    cursor: disabled ? "not-allowed" : "default",
    transition: "border-color 120ms, background 120ms",
  };

  return (
    <div
      onDragOver={(event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!disabled) setDragging(true);
      }}
      onDragLeave={(event) => {
        event.preventDefault();
        event.stopPropagation();
        setDragging(false);
      }}
      onDrop={handleDrop}
      className="font-mono uppercase"
      style={outerStyle}
      role="region"
      aria-label="Upload file by drag and drop or click to pick"
      aria-disabled={disabled}
    >
      <div
        style={{
          fontSize: 11,
          letterSpacing: "0.08em",
          color: "var(--text-primary)",
        }}
      >
        {dragging ? "drop to upload" : "drag a file here"}
      </div>
      <div
        style={{
          fontSize: 10,
          letterSpacing: "0.06em",
          color: "var(--text-muted)",
          marginTop: 6,
        }}
      >
        or{" "}
        <label
          style={{
            color: "var(--accent)",
            cursor: disabled ? "not-allowed" : "pointer",
            textDecoration: "underline",
          }}
        >
          pick from disk
          <input
            type="file"
            className="sr-only"
            accept={accept}
            disabled={disabled}
            onChange={handlePick}
          />
        </label>
      </div>
      {hint && (
        <div
          style={{
            fontSize: 9.5,
            letterSpacing: "0.06em",
            color: "var(--text-faint)",
            marginTop: 10,
            textTransform: "none",
          }}
        >
          {hint}
        </div>
      )}
    </div>
  );
}
