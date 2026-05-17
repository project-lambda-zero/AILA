import { useCallback, useState } from "react";

/**
 * Drag-drop file uploader for binary target artifacts
 * (08_FRONTEND_UX.md §1.2 promise — wizard step 1 + TargetDetailPage).
 *
 * Renders a dashed-border drop zone. Accepts files via drag-drop OR a
 * regular file picker button. On selection it surfaces the picked file
 * to the parent (`onFile`) — the parent decides whether to upload
 * immediately (TargetDetailPage) or stash the filename and upload after
 * project create (Wizard).
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
      className={
        "border-2 border-dashed rounded p-4 text-center transition-colors " +
        (disabled
          ? "border-border-default opacity-40 cursor-not-allowed"
          : dragging
            ? "border-accent bg-accent/5"
            : "border-border-default bg-surface hover:bg-surface-hover")
      }
      role="region"
      aria-label="Upload file by drag and drop or click to pick"
      aria-disabled={disabled}
    >
      <p className="text-sm font-medium text-foreground">
        {dragging ? "Drop to upload" : "Drag a file here"}
      </p>
      <p className="text-xs text-text-muted mt-1">
        or{" "}
        <label className="text-accent hover:underline cursor-pointer">
          pick from disk
          <input
            type="file"
            className="sr-only"
            accept={accept}
            disabled={disabled}
            onChange={handlePick}
          />
        </label>
      </p>
      {hint && (
        <p className="text-[10px] text-text-muted mt-2 font-mono">{hint}</p>
      )}
    </div>
  );
}
