import { useNavigate } from "react-router";

// ---------------------------------------------------------------------------
// EmptyState -- mock design-system empty state. A centered, bordered mono
// panel with an uppercase title, optional description, and up to two actions.
// API preserved from the previous AilaCard-based version so existing callers
// keep working; presentation is the mock language (tokens + mono, no shadcn).
// ---------------------------------------------------------------------------

interface EmptyStateAction {
  label: string;
  onClick?: () => void;
  href?: string;
}

export interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: EmptyStateAction;
  secondaryAction?: EmptyStateAction;
  className?: string;
}

function ActionButton({
  action,
  primary = false,
}: {
  action: EmptyStateAction;
  primary?: boolean;
}) {
  const navigate = useNavigate();
  const handle = () => {
    if (action.onClick) action.onClick();
    else if (action.href) navigate(action.href);
  };
  return (
    <button
      type="button"
      onClick={handle}
      className="font-mono uppercase"
      style={{
        height: 30,
        padding: "0 14px",
        fontSize: 11,
        letterSpacing: "0.06em",
        borderRadius: 3,
        cursor: "pointer",
        color: primary ? "var(--text-on-accent)" : "var(--text-muted)",
        background: primary ? "var(--accent)" : "var(--surface-sunk)",
        border: `1px solid ${primary ? "var(--accent)" : "var(--border-soft)"}`,
      }}
    >
      {action.label}
    </button>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  secondaryAction,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={`flex flex-col items-center gap-3 text-center ${className ?? ""}`}
      style={{
        padding: 34,
        border: "1px solid var(--border-soft)",
        background: "var(--surface-card)",
        borderRadius: 4,
        boxShadow: "var(--bevel-raised)",
      }}
    >
      {icon ? (
        <div aria-hidden="true" style={{ color: "var(--text-faint)" }}>
          {icon}
        </div>
      ) : null}
      <div
        className="font-mono uppercase"
        style={{ fontSize: 12, letterSpacing: "0.1em", color: "var(--text-primary)" }}
      >
        {title}
      </div>
      {description ? (
        <div
          className="font-mono"
          style={{ fontSize: 11, lineHeight: 1.5, color: "var(--text-muted)", maxWidth: 440 }}
        >
          {description}
        </div>
      ) : null}
      {action || secondaryAction ? (
        <div className="flex items-center gap-2" style={{ marginTop: 4 }}>
          {action ? <ActionButton action={action} primary /> : null}
          {secondaryAction ? <ActionButton action={secondaryAction} /> : null}
        </div>
      ) : null}
    </div>
  );
}
