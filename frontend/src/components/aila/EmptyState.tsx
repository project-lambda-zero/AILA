import { useNavigate } from "react-router";
import { Button } from "@/components/ui/button";
import { AilaCard } from "./AilaCard";

// ---------------------------------------------------------------------------
// Types
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

// ---------------------------------------------------------------------------
// Action button -- handles both onClick and href navigation
// ---------------------------------------------------------------------------

function ActionButton({
  action,
  variant = "default",
}: {
  action: EmptyStateAction;
  variant?: "default" | "outline";
}) {
  const navigate = useNavigate();

  function handleClick() {
    if (action.onClick) {
      action.onClick();
    } else if (action.href) {
      navigate(action.href);
    }
  }

  return (
    <Button
      size="sm"
      variant={variant}
      onClick={handleClick}
      className="min-h-[44px] sm:min-h-auto"
    >
      {action.label}
    </Button>
  );
}

// ---------------------------------------------------------------------------
// EmptyState
// ---------------------------------------------------------------------------

/**
 * EmptyState -- standardized empty state component for all AILA pages.
 *
 * Shows an optional icon, title, description, and up to two action buttons.
 * Use whenever a list, table, or data area has no items to display.
 *
 * @example
 * ```tsx
 * <EmptyState
 *   icon={<Monitor className="h-10 w-10" />}
 *   title="No systems registered"
 *   description="Register your first SSH-reachable system to start scanning."
 *   action={{ label: "Register System", onClick: () => setShowForm(true) }}
 * />
 * ```
 */
export function EmptyState({
  icon,
  title,
  description,
  action,
  secondaryAction,
  className,
}: EmptyStateProps) {
  return (
    <AilaCard variant="default"
    padding="lg"
    className={`flex flex-col items-center gap-4 text-center ${className ?? ""}`} techBorder glow>{icon && (
      <div className="text-text-muted opacity-40" aria-hidden="true">
        {icon}
      </div>
    )}
    
    <div className="flex flex-col gap-1">
      <h2 className="font-mono text-sm font-semibold text-text">{title}</h2>
      {description && (
        <p className="font-mono text-xs text-text-muted max-w-sm">{description}</p>
      )}
    </div>
    
    {(action || secondaryAction) && (
      <div className="flex flex-col sm:flex-row items-center gap-2">
        {action && <ActionButton action={action} variant="default" />}
        {secondaryAction && (
          <ActionButton action={secondaryAction} variant="outline" />
        )}
      </div>
    )}</AilaCard>
  );
}
