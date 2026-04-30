import { Question } from "@phosphor-icons/react";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HelpTipProps {
  title: string;
  description: string;
  side?: "top" | "right" | "bottom" | "left";
}

// ---------------------------------------------------------------------------
// HelpTip
// ---------------------------------------------------------------------------

/**
 * HelpTip — inline contextual help tooltip.
 *
 * Renders a small clickable/hoverable "?" icon that shows a tooltip with
 * a title and description. Use next to field labels to explain technical terms.
 *
 * @example
 * ```tsx
 * <label className="flex items-center gap-1">
 *   EPSS Score
 *   <HelpTip
 *     title="EPSS"
 *     description="Exploit Prediction Scoring System — probability a CVE will be exploited in the next 30 days."
 *   />
 * </label>
 * ```
 */
export function HelpTip({ title, description, side = "top" }: HelpTipProps) {
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger
          type="button"
          className="inline-flex items-center justify-center rounded-full text-text-muted hover:text-text transition-colors duration-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent"
          aria-label={`Help: ${title}`}
        >
          <Question size={14} weight="bold" />
        </TooltipTrigger>
        <TooltipContent side={side} className="max-w-xs">
          <div className="flex flex-col gap-1">
            <p className="font-mono text-xs font-semibold">{title}</p>
            <p className="font-mono text-xs text-muted-foreground">{description}</p>
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
