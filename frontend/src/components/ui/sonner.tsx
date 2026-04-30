/**
 * Toaster — thin wrapper around sonner's Toaster for consistent AILA styling.
 *
 * Re-exports `toast` from sonner so callers only need:
 *   import { toast } from "@/components/ui/sonner";
 *
 * Position: top-right on desktop.
 * richColors: maps variant to semantic AILA palette.
 * closeButton: always visible for accessibility.
 * Duration defaults: 5 000 ms (overridden per-call for warning/critical).
 */
import { Toaster as SonnerToaster } from "sonner";

export function Toaster() {
  return (
    <SonnerToaster
      position="top-right"
      richColors
      closeButton
      duration={5000}
      toastOptions={{
        classNames: {
          toast: "font-sans text-sm",
          title: "font-semibold",
          description: "text-xs text-muted-foreground",
          closeButton: "opacity-60 hover:opacity-100",
        },
      }}
    />
  );
}

export { toast } from "sonner";
