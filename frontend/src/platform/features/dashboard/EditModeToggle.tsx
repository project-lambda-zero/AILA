import { Lock, LockOpen } from "lucide-react";

import { Button } from "@/components/ui/button";

export interface EditModeToggleProps {
  editMode: boolean;
  onToggle: () => void;
}

/**
 * EditModeToggle — lock/unlock toggle for dashboard edit mode (D-02).
 *
 * Locked state: shows Lock icon, "Locked" label in muted text.
 * Editing state: shows LockOpen icon, "Editing" label in amber accent text.
 */
export function EditModeToggle({ editMode, onToggle }: EditModeToggleProps) {
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={onToggle}
      aria-label="Toggle dashboard edit mode"
      aria-pressed={editMode}
      className={editMode ? "text-amber-500 hover:text-amber-400" : "text-muted-foreground"}
    >
      {editMode ? (
        <LockOpen className="h-4 w-4 mr-1" />
      ) : (
        <Lock className="h-4 w-4 mr-1" />
      )}
      {editMode ? "Editing" : "Locked"}
    </Button>
  );
}
