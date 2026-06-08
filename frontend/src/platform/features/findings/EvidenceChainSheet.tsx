import { useState } from "react";
import { TreeStructure } from "@phosphor-icons/react/dist/csr/TreeStructure";

import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { EvidenceChainGraph } from "./EvidenceChainGraph";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface EvidenceChainSheetProps {
  findingId: number;
  findingLabel?: string;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * EvidenceChainSheet — slide-over panel with the ReactFlow evidence graph (UX-05).
 *
 * Renders a "Show Evidence Chain" trigger button. When clicked, opens a Sheet
 * containing the EvidenceChainGraph for the given finding ID.
 *
 * @example
 * ```tsx
 * <EvidenceChainSheet findingId={42} findingLabel="CVE-2023-12345 on arch-vm" />
 * ```
 */
export function EvidenceChainSheet({ findingId, findingLabel }: EvidenceChainSheetProps) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        onClick={() => setOpen(true)}
        className="gap-1.5"
        title="Show evidence provenance chain"
      >
        <TreeStructure size={14} />
        Evidence Chain
      </Button>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="w-full sm:max-w-3xl overflow-y-auto">
          <SheetHeader className="mb-4">
            <SheetTitle className="font-mono text-sm">
              Evidence Chain
            </SheetTitle>
            <SheetDescription className="font-mono text-xs text-text-muted">
              {findingLabel
                ? `Provenance graph for: ${findingLabel}`
                : `Finding #${findingId} — scan → advisory → score → triage`}
            </SheetDescription>
          </SheetHeader>

          <EvidenceChainGraph findingId={findingId} />
        </SheetContent>
      </Sheet>
    </>
  );
}
