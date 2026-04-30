/**
 * PublishVersionDialog.tsx — EDIT-05
 *
 * Confirmation dialog for publishing a new schema version.
 * Shows the next version number, warns about pinned sessions,
 * accepts optional release notes, and calls POST /sbd_nfr/schema/version/publish.
 *
 * Props:
 *   open          — controlled visibility
 *   onClose       — called after success or on cancel
 *   currentVersion — current live version number (next publish = currentVersion + 1)
 */
import { useState } from "react";

import { Warning, CircleNotch, CloudArrowUp } from "@phosphor-icons/react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { authorizedRequestJson } from "@platform/api/http";

import type { SchemaVersionRecord } from "./types";

// ---------------------------------------------------------------------------
// usePublishVersion — inline mutation (NOT re-exported from api.ts to keep
// publish logic scoped to this dialog)
// ---------------------------------------------------------------------------

function usePublishVersion() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (notes: string) =>
      authorizedRequestJson<SchemaVersionRecord>("/sbd_nfr/schema/version/publish", {
        method: "POST",
        body: { notes: notes || null },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "version"] });
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "sections"] });
      toast.success("Schema published successfully");
    },
    onError: (err) =>
      toast.error(
        `Publish failed: ${err instanceof Error ? err.message : String(err)}`,
      ),
  });
}

// ---------------------------------------------------------------------------
// PublishVersionDialog
// ---------------------------------------------------------------------------

interface PublishVersionDialogProps {
  open: boolean;
  onClose: () => void;
  currentVersion: number;
}

export function PublishVersionDialog({
  open,
  onClose,
  currentVersion,
}: PublishVersionDialogProps) {
  const [notes, setNotes] = useState("");
  const mutation = usePublishVersion();
  const nextVersion = currentVersion + 1;

  async function handlePublish() {
    await mutation.mutateAsync(notes);
    setNotes("");
    onClose();
  }

  function handleCancel() {
    if (mutation.isPending) return;
    setNotes("");
    onClose();
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !v && handleCancel()}>
      <DialogContent
        className="bg-[#1a1a1a] border border-amber-500/30 text-amber-100 sm:max-w-[520px]"
      >
        <DialogHeader>
          <DialogTitle className="font-mono text-amber-300 text-lg">
            Publish Schema v{nextVersion}
          </DialogTitle>
          <DialogDescription className="sr-only">
            Confirm publishing schema version {nextVersion}
          </DialogDescription>
        </DialogHeader>

        {/* Pinned session warning */}
        <div className="flex items-start gap-3 rounded-[2px] border border-amber-500/40 bg-amber-500/15 p-3">
          <Warning
            className="mt-0.5 h-5 w-5 shrink-0 text-amber-400"
            weight="fill"
          />
          <p className="text-sm text-amber-200 leading-relaxed">
            Existing assessment sessions will remain pinned to their schema
            version. They will not see questions added in this version.
          </p>
        </div>

        {/* Release notes */}
        <div className="flex flex-col gap-1.5">
          <label
            htmlFor="publish-notes"
            className="font-mono text-xs text-amber-500/80 uppercase tracking-wide"
          >
            Release notes (optional)
          </label>
          <Textarea
            id="publish-notes"
            rows={3}
            placeholder="Describe what changed in this version…"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            disabled={mutation.isPending}
            className="resize-none bg-[#131313] border-amber-500/20 text-amber-100 placeholder:text-amber-500/40 focus-visible:ring-amber-500/40 font-mono text-sm"
          />
        </div>

        <DialogFooter className="gap-2 sm:gap-2">
          <Button
            type="button"
            variant="ghost"
            disabled={mutation.isPending}
            onClick={handleCancel}
            className="font-mono text-xs text-amber-500/70 hover:text-amber-400 hover:bg-amber-500/10"
          >
            Cancel
          </Button>
          <Button
            type="button"
            disabled={mutation.isPending}
            onClick={() => void handlePublish()}
            className="font-mono text-xs bg-amber-500 hover:bg-amber-400 text-[#131313] font-semibold min-w-[140px]"
          >
            {mutation.isPending ? (
              <>
                <CircleNotch className="mr-1.5 h-4 w-4 animate-spin" />
                Publishing…
              </>
            ) : (
              <>
                <CloudArrowUp className="mr-1.5 h-4 w-4" />
                Publish v{nextVersion}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
