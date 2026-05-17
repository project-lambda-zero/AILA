import { useEffect, useRef } from "react";

import { toast } from "@/components/ui/sonner";

import { useVRProjects } from "../queries";

/** Browser/toast notification when a VR project transitions to a
 *  terminal state (08_FRONTEND_UX.md §Topic 6 — Kenji's quote on
 *  toast-on-complete). Mount at the shell-level once.
 *
 *  Tracks a per-project status snapshot in a ref. On poll diff, fires
 *  one notification per transition. If the document is hidden,
 *  attempts a browser Notification (gated on the user having granted
 *  permission). */
export function useProjectCompleteNotifier() {
  const { data } = useVRProjects();
  const prevStatusByProject = useRef<Map<string, string>>(new Map());

  useEffect(() => {
    const projects = data?.data ?? [];
    const current = new Map<string, string>();
    for (const p of projects) current.set(p.id, p.status);

    if (prevStatusByProject.current.size === 0) {
      // First render — seed the snapshot, don't notify.
      prevStatusByProject.current = current;
      return;
    }

    for (const [id, status] of current) {
      const prev = prevStatusByProject.current.get(id);
      if (!prev || prev === status) continue;
      // Notify on terminal transitions only
      if (status === "completed" || status === "failed") {
        const proj = projects.find((p) => p.id === id);
        const title = proj?.name ?? "VR project";
        const msg = `${title} → ${status}`;
        if (status === "completed") {
          toast.success(msg, {
            description: proj?.finding_count
              ? `${proj.finding_count} finding(s) produced`
              : "no findings",
          });
        } else {
          toast.error(msg);
        }
        if (
          typeof window !== "undefined" &&
          "Notification" in window &&
          Notification.permission === "granted" &&
          document.hidden
        ) {
          new Notification("AILA — VR", { body: msg });
        }
      }
    }

    prevStatusByProject.current = current;
  }, [data]);
}
