import { useMutation, useQueryClient } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";
import { toast } from "@/components/ui/sonner";

import type {
  DisclosureUpdate,
  Envelope,
  VRFinding,
  VRProjectCreate,
  VRProjectSummary,
} from "./types";

export function useCreateVRProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: VRProjectCreate) =>
      authorizedRequestJson<Envelope<VRProjectSummary>>("/vr/projects", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "projects"] });
      toast.success(`VR project "${result.data.name}" created`);
    },
    onError: (err: Error) => {
      toast.error(`Failed to create VR project: ${err.message}`);
    },
  });
}

export function useUpdateDisclosure(projectId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      findingId,
      body,
    }: {
      findingId: string;
      body: DisclosureUpdate;
    }) =>
      authorizedRequestJson<Envelope<VRFinding>>(
        `/vr/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/disclosure`,
        {
          method: "PATCH",
          body: JSON.stringify(body),
        },
      ),
    onSuccess: (_result, variables) => {
      queryClient.invalidateQueries({
        queryKey: ["vr", "findings", projectId],
      });
      queryClient.invalidateQueries({
        queryKey: ["vr", "finding", projectId, variables.findingId],
      });
      toast.success("Disclosure status updated");
    },
    onError: (err: Error) => {
      toast.error(`Failed to update disclosure: ${err.message}`);
    },
  });
}
