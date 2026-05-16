import { useMutation, useQueryClient } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";
import { toast } from "@/components/ui/sonner";

import type {
  DisclosureUpdate,
  Envelope,
  InvestigationKind,
  OperatorIntent,
  VRFinding,
  VRInvestigationSummary,
  VRMessageSummary,
  VRProjectCreate,
  VRProjectSummary,
  VRWorkspaceSummary,
  WorkspaceTheme,
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

export function usePauseInvestigation(investigationId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<VRInvestigationSummary>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/pause`,
        { method: "POST" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "investigation", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      toast.success("Investigation paused");
    },
    onError: (err: Error) => {
      toast.error(`Pause failed: ${err.message}`);
    },
  });
}

export function useResumeInvestigation(investigationId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<VRInvestigationSummary>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/resume`,
        { method: "POST" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "investigation", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      toast.success("Investigation resumed");
    },
    onError: (err: Error) => {
      toast.error(`Resume failed: ${err.message}`);
    },
  });
}

export interface SendOperatorMessageBody {
  text: string;
  branch_id?: string;
  explicit_intent?: OperatorIntent;
}

export function useSendOperatorMessage(investigationId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: SendOperatorMessageBody) =>
      authorizedRequestJson<Envelope<VRMessageSummary>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/messages`,
        {
          method: "POST",
          body: JSON.stringify(body),
        },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["vr", "investigation-messages", investigationId],
      });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigation", investigationId] });
      toast.success("Message sent — engine will see it next turn");
    },
    onError: (err: Error) => {
      toast.error(`Send failed: ${err.message}`);
    },
  });
}

export interface CreateInvestigationBody {
  title: string;
  initial_question: string;
  target_id: string;
  kind?: InvestigationKind;
  secondary_target_ids?: string[];
  parent_investigation_id?: string;
  strategy_family?: string;
  auto_pilot?: boolean;
  cost_budget_usd?: number;
}

export function useCreateInvestigation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateInvestigationBody) =>
      authorizedRequestJson<Envelope<VRInvestigationSummary>>(
        "/vr/investigations",
        {
          method: "POST",
          body: JSON.stringify(body),
        },
      ),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      toast.success(
        `Investigation "${result.data.title}" started — workflow firing`,
      );
    },
    onError: (err: Error) => {
      toast.error(`Create failed: ${err.message}`);
    },
  });
}

export interface CreateWorkspaceBody {
  name: string;
  slug: string;
  description?: string;
  theme?: WorkspaceTheme;
}

export function useCreateWorkspace() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateWorkspaceBody) =>
      authorizedRequestJson<Envelope<VRWorkspaceSummary>>("/vr/workspaces", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "workspaces"] });
      toast.success(`Workspace "${result.data.name}" created`);
    },
    onError: (err: Error) => {
      toast.error(`Create workspace failed: ${err.message}`);
    },
  });
}
