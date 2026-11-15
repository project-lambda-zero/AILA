import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ForensicsPanelView } from "../../../api/forensics";
import { InvestigateForm } from "./forms";
import { PanelSection } from "./PanelSection";

function json(data: unknown): Response {
  return new Response(JSON.stringify(data), { status: 200, headers: { "content-type": "application/json" } });
}

const investigation = {
  id: "inv-panel",
  project_id: "project-1",
  question: "How did it persist?",
  status: "pending",
  attempts_used: 0,
  max_attempts: 10,
  final_answer: null,
  confidence: null,
  task_id: "task-1",
  parent_investigation_id: null,
  needs_reap: false,
  needs_reap_reason: null,
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("InvestigateForm panel mode", () => {
  it("submits panel mode and hides the free-flow-only attempt budget", async () => {
    const calls: { url: string; body: string }[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL, init?: RequestInit) => {
      calls.push({ url: String(input), body: String(init?.body ?? "") });
      return json({ data: investigation });
    }));
    const onCreated = vi.fn();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <InvestigateForm projectId="project-1" onClose={() => {}} onCreated={onCreated} />
      </QueryClientProvider>,
    );

    fireEvent.click(screen.getByRole("radio", { name: "panel (3 examiners)" }));
    expect(screen.queryByText("max attempts")).toBeNull();
    fireEvent.change(screen.getByPlaceholderText("What executed on host X between 12:00 and 13:00 UTC?"), {
      target: { value: "How did it persist?" },
    });
    fireEvent.click(screen.getByRole("button", { name: "start investigation" }));

    await waitFor(() => expect(onCreated).toHaveBeenCalledWith("inv-panel"));
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toContain("/forensics/projects/project-1/investigate");
    expect(JSON.parse(calls[0]?.body ?? "{}")).toEqual({
      question: "How did it persist?",
      max_attempts: 10,
      mode: "panel",
    });
  });
});

describe("PanelSection", () => {
  it("renders branch state, answer provenance, votes, and analyzer output", () => {
    const view: ForensicsPanelView = {
      investigation_id: "inv-panel",
      branches: [
        { id: "branch-h", persona_voice: "halvar", status: "completed", turn_count: 4, closed_reason: "terminal_submit", created_at: null },
        { id: "branch-m", persona_voice: "maddie", status: "completed", turn_count: 3, closed_reason: null, created_at: null },
      ],
      outcomes: [{
        id: "outcome-1",
        branch_id: "branch-h",
        proposer_persona: "halvar",
        state: "dispatched",
        confidence: "strong",
        answer: "RunOnce launches updater.exe",
        provenance: { primary_artifact: "/evidence/registry.txt" },
        contributions: [],
        reviews: [{
          reviewer_branch_id: "branch-m",
          reviewer_persona: "maddie",
          vote: "approve",
          comment: "registry value verified",
        }],
        created_at: null,
      }],
      messages: [{
        id: "message-1",
        branch_id: "branch-h",
        persona_voice: "halvar",
        sender_kind: "engine",
        payload_kind: "tool_call",
        at_turn: 2,
        text: "tool_run exit=0",
        action: "tool_run",
        command: "grep RunOnce /evidence/registry.txt",
        stdout: "updater.exe",
        stderr: null,
        exit_code: 0,
        created_at: null,
      }],
    };

    render(<PanelSection view={view} />);

    expect(screen.getByTestId("panel-branch-halvar").textContent).toContain("4 turns");
    expect(screen.getByTestId("panel-outcome").textContent).toContain("RunOnce launches updater.exe");
    expect(screen.getByTestId("panel-outcome").textContent).toContain("maddie: approve -- registry value verified");
    expect(screen.getByText("/evidence/registry.txt")).not.toBeNull();
    expect(screen.getByText("updater.exe")).not.toBeNull();
  });
});
