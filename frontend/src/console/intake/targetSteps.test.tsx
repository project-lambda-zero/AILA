// @vitest-environment jsdom
/** Regression for issue #355: the intake target picker must show the backend
 * analysis_state_message for failed targets, and only for failed targets.
 *
 * Renders the real TargetSteps step body with the real malware intake config.
 * Only callbacks are stubbed. Synthetic fixtures only. */

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { TargetRow } from "../../api/intake";
import { INTAKE } from "./config";
import { TargetSteps } from "./targetSteps";

const FAILURE_MESSAGE = "synthetic sandbox timed out after 300s";

function row(overrides: Partial<TargetRow>): TargetRow {
  return {
    id: "target-1",
    display_name: "synthetic-sample",
    kind: "pe_sample",
    workspace_id: "ws-1",
    workspace_name: "synthetic-workspace",
    analysis_state: "ready",
    analysis_state_message: null,
    ...overrides,
  };
}

function renderPicker(matches: TargetRow[]) {
  const cfg = INTAKE.malware;

  return render(
    <TargetSteps
      cfg={cfg}
      step={1}
      kind="pe_sample"
      kd={cfg.kinds[0]}
      hasInv={false}
      invKind=""
      setInvKind={vi.fn()}
      auto={false}
      setAuto={vi.fn()}
      budget={5}
      setBudget={vi.fn()}
      question=""
      setQuestion={vi.fn()}
      targetId={null}
      targetName=""
      targetLine=""
      workspaceFilter=""
      setWorkspaceFilter={vi.fn()}
      workspaceRows={[]}
      targetsState={{ isLoading: false, isError: false, matches }}
      onPickKind={vi.fn()}
      onPickTarget={vi.fn()}
      autoStyle={{}}
      launchError={null}
      stage={0}
    />,
  );
}

afterEach(() => {
  cleanup();
});

describe("intake target picker failure reason", () => {
  it("shows the exact analysis_state_message on a failed target row", () => {
    renderPicker([row({ analysis_state: "failed", analysis_state_message: FAILURE_MESSAGE })]);

    expect(screen.getByText(/synthetic-workspace · failed/)).not.toBeNull();
    expect(screen.getByText(FAILURE_MESSAGE)).not.toBeNull();
  });

  it("shows only the state label on a failed row without a message", () => {
    renderPicker([row({ analysis_state: "failed", analysis_state_message: null })]);

    expect(screen.getByText(/synthetic-workspace · failed/)).not.toBeNull();
    expect(screen.queryByTestId("intake-target-failure-reason")).toBeNull();
  });

  it("shows only the state label on a failed row with a whitespace-only message", () => {
    renderPicker([row({ analysis_state: "failed", analysis_state_message: "   " })]);

    expect(screen.queryByTestId("intake-target-failure-reason")).toBeNull();
  });

  it("does not show a message on a ready row even when one is present", () => {
    renderPicker([row({ analysis_state: "ready", analysis_state_message: FAILURE_MESSAGE })]);

    expect(screen.getByText(/synthetic-workspace · ready/)).not.toBeNull();
    expect(screen.queryByText(FAILURE_MESSAGE)).toBeNull();
    expect(screen.queryByTestId("intake-target-failure-reason")).toBeNull();
  });

  it("does not show a message on a pending row even when one is present", () => {
    renderPicker([row({ analysis_state: "pending", analysis_state_message: FAILURE_MESSAGE })]);

    expect(screen.getByText(/synthetic-workspace · pending/)).not.toBeNull();
    expect(screen.queryByText(FAILURE_MESSAGE)).toBeNull();
    expect(screen.queryByTestId("intake-target-failure-reason")).toBeNull();
  });
});
