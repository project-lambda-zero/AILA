import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { AilaBadge, type TaskStatus } from "@/components/aila/AilaBadge";

describe("AilaBadge status variants", () => {
  const statuses: TaskStatus[] = [
    "completed",
    "running",
    "failed",
    "queued",
    "waiting",
    "paused",
  ];

  it.each(statuses)("applies aila-badge-status-%s class for status=%s", (status) => {
    render(
      <AilaBadge status={status} data-testid={`badge-${status}`}>
        {status}
      </AilaBadge>,
    );
    const node = screen.getByTestId(`badge-${status}`);
    expect(node.className).toContain(`aila-badge-status-${status}`);
  });

  it("status-completed class name differs from any severity class name (no collision)", () => {
    render(
      <>
        <AilaBadge status="completed" data-testid="s-completed">completed</AilaBadge>
        <AilaBadge severity="low" data-testid="sev-low">low</AilaBadge>
      </>,
    );
    const s = screen.getByTestId("s-completed").className;
    const l = screen.getByTestId("sev-low").className;
    expect(s).toContain("aila-badge-status-completed");
    expect(l).not.toContain("aila-badge-status-completed");
  });

  it("does not alter severity rendering when status is absent", () => {
    render(
      <AilaBadge severity="critical" data-testid="sev-critical">
        critical
      </AilaBadge>,
    );
    const node = screen.getByTestId("sev-critical");
    expect(node.className).not.toContain("aila-badge-status-");
  });
});
