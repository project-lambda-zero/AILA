import { describe, expect, it } from "vitest";

import type { RailRow } from "../api/forensicsRail";
import { RAIL_ROW_LIMIT, selectRailRows } from "./railRows";

function row(id: string, status: string, extra: Partial<RailRow> = {}): RailRow {
  return { id, title: id, status, is_favorite: false, branch_count: 0, message_count: 0, ...extra };
}

const ids = (rows: RailRow[]): string[] => rows.map((r) => r.id);

describe("selectRailRows: forensics", () => {
  it("keeps an unpinned analyzing project visible", () => {
    const rows = selectRailRows([row("f1", "analyzing")], [], "forensics");
    expect(ids(rows)).toEqual(["f1"]);
  });

  it("hides an unpinned ready project", () => {
    const rows = selectRailRows([row("f1", "ready")], [], "forensics");
    expect(rows).toEqual([]);
  });

  it("still keeps running and active projects visible", () => {
    const rows = selectRailRows(
      [row("f1", "running"), row("f2", "active")],
      [],
      "forensics",
    );
    expect(ids(rows).sort()).toEqual(["f1", "f2"]);
  });

  it("hides completed and failed projects unless pinned", () => {
    const rows = selectRailRows(
      [row("f1", "completed"), row("f2", "failed")],
      [],
      "forensics",
    );
    expect(rows).toEqual([]);
  });

  it("keeps a pinned ready project visible via the pinned list", () => {
    const rows = selectRailRows([row("f1", "ready")], ["f1"], "forensics");
    expect(ids(rows)).toEqual(["f1"]);
  });

  it("keeps a favorited ready project visible", () => {
    const rows = selectRailRows(
      [row("f1", "ready", { is_favorite: true })],
      [],
      "forensics",
    );
    expect(ids(rows)).toEqual(["f1"]);
  });

  it("does not produce an empty rail when only an analyzing project exists", () => {
    const rows = selectRailRows(
      [row("f1", "ready"), row("f2", "analyzing"), row("f3", "completed")],
      [],
      "forensics",
    );
    expect(rows.length).toBe(1);
    expect(ids(rows)).toEqual(["f2"]);
  });
});

describe("selectRailRows: non-forensics controls", () => {
  it.each(["vr", "malware", "vulnerability"])(
    "%s: analyzing is not active and stays hidden",
    (moduleId) => {
      const rows = selectRailRows([row("x1", "analyzing")], [], moduleId);
      expect(rows).toEqual([]);
    },
  );

  it.each(["vr", "malware", "vulnerability"])(
    "%s: ready stays hidden unless pinned",
    (moduleId) => {
      const hidden = selectRailRows([row("x1", "ready")], [], moduleId);
      const pinned = selectRailRows([row("x1", "ready")], ["x1"], moduleId);
      expect(hidden).toEqual([]);
      expect(ids(pinned)).toEqual(["x1"]);
    },
  );

  it.each(["vr", "malware", "vulnerability"])(
    "%s: running and active remain visible",
    (moduleId) => {
      const rows = selectRailRows(
        [row("x1", "running"), row("x2", "active")],
        [],
        moduleId,
      );
      expect(ids(rows).sort()).toEqual(["x1", "x2"]);
    },
  );
});

describe("selectRailRows: ordering and bounds", () => {
  it("places pinned rows first, then orders by activity weight", () => {
    const rows = selectRailRows(
      [
        row("low", "running", { branch_count: 1, message_count: 0 }),
        row("high", "running", { branch_count: 5, message_count: 0 }),
        row("pinnedReady", "ready", { branch_count: 0, message_count: 0 }),
      ],
      ["pinnedReady"],
      "forensics",
    );
    expect(ids(rows)).toEqual(["pinnedReady", "high", "low"]);
  });

  it("caps the result at the row limit", () => {
    const many = Array.from({ length: RAIL_ROW_LIMIT + 10 }, (_, i) =>
      row(`r${i}`, "running", { branch_count: i }),
    );
    const rows = selectRailRows(many, [], "forensics");
    expect(rows.length).toBe(RAIL_ROW_LIMIT);
  });

  it("does not mutate the input array", () => {
    const raw = [row("a", "ready"), row("b", "analyzing", { branch_count: 2 })];
    const snapshot = ids(raw);
    selectRailRows(raw, ["a"], "forensics");
    expect(ids(raw)).toEqual(snapshot);
  });
});
