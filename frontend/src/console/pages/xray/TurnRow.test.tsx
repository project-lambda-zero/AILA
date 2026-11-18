import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Message } from "../../../api/types";
import { TurnList } from "./TurnRow";

const lazyMounts = vi.hoisted(() => ({ count: 0 }));

vi.mock("./LazyCode", () => ({
  LazyCodeBlock: () => {
    lazyMounts.count += 1;
    return null;
  },
}));

function textMessage(id: string, atTurn: number): Message {
  return {
    id,
    investigation_id: "synthetic-investigation",
    sender_kind: "agent",
    payload_kind: "text",
    payload: { text: `prose ${id}` },
    at_turn: atTurn,
  };
}

function toolCallMessage(id: string, atTurn: number): Message {
  return {
    id,
    investigation_id: "synthetic-investigation",
    sender_kind: "agent",
    payload_kind: "tool_call",
    payload: { reasoning: "inspect the parser", script_content: "print('synthetic')" },
    at_turn: atTurn,
  };
}

afterEach(() => {
  cleanup();
  lazyMounts.count = 0;
});

describe("TurnList", () => {
  it("does not re-render unchanged rows when the parent re-renders", () => {
    const groups = [[textMessage("a", 1)], [textMessage("b", 2)], [textMessage("c", 3)]];
    const resolvePersona = vi.fn(() => ({ name: "AGENT", role: "agent", tone: "#000" }));
    const setOpenTurn = vi.fn();
    const props = { groups, openTurn: null, setOpenTurn, resolvePersona, showClock: false };

    const { rerender } = render(<TurnList {...props} />);
    const initialCalls = resolvePersona.mock.calls.length;
    expect(initialCalls).toBeGreaterThan(0);

    // Same group object references and same openTurn: memoized rows must skip rendering.
    rerender(<TurnList {...props} groups={[...groups]} />);
    expect(resolvePersona.mock.calls.length).toBe(initialCalls);
  });

  it("mounts the code block only for the open tool-call row", () => {
    const groups = [[toolCallMessage("tool", 1)], [textMessage("text", 2)]];
    const resolvePersona = vi.fn(() => ({ name: "AGENT", role: "agent", tone: "#000" }));
    const setOpenTurn = vi.fn();
    const base = { groups, setOpenTurn, resolvePersona, showClock: false };

    const { rerender } = render(<TurnList {...base} openTurn={null} />);
    expect(lazyMounts.count).toBe(0);

    rerender(<TurnList {...base} openTurn="tool" />);
    expect(lazyMounts.count).toBe(1);
  });
});
