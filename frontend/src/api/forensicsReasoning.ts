/**
 * Forensics reasoning-graph replay queries: the per-turn ReasoningGraphSnapshot
 * list and the backend diff between two steps. Shapes mirror
 * platform/contracts/reasoning.py (ReasoningGraphNode / Edge / Diff) and
 * forensics/contracts/investigation.py (ReasoningGraphSnapshot,
 * ReasoningGraphDiffResult).
 */
import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "./client";
import { parseOne, parseRows } from "./forensics";
import { asRecord, readArray, readNum, readStr } from "./parse";

type Obj = Record<string, unknown>;

export interface ReasoningGraphNode {
  id: string;
  kind: string;
  label: string;
  attributes: Obj;
}

export interface ReasoningGraphEdge {
  source: string;
  target: string;
  kind: string;
  attributes: Obj;
}

export interface ReasoningSnapshot {
  id: string;
  step_number: number;
  strategy_family: string;
  nodes: ReasoningGraphNode[];
  edges: ReasoningGraphEdge[];
  created_at: string | null;
  updated_at: string | null;
}

/** Backend diff: added/removed keyed by node id and (source, target, kind). */
export interface ReasoningGraphDiff {
  from_step: number;
  to_step: number;
  added_nodes: ReasoningGraphNode[];
  removed_nodes: ReasoningGraphNode[];
  added_edges: ReasoningGraphEdge[];
  removed_edges: ReasoningGraphEdge[];
}

const str = (o: Obj, k: string): string => readStr(o, k) ?? "";
const rec = (o: Obj, k: string): Obj => asRecord(o[k]) ?? {};

function parseNode(o: Obj): ReasoningGraphNode {
  return { id: str(o, "id"), kind: str(o, "kind"), label: str(o, "label"), attributes: rec(o, "attributes") };
}

function parseEdge(o: Obj): ReasoningGraphEdge {
  return { source: str(o, "source"), target: str(o, "target"), kind: str(o, "kind"), attributes: rec(o, "attributes") };
}

function parseSnapshot(o: Obj): ReasoningSnapshot {
  const graph = rec(o, "graph");
  return {
    id: str(o, "id"),
    step_number: readNum(o, "step_number") ?? 0,
    strategy_family: str(o, "strategy_family"),
    nodes: parseRows(readArray(graph, "nodes"), parseNode),
    edges: parseRows(readArray(graph, "edges"), parseEdge),
    created_at: readStr(o, "created_at"),
    updated_at: readStr(o, "updated_at"),
  };
}

function parseDiffResult(o: Obj): ReasoningGraphDiff {
  const d = rec(o, "diff");
  return {
    from_step: readNum(d, "from_step") ?? 0,
    to_step: readNum(d, "to_step") ?? 0,
    added_nodes: parseRows(readArray(d, "added_nodes"), parseNode),
    removed_nodes: parseRows(readArray(d, "removed_nodes"), parseNode),
    added_edges: parseRows(readArray(d, "added_edges"), parseEdge),
    removed_edges: parseRows(readArray(d, "removed_edges"), parseEdge),
  };
}

/** GET .../reasoning-graphs: snapshots ordered by step_number. */
export function useReasoningGraphs(projectId: string, investigationId: string) {
  return useQuery({
    queryKey: ["forensics", projectId, "investigation", investigationId, "graphs"],
    queryFn: async () =>
      parseRows(
        await apiFetch<unknown>(`/forensics/projects/${projectId}/investigations/${investigationId}/reasoning-graphs`),
        parseSnapshot,
      ),
    enabled: Boolean(projectId && investigationId),
    retry: false,
  });
}

/** GET .../reasoning-graphs/diff?from_step=&to_step= (both >= 1). */
export function useReasoningGraphDiff(projectId: string, investigationId: string, fromStep: number | null, toStep: number | null) {
  return useQuery({
    queryKey: ["forensics", projectId, "investigation", investigationId, "graph-diff", fromStep, toStep],
    queryFn: async () =>
      parseOne(
        await apiFetch<unknown>(
          `/forensics/projects/${projectId}/investigations/${investigationId}/reasoning-graphs/diff?from_step=${fromStep}&to_step=${toStep}`,
        ),
        parseDiffResult,
      ),
    enabled: Boolean(projectId && investigationId) && fromStep !== null && toStep !== null && fromStep >= 1 && toStep >= 1,
    retry: false,
  });
}
