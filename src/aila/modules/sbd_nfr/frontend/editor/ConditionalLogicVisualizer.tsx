/**
 * ConditionalLogicVisualizer.tsx — EDIT-04
 *
 * ReactFlow-based tree showing scope answer → section/question trigger chains.
 * Nodes are derived from real section + question data (no hardcoded sample graph).
 *
 * Node types:
 *  - rootNode: "Scope Answers" anchor
 *  - scopeNode: questions with question_type === "scope"
 *  - sectionNode: sections with depends_on_question_id != null
 *  - condNode: non-scope questions with depends_on_question_id != null
 *
 * Clicking a node highlights it and its connected edges in amber.
 */
import * as React from "react";

import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type NodeTypes,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { EmptyState } from "@/components/aila/EmptyState";
import { Badge } from "@/components/ui/badge";

import { useSchemaSections, useSchemaQuestions } from "./api";
import type { QuestionListItem as QuestionFlat, SectionFlat } from "./types";

// ---------------------------------------------------------------------------
// Custom node renderers
// ---------------------------------------------------------------------------

function RootNode({ data }: NodeProps) {
  const label = (data as { label?: string }).label ?? "Scope Answers";
  return (
    <div
      style={{ clipPath: "polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%)", background: 'var(--color-accent)' }}
      className="flex h-14 w-36 items-center justify-center shadow-lg"
    >
      <span className="font-mono text-xs font-bold text-badge-text text-center px-1">{label}</span>
    </div>
  );
}

function ScopeNode({ data }: NodeProps) {
  const d = data as { label?: string; answerId?: string };
  return (
    <div className="rounded-md border border-accent/60 bg-surface px-3 py-2 shadow" style={{ maxWidth: 180 }}>
      <p className="font-mono text-3xs text-accent uppercase tracking-wider mb-0.5">Scope Q</p>
      <p className="font-mono text-xs text-text leading-tight">{d.label ?? "Question"}</p>
    </div>
  );
}

function SectionNode({ data }: NodeProps) {
  const d = data as { label?: string; sectionKey?: string };
  return (
    <div className="rounded-md border-l-2 border-l-lavender border border-border bg-surface px-3 py-2 shadow" style={{ maxWidth: 200 }}>
      <p className="font-mono text-3xs text-lavender uppercase tracking-wider mb-0.5">Section</p>
      <p className="font-mono text-xs text-text leading-tight">{d.label ?? "Section"}</p>
      {d.sectionKey && (
        <Badge
          variant="outline"
          className="mt-1 text-4xs border-lavender/30 text-lavender"
        >
          {d.sectionKey}
        </Badge>
      )}
    </div>
  );
}

function CondNode({ data }: NodeProps) {
  const d = data as { label?: string };
  return (
    <div className="rounded-md border border-dashed border-accent/50 bg-surface px-3 py-2 shadow" style={{ maxWidth: 180 }}>
      <p className="font-mono text-3xs text-accent/60 uppercase tracking-wider mb-0.5">Conditional Q</p>
      <p className="font-mono text-xs text-text/90 leading-tight">{d.label ?? "Question"}</p>
    </div>
  );
}

const nodeTypes: NodeTypes = {
  rootNode: RootNode,
  scopeNode: ScopeNode,
  sectionNode: SectionNode,
  condNode: CondNode,
};

// ---------------------------------------------------------------------------
// Graph construction
// ---------------------------------------------------------------------------

interface BuildResult {
  nodes: Node[];
  edges: Edge[];
}

function truncate(text: string, max = 40): string {
  return text.length > max ? text.slice(0, max) + "…" : text;
}

function buildGraph(sections: SectionFlat[], questions: QuestionFlat[]): BuildResult {
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Root node
  nodes.push({
    id: "root",
    type: "rootNode",
    position: { x: 0, y: 200 },
    data: { label: "Scope Answers" },
    deletable: false,
  });

  // Scope questions → root
  const scopeQuestions = questions.filter((q) => q.question_type === "scope");
  scopeQuestions.forEach((q, idx) => {
    const nodeId = `q:${q.id}`;
    const y = idx * 90;
    nodes.push({
      id: nodeId,
      type: "scopeNode",
      position: { x: 250, y },
      data: { label: truncate(q.label), answerId: q.id },
    });
    edges.push({
      id: `e:root:${nodeId}`,
      source: "root",
      target: nodeId,
      style: { stroke: 'var(--color-accent)', strokeWidth: 1.5 },
    });
  });

  // Conditional sections → triggered by scope question
  const conditionalSections = sections.filter((s) => s.depends_on_question_id != null);
  let sectionY = 0;
  for (const section of conditionalSections) {
    const nodeId = `s:${section.id}`;
    nodes.push({
      id: nodeId,
      type: "sectionNode",
      position: { x: 500, y: sectionY },
      data: { label: truncate(section.label), sectionKey: section.section_key },
    });
    edges.push({
      id: `e:q:${section.depends_on_question_id}:s:${section.id}`,
      source: `q:${section.depends_on_question_id}`,
      target: nodeId,
      label: section.expected_when ? `when: ${section.expected_when}` : undefined,
      labelStyle: { fill: 'var(--color-accent)', fontSize: 9, fontFamily: 'var(--font-mono)' },
      labelBgStyle: { fill: 'var(--color-base)' },
      style: { stroke: 'var(--color-accent)', strokeWidth: 1 },
    });
    sectionY += 90;
  }

  // Conditional questions → triggered by other question
  const conditionalQuestions = questions.filter(
    (q) => q.depends_on_question_id != null && q.question_type !== "scope",
  );
  let condY = 0;
  for (const q of conditionalQuestions) {
    const nodeId = `qc:${q.id}`;
    nodes.push({
      id: nodeId,
      type: "condNode",
      position: { x: 750, y: condY },
      data: { label: truncate(q.label), questionId: q.id },
    });
    edges.push({
      id: `e:dep:${q.id}`,
      source: `q:${q.depends_on_question_id}`,
      target: nodeId,
      label: q.expected_when ? `when: ${q.expected_when}` : undefined,
      labelStyle: { fill: 'var(--color-accent)', fontSize: 9, fontFamily: 'var(--font-mono)' },
      labelBgStyle: { fill: 'var(--color-base)' },
      style: { stroke: 'var(--color-accent)', strokeWidth: 1 },
    });
    condY += 80;
  }

  return { nodes, edges };
}

// ---------------------------------------------------------------------------
// Info panel for selected node
// ---------------------------------------------------------------------------

interface SelectedNodeData {
  id: string;
  label?: string;
  answerId?: string;
  sectionKey?: string;
  questionId?: string;
  expectedWhen?: string;
}

function InfoPanel({ nodeData }: { nodeData: SelectedNodeData }) {
  return (
    <div className="absolute bottom-4 left-4 z-10 rounded-md border border-border bg-base/95 px-4 py-3 shadow-lg" style={{ maxWidth: 240 }}>
      <p className="font-mono text-3xs text-accent/70 uppercase tracking-wider mb-1">
        Selected node
      </p>
      <p className="font-mono text-sm text-text font-medium leading-snug">
        {nodeData.label ?? nodeData.id}
      </p>
      {(nodeData.sectionKey ?? nodeData.questionId ?? nodeData.answerId) && (
        <p className="font-mono text-2xs text-text-muted mt-1">
          key: {nodeData.sectionKey ?? nodeData.questionId ?? nodeData.answerId}
        </p>
      )}
      {nodeData.expectedWhen && (
        <p className="font-mono text-2xs text-accent/70 mt-0.5">
          when: {nodeData.expectedWhen}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

/**
 * ConditionalLogicVisualizer — EDIT-04
 *
 * Renders a ReactFlow graph derived from real section + question depends_on data.
 * Shows empty state when no conditional logic is defined.
 */
export function ConditionalLogicVisualizer() {
  const { data: sections, isLoading: loadingSections } = useSchemaSections();
  const { data: questions, isLoading: loadingQuestions } = useSchemaQuestions();

  const [selectedNodeId, setSelectedNodeId] = React.useState<string | null>(null);

  const { nodes: initialNodes, edges: initialEdges } = React.useMemo(() => {
    if (!sections || !questions) return { nodes: [], edges: [] };
    return buildGraph(sections, questions);
  }, [sections, questions]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync when data loads
  React.useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  // Apply amber highlight to selected node + connected edges
  const styledNodes = React.useMemo(
    () =>
      nodes.map((n) => ({
        ...n,
        style:
          n.id === selectedNodeId
            ? { outline: "2px solid #F59E0B", outlineOffset: "2px", ...n.style }
            : n.style,
      })),
    [nodes, selectedNodeId],
  );

  const styledEdges = React.useMemo(() => {
    if (!selectedNodeId) return edges;
    return edges.map((e) => {
      const connected = e.source === selectedNodeId || e.target === selectedNodeId;
      if (!connected) return e;
      return {
        ...e,
        style: { stroke: "#F59E0B", strokeWidth: 2.5, ...(e.style ?? {}) },
        animated: true,
      };
    });
  }, [edges, selectedNodeId]);

  const isLoading = loadingSections || loadingQuestions;

  if (isLoading) {
    return (
      <div style={{ height: 600 }} className="flex items-center justify-center bg-base rounded-md border border-border">
        <p className="font-mono text-sm text-text-muted animate-pulse">
          Building conditional logic graph...
        </p>
      </div>
    );
  }

  const hasConditionalLogic =
    (sections ?? []).some((s) => s.depends_on_question_id != null) ||
    (questions ?? []).some((q) => q.depends_on_question_id != null && q.question_type !== "scope");

  if (!hasConditionalLogic) {
    return (
      <EmptyState
        title="No conditional logic defined"
        description="Add depends_on_question_id to sections or questions to see the trigger tree."
      />
    );
  }

  // Find info for selected node
  const selectedNode = selectedNodeId
    ? styledNodes.find((n) => n.id === selectedNodeId)
    : null;

  const selectedNodeData: SelectedNodeData | null = selectedNode
    ? { id: selectedNode.id, ...(selectedNode.data as Record<string, unknown>) }
    : null;

  return (
    <div
      style={{ height: 600, position: 'relative', overflow: 'hidden', borderRadius: 'var(--radius-md)', border: '1px solid var(--color-border)' }}
    >
      <ReactFlow
        nodes={styledNodes}
        edges={styledEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        nodesDraggable
        nodesConnectable={false}
        elementsSelectable
        onNodeClick={(_event, node) => {
          setSelectedNodeId((prev) => (prev === node.id ? null : node.id));
        }}
        onPaneClick={() => setSelectedNodeId(null)}
        style={{ background: 'var(--color-base)' }}
      >
        <Background color="var(--grid-color, rgba(255,255,255,0.04))" gap={24} />
        <Controls />
        <MiniMap
          style={{ background: 'var(--color-surface)' }}
          nodeColor={(n) => {
            if (n.id === "root") return "var(--color-accent)";
            if (n.type === "scopeNode") return "var(--color-peach)";
            if (n.type === "sectionNode") return "var(--color-lavender)";
            return "var(--color-low)";
          }}
        />
      </ReactFlow>

      {selectedNodeData && <InfoPanel nodeData={selectedNodeData} />}
    </div>
  );
}
