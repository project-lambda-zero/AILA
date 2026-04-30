/**
 * BlueprintCanvas.tsx — Interactive ReactFlow graph editor for the NFR schema.
 *
 * Every question is a draggable node with source/target connection handles.
 * Dependencies ("ropes") are animated edges connecting source → target.
 * Dragging from one handle to another persists a new `depends_on_question_id`.
 * Clicking a question node opens the question editor drawer.
 */
import { createContext, useCallback, useContext, useEffect, useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Panel,
  Handle,
  Position,
  BackgroundVariant,
  MarkerType,
  useNodesState,
  useEdgesState,
  addEdge,
  type Node,
  type Edge,
  type NodeTypes,
  type NodeProps,
  type Connection,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { AilaBadge } from "@/components/aila/AilaBadge";

import type { EditorSectionTree } from "./treeModel";
import { usePatchQuestion } from "./api";

// ---------------------------------------------------------------------------
// Context for node click handler (ReactFlow v12 onNodeClick is unreliable)
// ---------------------------------------------------------------------------

interface BlueprintCtx {
  onEditQuestion: (questionId: string, subgroupId: string) => void;
}

const BlueprintContext = createContext<BlueprintCtx>({ onEditQuestion: () => {} });

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

const COL_W = 340;
const COLS = 2;
const SECTION_HEADER_H = 56;
const SUBGROUP_HEADER_H = 38;
const QUESTION_NODE_H = 82;
const Y_GAP = 16;
const SECTION_Y_GAP = 52;
const X_PAD = 48;

// ---------------------------------------------------------------------------
// Custom node renderers
// ---------------------------------------------------------------------------

function SectionHeaderNode({ data }: NodeProps) {
  const d = data as Record<string, unknown>;
  const label = (d.label as string) ?? "";
  const sectionKey = (d.sectionKey as string) ?? "";
  const questionCount = (d.questionCount as number) ?? 0;
  const logicCount = (d.logicCount as number) ?? 0;

  return (
    <div
      className="flex items-center gap-3 rounded-[6px] border border-accent/25 px-5 py-3"
      style={{
        minWidth: COL_W * COLS + X_PAD,
        background: "linear-gradient(90deg, var(--color-accent-muted), transparent 55%)",
      }}
    >
      <div
        className="h-3.5 w-3.5 rounded-full"
        style={{ background: "var(--color-accent)" }}
      />
      <span className="font-mono text-base font-bold text-text">{label}</span>
      <span className="ml-auto font-mono text-[10px] uppercase tracking-[0.2em] text-text-muted">
        {sectionKey}
      </span>
      <AilaBadge severity="info" size="sm">
        {questionCount}q
      </AilaBadge>
      {logicCount > 0 && (
        <AilaBadge severity="medium" size="sm">
          {logicCount} dep
        </AilaBadge>
      )}
    </div>
  );
}

function SubgroupLabelNode({ data }: NodeProps) {
  const d = data as Record<string, unknown>;
  const label = (d.label as string) ?? "";
  const subgroupKey = (d.subgroupKey as string) ?? "";

  return (
    <div
      className="flex items-center gap-2 rounded-[4px] border border-border bg-surface px-3 py-1.5"
      style={{ minWidth: COL_W * COLS + X_PAD - 20 }}
    >
      <span
        className="h-2 w-2 rounded-full"
        style={{ background: "var(--color-accent)" }}
      />
      <span className="font-mono text-xs font-medium text-text">{label}</span>
      <span className="ml-auto font-mono text-[9px] text-text-muted">{subgroupKey}</span>
    </div>
  );
}

function answerTypeSeverity(t: string): "info" | "medium" | "low" | "neutral" {
  if (t === "binary") return "info";
  if (t === "maturity_tier") return "medium";
  if (t === "single_choice") return "low";
  return "neutral";
}

function QuestionNodeRenderer({ data }: NodeProps) {
  const { onEditQuestion } = useContext(BlueprintContext);
  const d = data as Record<string, unknown>;
  const label = (d.label as string) ?? "";
  const answerType = (d.answerType as string) ?? "text";
  const questionType = (d.questionType as string) ?? "";
  const hasLogic = (d.hasLogic as boolean) ?? false;
  const mappingCount = (d.mappingCount as number) ?? 0;
  const questionId = (d.questionId as string) ?? "";
  const subgroupId = (d.subgroupId as string) ?? "";

  return (
    <div
      onClick={() => {
        if (questionId && subgroupId) onEditQuestion(questionId, subgroupId);
      }}
      className="group relative cursor-pointer rounded-[4px] border border-border bg-elevated px-3.5 py-3 transition-colors duration-150 hover:border-border-hover"
      style={{ width: COL_W - 24 }}
    >
      <Handle
        type="target"
        position={Position.Left}
        style={{
          left: -8,
          width: 16,
          height: 16,
          borderRadius: 9999,
          border: "2px solid var(--color-accent)",
          background: "var(--color-base)",
        }}
      />
      <Handle
        type="source"
        position={Position.Right}
        style={{
          right: -8,
          width: 16,
          height: 16,
          borderRadius: 9999,
          border: "2px solid var(--color-accent)",
          background: "var(--color-base)",
        }}
      />
      <p
        className="truncate font-mono text-xs font-medium leading-snug text-text"
        title={label}
      >
        {label}
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <AilaBadge severity={answerTypeSeverity(answerType)} size="sm">
          {answerType}
        </AilaBadge>
        {hasLogic && (
          <AilaBadge severity="medium" size="sm">
            ⚡ dep
          </AilaBadge>
        )}
        {mappingCount > 0 && (
          <AilaBadge severity="info" size="sm">
            {mappingCount} map
          </AilaBadge>
        )}
        <span className="font-mono text-[9px] text-text-muted">{questionType}</span>
      </div>
    </div>
  );
}

const NODE_TYPES: NodeTypes = {
  sectionHeader: SectionHeaderNode,
  subgroupLabel: SubgroupLabelNode,
  question: QuestionNodeRenderer,
};

// ---------------------------------------------------------------------------
// Graph layout builder
// ---------------------------------------------------------------------------

function buildBlueprintGraph(sections: EditorSectionTree[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  let cursorY = 0;

  for (const section of sections) {
    const questionCount = section.subgroups.reduce((t, sg) => t + sg.questions.length, 0);
    const logicCount = section.subgroups.reduce(
      (t, sg) =>
        t + sg.questions.filter((q) => q.depends_on_question_id || q.condition_expr_json).length,
      0,
    );

    // --- Section header ---
    nodes.push({
      id: `sec:${section.id}`,
      type: "sectionHeader",
      position: { x: 0, y: cursorY },
      data: {
        label: section.label,
        sectionKey: section.section_key,
        questionCount,
        logicCount,
      },
      draggable: true,
      selectable: false,
      connectable: false,
    });
    cursorY += SECTION_HEADER_H + Y_GAP;

    for (const subgroup of section.subgroups) {
      // --- Subgroup label ---
      nodes.push({
        id: `sg:${subgroup.id}`,
        type: "subgroupLabel",
        position: { x: X_PAD / 2, y: cursorY },
        data: { label: subgroup.label, subgroupKey: subgroup.subgroup_key },
        draggable: true,
        selectable: false,
        connectable: false,
      });
      cursorY += SUBGROUP_HEADER_H + Y_GAP;

      // --- Questions in 2-column grid ---
      const sorted = [...subgroup.questions].sort((a, b) => a.display_order - b.display_order);
      sorted.forEach((q, idx) => {
        const col = idx % COLS;
        const row = Math.floor(idx / COLS);
        const x = X_PAD + col * COL_W;
        const y = cursorY + row * (QUESTION_NODE_H + Y_GAP);

        const hasLogicFlag = Boolean(q.depends_on_question_id || q.condition_expr_json);

        nodes.push({
          id: `q:${q.id}`,
          type: "question",
          position: { x, y },
          data: {
            label: q.label,
            answerType: q.answer_type,
            questionType: q.question_type,
            hasLogic: hasLogicFlag,
            mappingCount: q.subtask_mappings.length,
            questionId: q.id,
            subgroupId: subgroup.id,
          },
        });

        // Dependency edge (question → question)
        if (q.depends_on_question_id) {
          edges.push({
            id: `dep:${q.id}`,
            source: `q:${q.depends_on_question_id}`,
            target: `q:${q.id}`,
            type: "smoothstep",
            animated: true,
            style: { stroke: "var(--color-accent)", strokeWidth: 2 },
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: "var(--color-accent)",
              width: 16,
              height: 16,
            },
            label: q.expected_when ? `when: ${q.expected_when}` : undefined,
            labelStyle: { fill: "var(--color-accent)", fontSize: 10, fontFamily: "monospace" },
            labelBgStyle: { fill: "var(--color-base)", fillOpacity: 0.92 },
            labelBgPadding: [6, 3] as [number, number],
          });
        }
      });

      const questionRows = Math.ceil(sorted.length / COLS);
      cursorY += questionRows * (QUESTION_NODE_H + Y_GAP) + Y_GAP;
    }

    // Section-level dependency edge (question → section header)
    if (section.depends_on_question_id) {
      edges.push({
        id: `sec-dep:${section.id}`,
        source: `q:${section.depends_on_question_id}`,
        target: `sec:${section.id}`,
        type: "smoothstep",
        animated: true,
        style: { stroke: "var(--color-lavender)", strokeWidth: 2 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: "var(--color-lavender)",
          width: 16,
          height: 16,
        },
        label: section.expected_when
          ? `section when: ${section.expected_when}`
          : "triggers section",
        labelStyle: { fill: "var(--color-lavender)", fontSize: 10, fontFamily: "monospace" },
        labelBgStyle: { fill: "var(--color-base)", fillOpacity: 0.92 },
        labelBgPadding: [6, 3] as [number, number],
      });
    }

    cursorY += SECTION_Y_GAP;
  }

  return { nodes, edges };
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export interface BlueprintCanvasProps {
  sections: EditorSectionTree[];
  onEditQuestion: (questionId: string, subgroupId: string) => void;
  onAddQuestion: (subgroupId: string) => void;
}

export function BlueprintCanvas({ sections, onEditQuestion }: BlueprintCanvasProps) {
  const patchQuestion = usePatchQuestion();
  const ctxValue = useMemo<BlueprintCtx>(() => ({ onEditQuestion }), [onEditQuestion]);

  const { nodes: initialNodes, edges: initialEdges } = useMemo(
    () => buildBlueprintGraph(sections),
    [sections],
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync when schema data reloads
  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  // --- Connect handler: drag a rope from source → target ---
  const onConnect = useCallback(
    (connection: Connection) => {
      if (!connection.source || !connection.target) return;
      // Only connect question → question
      if (!connection.source.startsWith("q:") || !connection.target.startsWith("q:")) return;

      const sourceQId = connection.source.slice(2);
      const targetQId = connection.target.slice(2);
      if (sourceQId === targetQId) return;

      // Persist the dependency
      patchQuestion.mutate({
        id: targetQId,
        patch: { depends_on_question_id: sourceQId },
      });

      // Add edge visually
      setEdges((prev) =>
        addEdge(
          {
            ...connection,
            id: `dep:${targetQId}`,
            type: "smoothstep",
            animated: true,
            style: { stroke: "var(--color-accent)", strokeWidth: 2 },
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: "var(--color-accent)",
              width: 16,
              height: 16,
            },
          },
          prev,
        ),
      );
    },
    [patchQuestion, setEdges],
  );

  // --- Delete handler: removing an edge clears the dependency ---
  const onDelete = useCallback(
    ({ edges: deletedEdges }: { nodes: Node[]; edges: Edge[] }) => {
      for (const edge of deletedEdges) {
        if (edge.target.startsWith("q:")) {
          const targetQId = edge.target.slice(2);
          patchQuestion.mutate({
            id: targetQId,
            patch: { depends_on_question_id: null },
          });
        }
      }
    },
    [patchQuestion],
  );

  // --- Click handler: open the question editor drawer ---
  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      if (node.type !== "question") return;
      const d = node.data as Record<string, unknown>;
      const questionId = d.questionId as string;
      const subgroupId = d.subgroupId as string;
      if (questionId && subgroupId) {
        onEditQuestion(questionId, subgroupId);
      }
    },
    [onEditQuestion],
  );

  return (
    <BlueprintContext.Provider value={ctxValue}>
      <div
        style={{
          height: 720,
          background: "var(--color-base)",
          borderRadius: "var(--radius-lg)",
          border: "1px solid var(--color-border)",
        }}
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onDelete={onDelete}
          onNodeClick={onNodeClick}
          nodeTypes={NODE_TYPES}
          fitView
          fitViewOptions={{ padding: 0.12 }}
          proOptions={{ hideAttribution: true }}
          defaultEdgeOptions={{
            type: "smoothstep",
            animated: true,
            style: { stroke: "var(--color-accent)", strokeWidth: 1.5 },
          }}
          connectionLineStyle={{
            stroke: "var(--color-accent)",
            strokeWidth: 2,
            strokeDasharray: "6 3",
          }}
          style={{ background: "var(--color-base)" }}
          minZoom={0.15}
          maxZoom={2.5}
          snapToGrid
          snapGrid={[16, 16]}
        >
          <Background
            variant={BackgroundVariant.Dots}
            gap={24}
            size={1}
            color="var(--grid-color)"
          />
          <Controls showInteractive />
          <MiniMap
            nodeColor={(node) => {
              if (node.type === "sectionHeader") return "var(--color-accent)";
              if (node.type === "subgroupLabel") return "var(--color-text-muted)";
              return "var(--color-accent)";
            }}
            maskColor="rgba(0,0,0,0.85)"
            style={{
              background: "var(--color-surface)",
              border: "1px solid var(--color-border)",
              borderRadius: "var(--radius-md)",
            }}
          />
          <Panel position="top-right">
            <div
              style={{
                maxWidth: 220,
                padding: "12px 16px",
                borderRadius: "var(--radius-lg)",
                border: "1px solid var(--color-border)",
                background: "var(--color-surface)",
              }}
            >
              <p
                style={{
                  fontFamily: "var(--font-mono, ui-monospace, monospace)",
                  fontSize: 10,
                  textTransform: "uppercase",
                  letterSpacing: "0.2em",
                  color: "var(--color-text-muted)",
                  marginBottom: 8,
                }}
              >
                Blueprint controls
              </p>
              <ul
                style={{
                  listStyle: "none",
                  padding: 0,
                  margin: 0,
                  display: "flex",
                  flexDirection: "column",
                  gap: 6,
                }}
              >
                <li style={{ fontSize: 12, lineHeight: 1.5, color: "var(--color-text)" }}>
                  Drag <strong style={{ color: "var(--color-accent)" }}>●</strong> handles to connect questions
                </li>
                <li style={{ fontSize: 12, lineHeight: 1.5, color: "var(--color-text)" }}>
                  Click a question to open the editor
                </li>
                <li style={{ fontSize: 12, lineHeight: 1.5, color: "var(--color-text)" }}>
                  Select an edge + press{" "}
                  <kbd
                    style={{
                      border: "1px solid var(--color-border)",
                      borderRadius: 3,
                      padding: "1px 4px",
                      fontSize: 10,
                      color: "var(--color-accent)",
                    }}
                  >
                    ⌫
                  </kbd>{" "}
                  to remove
                </li>
                <li style={{ fontSize: 12, lineHeight: 1.5, color: "var(--color-text)" }}>
                  Scroll to zoom, drag background to pan
                </li>
              </ul>
            </div>
          </Panel>
        </ReactFlow>
      </div>
    </BlueprintContext.Provider>
  );
}
