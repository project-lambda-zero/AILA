import Editor, { loader, type OnMount } from "@monaco-editor/react";
import { useQuery } from "@tanstack/react-query";
import * as monaco from "monaco-editor";
import { useEffect, useMemo, useRef, useState, type JSX } from "react";

import { apiFetch } from "../../api/client";
import { apiErrDetail, asRecord, readBool, readNum, readRecordArray, readStr } from "../../api/parse";
import { css } from "../css";
import type { SastDiagnostic, SastDiagnosticLocation } from "./SastAuditResults";

loader.config({ monaco });

const border = "1px solid var(--border-soft)";
const muted = css("color:var(--text-muted);font-size:11px;");
const button = css("border:1px solid var(--border-soft);background:var(--bg-surface);color:var(--text-primary);padding:5px 9px;cursor:pointer;font:inherit;font-size:11px;");
const fileButton = css("display:block;width:100%;border:0;background:transparent;color:var(--text-primary);padding:3px 5px;text-align:left;cursor:pointer;font:inherit;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;");
const markerOwner = "aila-sast-workbench";

interface SourceFileEntry {
  path: string;
  language: string;
  diagnosticCount: number;
}

interface SourceTree {
  files: SourceFileEntry[];
  complete: boolean;
}

interface SourceFile {
  path: string;
  content: string;
  language: string;
  totalLines: number;
  truncated: boolean;
}

interface TreeNode {
  name: string;
  path: string;
  children: Map<string, TreeNode>;
  file?: SourceFileEntry;
}

function parseTree(value: unknown): SourceTree {
  const row = asRecord(value);
  if (!row) return { files: [], complete: false };
  return {
    files: readRecordArray(row, "files").flatMap((entry) => {
      const path = readStr(entry, "path");
      if (!path) return [];
      return [{ path, language: readStr(entry, "language") ?? "plaintext", diagnosticCount: readNum(entry, "diagnostic_count") ?? 0 }];
    }),
    complete: readBool(row, "complete") ?? false,
  };
}

function parseSource(value: unknown): SourceFile | null {
  const row = asRecord(value);
  const path = row ? readStr(row, "path") : null;
  const content = row ? readStr(row, "content") : null;
  if (!row || !path || content === null) return null;
  return {
    path,
    content,
    language: readStr(row, "language") ?? "plaintext",
    totalLines: readNum(row, "total_lines") ?? content.split("\n").length,
    truncated: readBool(row, "truncated") ?? false,
  };
}

function buildTree(files: SourceFileEntry[]): TreeNode {
  const root: TreeNode = { name: "", path: "", children: new Map() };
  for (const file of files) {
    let parent = root;
    const parts = file.path.split("/");
    parts.forEach((part, index) => {
      const path = parts.slice(0, index + 1).join("/");
      let node = parent.children.get(part);
      if (!node) {
        node = { name: part, path, children: new Map() };
        parent.children.set(part, node);
      }
      if (index === parts.length - 1) node.file = file;
      parent = node;
    });
  }
  return root;
}

function nodeDiagnosticCount(node: TreeNode, diagnostics: SastDiagnostic[]): number {
  if (node.file) return diagnostics.filter((diagnostic) => diagnostic.path === node.file?.path).length;
  return [...node.children.values()].reduce((total, child) => total + nodeDiagnosticCount(child, diagnostics), 0);
}

function TreeNodes({ node, depth, diagnostics, expanded, onToggle, onOpen, selectedPath }: {
  node: TreeNode;
  depth: number;
  diagnostics: SastDiagnostic[];
  expanded: Set<string>;
  onToggle: (path: string) => void;
  onOpen: (path: string) => void;
  selectedPath: string | null;
}): JSX.Element {
  const nodes = [...node.children.values()].sort((left, right) => Number(Boolean(right.children.size)) - Number(Boolean(left.children.size)) || left.name.localeCompare(right.name));
  return <>{nodes.map((child) => {
    const count = nodeDiagnosticCount(child, diagnostics);
    if (child.file) return <div key={child.path}>
      <button type="button" title={child.path} onClick={() => onOpen(child.path)} style={{ ...fileButton, paddingLeft: 5 + depth * 13, color: selectedPath === child.path ? "var(--accent)" : "var(--text-primary)", background: selectedPath === child.path ? "var(--bg-hover)" : "transparent" }}>
        <span style={{ color: "var(--text-faint)", marginRight: 5 }}>◇</span>{child.name}{count ? <span style={{ float: "right", color: "var(--status-err)" }}>{count}</span> : null}
      </button>
    </div>;
    const open = expanded.has(child.path);
    return <div key={child.path}>
      <button type="button" aria-expanded={open} onClick={() => onToggle(child.path)} style={{ ...fileButton, paddingLeft: 5 + depth * 13 }}>
        <span style={{ color: "var(--text-faint)", marginRight: 5 }}>{open ? "▾" : "▸"}</span>{child.name}{count ? <span style={{ float: "right", color: "var(--status-err)" }}>{count}</span> : null}
      </button>
      {open ? <TreeNodes node={child} depth={depth + 1} diagnostics={diagnostics} expanded={expanded} onToggle={onToggle} onOpen={onOpen} selectedPath={selectedPath} /> : null}
    </div>;
  })}</>;
}

function markerSeverity(monacoApi: typeof monaco, severity: string): monaco.MarkerSeverity {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
      return monacoApi.MarkerSeverity.Error;
    case "medium":
      return monacoApi.MarkerSeverity.Warning;
    case "low":
      return monacoApi.MarkerSeverity.Info;
    default:
      return monacoApi.MarkerSeverity.Hint;
  }
}

function locationRange(diagnostic: SastDiagnostic | SastDiagnosticLocation) {
  if (diagnostic.lineStart === null) return null;
  const startLine = Math.max(1, diagnostic.lineStart);
  const endLine = Math.max(startLine, diagnostic.lineEnd ?? startLine);
  return {
    startLine,
    endLine,
    startColumn: Math.max(1, diagnostic.columnStart ?? 1),
    endColumn: Math.max(1, diagnostic.columnEnd ?? diagnostic.columnStart ?? 1),
  };
}

export default function SastCodeWorkbench({ targetId, auditId, diagnostics, onClose }: {
  targetId: string;
  auditId: string;
  diagnostics: SastDiagnostic[];
  onClose: () => void;
}): JSX.Element {
  const [selectedPath, setSelectedPath] = useState<string | null>(() => diagnostics.find((diagnostic) => diagnostic.path)?.path ?? null);
  const [selectedDiagnosticId, setSelectedDiagnosticId] = useState<string | null>(null);
  const [pendingLocation, setPendingLocation] = useState<{ id: string; path: string; location: SastDiagnostic | SastDiagnosticLocation } | null>(null);
  const [filter, setFilter] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const editorRef = useRef<Parameters<OnMount>[0] | null>(null);
  const monacoRef = useRef<typeof monaco | null>(null);
  const [editorReady, setEditorReady] = useState(0);

  const filesQ = useQuery({
    queryKey: ["sast-workbench", "files", auditId],
    queryFn: async () => parseTree(await apiFetch<unknown>(`/vr/targets/${encodeURIComponent(targetId)}/sast-audit-files?audit_id=${encodeURIComponent(auditId)}`)),
  });
  const sourceQ = useQuery({
    queryKey: ["sast-workbench", "source", auditId, selectedPath],
    queryFn: async () => parseSource(await apiFetch<unknown>(`/vr/targets/${encodeURIComponent(targetId)}/sast-audit-source?audit_id=${encodeURIComponent(auditId)}&path=${encodeURIComponent(selectedPath ?? "")}`)),
    enabled: selectedPath !== null,
  });

  const counts = useMemo(() => {
    const result = new Map<string, number>();
    for (const diagnostic of diagnostics) if (diagnostic.path) result.set(diagnostic.path, (result.get(diagnostic.path) ?? 0) + 1);
    return result;
  }, [diagnostics]);
  const files = useMemo(() => {
    const merged = new Map<string, SourceFileEntry>();
    for (const file of filesQ.data?.files ?? []) merged.set(file.path, { ...file, diagnosticCount: counts.get(file.path) ?? file.diagnosticCount });
    for (const [path, diagnosticCount] of counts) if (!merged.has(path)) merged.set(path, { path, language: "plaintext", diagnosticCount });
    return [...merged.values()].filter((file) => file.path.toLowerCase().includes(filter.trim().toLowerCase())).sort((left, right) => left.path.localeCompare(right.path));
  }, [counts, filesQ.data, filter]);
  const tree = useMemo(() => buildTree(files), [files]);
  const selectedDiagnostic = diagnostics.find((diagnostic) => diagnostic.id === selectedDiagnosticId) ?? null;
  const currentSource = sourceQ.data?.path === selectedPath ? sourceQ.data : null;
  const displayedLineCount = currentSource?.content
    ? currentSource.content.split("\n").length - (currentSource.content.endsWith("\n") ? 1 : 0)
    : 0;
  const modelPath = selectedPath ? `inmemory://sast-workbench/${auditId}/${selectedPath}` : `inmemory://sast-workbench/${auditId}/empty`;

  useEffect(() => {
    if (selectedPath === null && files.length) setSelectedPath(files[0].path);
  }, [files, selectedPath]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    const editor = editorRef.current;
    const monacoApi = monacoRef.current;
    const model = editor?.getModel();
    if (!editor || !monacoApi || !model || !selectedPath || !currentSource) return;
    const markers = diagnostics.filter((diagnostic) => diagnostic.path === selectedPath).flatMap((diagnostic) => {
      const range = locationRange(diagnostic);
      if (!range || range.startLine > model.getLineCount()) return [];
      const endLine = Math.min(range.endLine, model.getLineCount());
      const startColumn = Math.min(range.startColumn, model.getLineMaxColumn(range.startLine));
      const requestedEndColumn = diagnostic.columnEnd === null && diagnostic.lineStart === endLine
        ? model.getLineMaxColumn(endLine)
        : range.endColumn;
      const endColumn = Math.min(requestedEndColumn, model.getLineMaxColumn(endLine));
      return [{
        severity: markerSeverity(monacoApi, diagnostic.severity),
        message: `${diagnostic.message} [${diagnostic.skillId}]`,
        startLineNumber: range.startLine,
        startColumn,
        endLineNumber: endLine,
        endColumn,
        code: diagnostic.skillId,
        source: "AILA SAST",
      }];
    });
    monacoApi.editor.setModelMarkers(model, markerOwner, markers);
    if (pendingLocation?.path === selectedPath) {
      const range = locationRange(pendingLocation.location);
      if (range) {
        const selection = { startLineNumber: range.startLine, startColumn: range.startColumn, endLineNumber: range.endLine, endColumn: range.endColumn };
        editor.revealRangeInCenter(selection);
        editor.setSelection(selection);
        editor.focus();
      }
      setPendingLocation(null);
    }
    return () => { monacoApi.editor.setModelMarkers(model, markerOwner, []); };
  }, [currentSource, diagnostics, editorReady, pendingLocation, selectedPath]);

  useEffect(() => () => {
    const monacoApi = monacoRef.current;
    if (!monacoApi) return;
    for (const model of monacoApi.editor.getModels()) {
      if (model.uri.toString().includes(`sast-workbench/${auditId}/`)) {
        monacoApi.editor.setModelMarkers(model, markerOwner, []);
        model.dispose();
      }
    }
  }, [auditId]);

  const openLocation = (diagnostic: SastDiagnostic, location: SastDiagnostic | SastDiagnosticLocation = diagnostic) => {
    setSelectedDiagnosticId(diagnostic.id);
    const path = location.path;
    if (!path || location.lineStart === null) return;
    setSelectedPath(path);
    setPendingLocation({ id: `${diagnostic.id}:${path}:${location.lineStart}`, path, location });
  };
  const cycleProblem = (direction: number) => {
    if (!diagnostics.length) return;
    const current = diagnostics.findIndex((diagnostic) => diagnostic.id === selectedDiagnosticId);
    const next = diagnostics[(current + direction + diagnostics.length) % diagnostics.length];
    openLocation(next);
  };
  const onMount: OnMount = (editor, monacoApi) => {
    editorRef.current = editor;
    monacoRef.current = monacoApi;
    setEditorReady((value) => value + 1);
  };

  return <div role="dialog" aria-modal="true" aria-label="SAST code workbench" style={css("position:fixed;inset:12px;z-index:1000;display:flex;flex-direction:column;background:var(--bg-app);border:1px solid var(--border-strong);box-shadow:0 16px 60px #000a;color:var(--text-primary);min-width:0;")}>
    <header style={css("display:flex;align-items:center;gap:8px;padding:8px 10px;border-bottom:1px solid var(--border-strong);flex-wrap:wrap;")}>
      <strong style={{ fontSize: 12 }}>SAST CODE WORKBENCH</strong>
      <span style={muted}>{diagnostics.length} problems · {files.length} files</span>
      <div style={{ flex: 1 }} />
      <button type="button" style={button} onClick={() => cycleProblem(-1)} disabled={!diagnostics.length}>Previous problem</button>
      <button type="button" style={button} onClick={() => cycleProblem(1)} disabled={!diagnostics.length}>Next problem</button>
      <button type="button" style={button} onClick={onClose}>Close</button>
    </header>
    <div style={css("display:grid;grid-template-columns:240px minmax(0,1fr);flex:1;min-height:0;")}>
      <aside style={css("display:flex;flex-direction:column;min-height:0;border-right:1px solid var(--border-strong);")}>
        <div style={{ padding: 8, borderBottom: border }}>
          <div style={{ ...muted, marginBottom: 6 }}>EXPLORER</div>
          <input aria-label="Filter repository files" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter files" style={css("width:100%;box-sizing:border-box;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border-soft);padding:5px;font:inherit;font-size:11px;")} />
          {filesQ.data && !filesQ.data.complete ? <div style={{ ...muted, marginTop: 6 }}>Evidence files only; full repository tree is unavailable on the API host.</div> : null}
        </div>
        <div style={css("overflow:auto;flex:1;padding:4px;")}>
          {filesQ.isPending ? <p style={muted}>Loading repository...</p> : null}
          {filesQ.isError ? <p style={muted}>{apiErrDetail(filesQ.error)}</p> : null}
          <TreeNodes node={tree} depth={0} diagnostics={diagnostics} expanded={expanded} selectedPath={selectedPath} onOpen={(path) => { setSelectedPath(path); setSelectedDiagnosticId(null); }} onToggle={(path) => setExpanded((current) => { const next = new Set(current); if (next.has(path)) next.delete(path); else next.add(path); return next; })} />
          {!filesQ.isPending && !files.length ? <p style={muted}>No source files match.</p> : null}
        </div>
      </aside>
      <main style={css("display:grid;grid-template-rows:minmax(0,1fr) 210px;min-width:0;min-height:0;")}>
        <section style={css("display:flex;flex-direction:column;min-height:0;min-width:0;")}>
          <div style={css("padding:6px 10px;border-bottom:1px solid var(--border-soft);font-family:var(--font-mono);font-size:11px;display:flex;gap:8px;align-items:center;")}>
            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{selectedPath?.split("/").join(" › ") ?? "Select a file"}</span>
            {currentSource?.truncated ? <span style={{ color: "var(--status-warn)" }}>Truncated · showing first {displayedLineCount}{currentSource.totalLines > displayedLineCount ? ` of ${currentSource.totalLines}` : ""} lines</span> : null}
          </div>
          <div style={{ flex: 1, minHeight: 0, position: "relative" }}>
            {sourceQ.isPending && selectedPath ? <div style={{ ...muted, position: "absolute", zIndex: 2, top: 8, left: 45 }}>Loading source...</div> : null}
            {sourceQ.isError ? <p style={{ ...muted, padding: 12 }}>{apiErrDetail(sourceQ.error)}</p> : null}
            <Editor
              path={modelPath}
              language={currentSource?.language ?? "plaintext"}
              value={currentSource?.content ?? ""}
              theme="vs-dark"
              onMount={onMount}
              options={{ readOnly: true, domReadOnly: true, renderValidationDecorations: "on", minimap: { enabled: true }, fontSize: 12, fontFamily: "'Spline Sans Mono', ui-monospace, monospace", lineNumbers: "on", scrollBeyondLastLine: false, renderLineHighlight: "all", folding: true, wordWrap: "off", automaticLayout: true, overviewRulerLanes: 3, scrollbar: { vertical: "auto", horizontal: "auto" } }}
            />
          </div>
        </section>
        <section style={css("display:grid;grid-template-columns:minmax(0,1.4fr) minmax(260px,1fr);border-top:1px solid var(--border-strong);min-height:0;")}>
          <div style={css("overflow:auto;border-right:1px solid var(--border-soft);")}>
            <div style={{ ...muted, padding: "7px 9px", position: "sticky", top: 0, background: "var(--bg-surface)" }}>PROBLEMS ({diagnostics.length})</div>
            {diagnostics.map((diagnostic) => <button key={diagnostic.id} type="button" onClick={() => openLocation(diagnostic)} style={{ ...fileButton, padding: "6px 9px", borderTop: border, background: selectedDiagnosticId === diagnostic.id ? "var(--bg-hover)" : "transparent", whiteSpace: "normal" }}>
              <span style={{ color: ["critical", "high"].includes(diagnostic.severity.toLowerCase()) ? "var(--status-err)" : "var(--status-warn)", marginRight: 7 }}>●</span>
              {diagnostic.message}
              <span style={{ display: "block", color: "var(--text-muted)", marginLeft: 16, marginTop: 3 }}>{diagnostic.path ?? "No source location"}{diagnostic.lineStart !== null ? `:${diagnostic.lineStart}` : ""} · {diagnostic.skillId} · {diagnostic.severity}</span>
            </button>)}
            {!diagnostics.length ? <p style={{ ...muted, padding: 9 }}>No diagnostics have been emitted by the detector outcomes.</p> : null}
          </div>
          <div style={css("overflow:auto;padding:10px;font-size:11px;")}>
            {selectedDiagnostic ? <>
              <strong>{selectedDiagnostic.message}</strong>
              <div style={{ ...muted, margin: "6px 0" }}>{selectedDiagnostic.severity} · {selectedDiagnostic.confidence ?? "unrated confidence"} · {selectedDiagnostic.skillId}</div>
              <p style={{ whiteSpace: "pre-wrap", lineHeight: 1.5 }}>{selectedDiagnostic.description || "No additional explanation was persisted."}</p>
              <div style={muted}>Investigation {selectedDiagnostic.investigationId}<br />Outcome {selectedDiagnostic.outcomeId}</div>
              {selectedDiagnostic.relatedLocations.length ? <div style={{ marginTop: 10 }}><div style={{ ...muted, marginBottom: 5 }}>RELATED LOCATIONS</div>{selectedDiagnostic.relatedLocations.map((location, index) => <button key={`${location.path}:${location.lineStart}:${index}`} type="button" style={{ ...fileButton, color: "var(--accent)", padding: "4px 0" }} onClick={() => openLocation(selectedDiagnostic, location)}>{location.path ?? "No source location"}{location.lineStart !== null ? `:${location.lineStart}` : ""}</button>)}</div> : null}
              {!selectedDiagnostic.path || selectedDiagnostic.lineStart === null ? <p style={{ color: "var(--status-warn)" }}>This finding has no verified source coordinate. No marker or navigation target was invented.</p> : null}
            </> : <p style={muted}>Select a problem to inspect its explanation, provenance, and related locations.</p>}
          </div>
        </section>
      </main>
    </div>
  </div>;
}
