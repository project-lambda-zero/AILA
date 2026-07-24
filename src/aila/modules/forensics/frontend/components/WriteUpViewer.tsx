import { useMemo, useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";

import { useProjectInvestigations, useProjectWriteups } from "../queries";
import {
  useDeleteWriteup,
  useDownloadWriteup,
  useDownloadWriteupsBundle,
} from "../mutations";
import type { InvestigationSummary, WriteUpItem } from "../types";

type ExpandState = Record<string, boolean>;

const truncate = (s: string, max: number): string =>
  s.length <= max ? s : `${s.slice(0, max - 1)}…`;

const stamp = (iso: string | null): string => {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    })}`;
  } catch {
    return iso;
  }
};

const slug = (s: string, max = 48): string =>
  (s || "writeup")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, max) || "writeup";

export function WriteUpViewer({ projectId }: { projectId: string }) {
  const { data: writeups, isLoading } = useProjectWriteups(projectId);
  const { data: investigations } = useProjectInvestigations(projectId);
  const downloadOne = useDownloadWriteup(projectId);
  const downloadBundle = useDownloadWriteupsBundle(projectId);
  const deleteWriteup = useDeleteWriteup(projectId);

  const [expanded, setExpanded] = useState<ExpandState>({});
  const [filter, setFilter] = useState("");

  const invById = useMemo(() => {
    const m = new Map<string, InvestigationSummary>();
    for (const inv of investigations ?? []) m.set(inv.id, inv);
    return m;
  }, [investigations]);

  const items = useMemo(() => {
    const arr = writeups ?? [];
    if (!filter.trim()) return arr;
    const q = filter.trim().toLowerCase();
    return arr.filter((w) => {
      const inv = w.investigation_id ? invById.get(w.investigation_id) : null;
      return (
        w.title.toLowerCase().includes(q) ||
        (w.methodology || "").toLowerCase().includes(q) ||
        (w.content_markdown || "").toLowerCase().includes(q) ||
        (inv?.question || "").toLowerCase().includes(q)
      );
    });
  }, [writeups, filter, invById]);

  const allExpanded = items.length > 0 && items.every((w) => expanded[w.id]);
  const expandAll = () => {
    const next: ExpandState = {};
    for (const w of items) next[w.id] = true;
    setExpanded(next);
  };
  const collapseAll = () => setExpanded({});
  const toggle = (id: string) =>
    setExpanded((s) => ({ ...s, [id]: !s[id] }));

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  if (!writeups || writeups.length === 0) {
    return (
      <AilaCard  techBorder glow><p className="text-sm text-text-muted text-center py-8">
        No write-ups generated yet. Complete an investigation to generate a
        professional report.
      </p></AilaCard>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs text-text-muted">
            {items.length} of {writeups.length} write-up
            {writeups.length === 1 ? "" : "s"}
          </span>
          <input
            aria-label="Filter write-ups"
            type="search"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by title, question, methodology, content…"
            className="h-8 w-72 max-w-full rounded border border-border bg-background px-2 text-xs"
          />
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={allExpanded ? collapseAll : expandAll}
            disabled={items.length === 0}
          >
            {allExpanded ? "Collapse all" : "Expand all"}
          </Button>
          <Button
            size="sm"
            onClick={() => downloadBundle.mutate()}
            disabled={downloadBundle.isPending || writeups.length === 0}
          >
            {downloadBundle.isPending ? "Exporting…" : "Download all (.md)"}
          </Button>
        </div>
      </div>

      {items.length === 0 ? (
        <AilaCard  techBorder glow><p className="text-xs text-text-muted text-center py-6">
          No write-ups match the current filter.
        </p></AilaCard>
      ) : (
        <div className="space-y-3">
          {items.map((w) => {
            const inv = w.investigation_id
              ? invById.get(w.investigation_id)
              : null;
            const isOpen = !!expanded[w.id];
            return (
              <WriteUpCard
                key={w.id}
                writeup={w}
                investigation={inv}
                open={isOpen}
                onToggle={() => toggle(w.id)}
                onDownload={() =>
                  downloadOne.mutate({
                    writeupId: w.id,
                    titleSlug: slug(w.title),
                  })
                }
                downloading={downloadOne.isPending}
                onDelete={() => deleteWriteup.mutate(w.id)}
                deleting={
                  deleteWriteup.isPending && deleteWriteup.variables === w.id
                }
              />
            );
          })}
        </div>
      )}
    </div>
  );
}

function WriteUpCard({
  writeup,
  investigation,
  open,
  onToggle,
  onDownload,
  downloading,
  onDelete,
  deleting,
}: {
  writeup: WriteUpItem;
  investigation: InvestigationSummary | null | undefined;
  open: boolean;
  onToggle: () => void;
  onDownload: () => void;
  downloading: boolean;
  onDelete: () => void;
  deleting: boolean;
}) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  const preview = useMemo(() => {
    const stripped = (writeup.content_markdown || "")
      .replace(/^#{1,6}\s+/gm, "")
      .replace(/[*_`>]/g, "")
      .replace(/\n{2,}/g, " · ")
      .replace(/\s+/g, " ")
      .trim();
    return truncate(stripped, 220);
  }, [writeup.content_markdown]);

  return (
    <AilaCard  techBorder glow><div className="space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <button
            type="button"
            onClick={onToggle}
            className="group flex items-start gap-2 text-left w-full"
            aria-expanded={open}
          >
            <span
              className={`mt-1 text-text-muted transition-transform ${
                open ? "rotate-90" : ""
              }`}
              aria-hidden
            >
              ▶
            </span>
            <div className="flex-1 min-w-0">
              <h3 className="text-sm font-semibold text-foreground group-hover:underline decoration-dotted underline-offset-2">
                {writeup.title}
              </h3>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 mt-1">
                {investigation ? (
                  <span className="inline-flex items-center gap-1.5 text-2xs text-text-muted">
                    <AilaBadge severity="info" size="sm">
                      I
                    </AilaBadge>
                    <span className="truncate" title={investigation.question}>
                      {truncate(investigation.question, 90)}
                    </span>
                    <span className="font-mono opacity-70">
                      {investigation.id.slice(0, 8)}
                    </span>
                  </span>
                ) : writeup.investigation_id ? (
                  <span className="inline-flex items-center gap-1 text-2xs text-text-muted">
                    <AilaBadge severity="info" size="sm">
                      I
                    </AilaBadge>
                    <span className="font-mono">
                      {writeup.investigation_id.slice(0, 8)}
                    </span>
                    <span className="italic opacity-70">
                      (investigation not on record)
                    </span>
                  </span>
                ) : (
                  <span className="text-2xs text-text-muted italic">
                    Project-wide write-up (no single investigation)
                  </span>
                )}
                {writeup.created_at && (
                  <span className="text-2xs text-text-muted">
                    {stamp(writeup.created_at)}
                  </span>
                )}
                {writeup.artifacts_referenced.length > 0 && (
                  <span className="text-2xs text-text-muted">
                    {writeup.artifacts_referenced.length} artifact ref
                    {writeup.artifacts_referenced.length === 1 ? "" : "s"}
                  </span>
                )}
              </div>
              {!open && preview && (
                <p className="text-xs text-text-muted mt-1.5 line-clamp-2">
                  {preview}
                </p>
              )}
            </div>
          </button>
        </div>
        <div className="flex shrink-0 items-center gap-2 relative">
          <Button
            size="sm"
            variant="secondary"
            onClick={onDownload}
            disabled={downloading}
          >
            {downloading ? "…" : ".md"}
          </Button>
          {confirmDelete ? (
            <div className="flex items-center gap-1">
              <span className="text-2xs text-text-muted">Delete?</span>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => setConfirmDelete(false)}
                disabled={deleting}
              >
                No
              </Button>
              <Button
                size="sm"
                onClick={() => {
                  setConfirmDelete(false);
                  onDelete();
                }}
                disabled={deleting}
                className="bg-red-600 hover:bg-red-500 text-white"
              >
                {deleting ? "…" : "Yes"}
              </Button>
            </div>
          ) : (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setConfirmDelete(true)}
              disabled={deleting}
              title={`Delete "${writeup.title}"`}
              aria-label="Delete write-up"
            >
              {deleting ? "…" : "✕"}
            </Button>
          )}
        </div>
      </div>
    
      {open && (
        <div className="space-y-3 pl-5 border-l-2 border-border/60">
          {writeup.methodology && (
            <div className="rounded-md bg-surface-secondary px-3 py-2">
              <h4 className="text-2xs font-medium text-text-muted uppercase tracking-wide mb-1">
                Methodology
              </h4>
              <p className="text-xs text-foreground whitespace-pre-wrap">
                {writeup.methodology}
              </p>
            </div>
          )}
    
          <div
            className="prose prose-sm max-w-none text-sm text-foreground writeup-md [&_h1]:text-foreground [&_h2]:text-foreground [&_h3]:text-foreground [&_h4]:text-foreground [&_strong]:text-foreground [&_code]:text-foreground [&_a]:text-accent"
            dangerouslySetInnerHTML={{
              __html: renderMarkdown(writeup.content_markdown || ""),
            }}
          />
    
          {writeup.artifacts_referenced.length > 0 && (
            <div className="flex flex-wrap items-center gap-1 pt-2 border-t border-border/60">
              <span className="text-2xs text-text-muted mr-1">
                Referenced artifacts:
              </span>
              {writeup.artifacts_referenced.map((id) => (
                <span
                  key={id}
                  className="px-1.5 py-0.5 text-2xs bg-surface-secondary rounded font-mono text-text-muted"
                  title={id}
                >
                  {id.slice(0, 8)}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div></AilaCard>
  );
}

/**
 * Minimal safe markdown → HTML. Renders headings, emphasis, inline code,
 * code blocks, unordered / ordered lists, and paragraphs. Everything is
 * HTML-escaped before any replacement, so the output is safe from any
 * user-controlled strings in the source markdown.
 */
function renderMarkdown(md: string): string {
  const escaped = md
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Extract fenced code blocks first so their content is not touched by
  // downstream replacers. We replace each block with a placeholder and
  // re-insert it at the end.
  const codeBlocks: string[] = [];
  const withFences = escaped.replace(
    /^```([a-zA-Z0-9_+-]*)\n([\s\S]*?)\n```$/gm,
    (_, _lang, body) => {
      const idx = codeBlocks.length;
      codeBlocks.push(
        `<pre class="px-3 py-2 bg-surface-secondary rounded-md overflow-x-auto text-xs font-mono my-2"><code>${body}</code></pre>`,
      );
      return `\u0000CODEBLOCK_${idx}\u0000`;
    },
  );

  // Split into blocks on blank lines so lists + paragraphs can be grouped.
  const blocks = withFences.split(/\n{2,}/);
  const rendered: string[] = [];

  for (const rawBlock of blocks) {
    const block = rawBlock.replace(/\n+$/, "");
    if (!block.trim()) continue;

    // Heading -- first line is # ... ###### ... with the rest ignored as a block header.
    const heading = block.match(/^(#{1,6})\s+(.+)$/);
    if (heading && !block.includes("\n")) {
      const level = heading[1].length;
      const size =
        level === 1
          ? "text-xl font-bold mt-5 mb-2"
          : level === 2
            ? "text-lg font-semibold mt-4 mb-2"
            : "text-base font-semibold mt-3 mb-1";
      rendered.push(`<h${level} class="${size}">${inline(heading[2])}</h${level}>`);
      continue;
    }

    // Unordered list -- all lines start with - or *
    const ulLines = block.split("\n");
    if (ulLines.every((l) => /^[-*]\s+/.test(l))) {
      const items = ulLines
        .map((l) => `<li>${inline(l.replace(/^[-*]\s+/, ""))}</li>`)
        .join("");
      rendered.push(
        `<ul class="list-disc ml-5 space-y-0.5 my-2">${items}</ul>`,
      );
      continue;
    }

    // Ordered list
    if (ulLines.every((l) => /^\d+\.\s+/.test(l))) {
      const items = ulLines
        .map((l) => `<li>${inline(l.replace(/^\d+\.\s+/, ""))}</li>`)
        .join("");
      rendered.push(
        `<ol class="list-decimal ml-5 space-y-0.5 my-2">${items}</ol>`,
      );
      continue;
    }

    // Blockquote
    if (ulLines.every((l) => /^&gt;\s?/.test(l))) {
      const inner = ulLines
        .map((l) => inline(l.replace(/^&gt;\s?/, "")))
        .join("<br />");
      rendered.push(
        `<blockquote class="border-l-4 border-border pl-3 text-text-muted italic my-2">${inner}</blockquote>`,
      );
      continue;
    }

    // Horizontal rule
    if (/^---+$/.test(block.trim())) {
      rendered.push(`<hr class="my-3 border-border" />`);
      continue;
    }

    // Paragraph -- keep internal single newlines as <br />
    const paragraph = block.split("\n").map(inline).join("<br />");
    rendered.push(`<p class="my-1.5 leading-relaxed">${paragraph}</p>`);
  }

  let html = rendered.join("\n");
  html = html.replace(/\u0000CODEBLOCK_(\d+)\u0000/g, (_, n) => codeBlocks[+n] ?? "");
  return html;
}

/**
 * Neutralize a markdown link target before it reaches an href (43-5).
 *
 * The surrounding markdown is HTML-escaped for &, <, and > only, so a raw URL
 * can still (a) carry a javascript:/data:/vbscript: scheme that executes on
 * click, or (b) contain a quote that breaks out of the href attribute. Collapse
 * whitespace and control characters (browsers strip these before resolving a
 * scheme) to detect the real scheme, reject anything outside http/https/mailto
 * (relative and anchor links have no scheme and pass), then escape quotes.
 */
function safeHref(raw: string): string {
  const collapsed = raw.replace(/[\u0000-\u0020]+/g, "").toLowerCase();
  const scheme = collapsed.match(/^([a-z][a-z0-9+.-]*):/);
  if (scheme && !["http", "https", "mailto"].includes(scheme[1])) {
    return "about:blank";
  }
  return raw.trim().replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function inline(text: string): string {
  return text
    .replace(
      /`([^`]+)`/g,
      '<code class="px-1 py-0.5 bg-surface-secondary rounded text-2xs font-mono">$1</code>',
    )
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.+?)\*/g, "<em>$1</em>")
    .replace(
      /\[([^\]]+)\]\(([^)]+)\)/g,
      (_m, label, url) =>
        `<a href="${safeHref(url)}" class="underline decoration-dotted" target="_blank" rel="noopener noreferrer">${label}</a>`,
    );
}
