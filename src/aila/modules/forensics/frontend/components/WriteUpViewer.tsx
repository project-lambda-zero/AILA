import { useMemo, useState } from "react";
import { Link } from "react-router";

import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge } from "@/components/aila/mock";

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

const shortId = (id: string | null | undefined): string =>
  (id ?? "").slice(0, 8);

// --- shared inline styles for the raw mono buttons -------------------------

const BTN_PRIMARY: React.CSSProperties = {
  height: 26,
  padding: "0 11px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-on-accent)",
  background: "var(--accent)",
  border: "1px solid var(--accent)",
  borderRadius: 3,
  cursor: "pointer",
};

const BTN_MUTED: React.CSSProperties = {
  height: 26,
  padding: "0 11px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

const BTN_TITLEBAR: React.CSSProperties = {
  height: 20,
  padding: "0 8px",
  fontSize: 9,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 2,
  cursor: "pointer",
};

const BTN_TITLEBAR_DANGER: React.CSSProperties = {
  ...BTN_TITLEBAR,
  color: "var(--accent)",
  border: "1px solid color-mix(in srgb, var(--accent) 45%, transparent)",
};

// --- top-level viewer ------------------------------------------------------

export function WriteUpViewer({ projectId }: { projectId: string }) {
  const { data: writeups, isLoading } = useProjectWriteups(projectId);
  const { data: investigations } = useProjectInvestigations(projectId);
  const downloadOne = useDownloadWriteup(projectId);
  const downloadBundle = useDownloadWriteupsBundle(projectId);
  const deleteWriteup = useDeleteWriteup(projectId);

  const [expanded, setExpanded] = useState<ExpandState>({});

  const invById = useMemo(() => {
    const m = new Map<string, InvestigationSummary>();
    for (const inv of investigations ?? []) m.set(inv.id, inv);
    return m;
  }, [investigations]);

  const toggle = (id: string) =>
    setExpanded((s) => ({ ...s, [id]: !s[id] }));

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  if (!writeups || writeups.length === 0) {
    return (
      <WindowPanel title="write-ups" tone="muted" status="forensics ; no reports generated">
        <EmptyState
          title="No write-ups yet"
          description="Complete an investigation to generate a professional report."
        />
      </WindowPanel>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between" style={{ gap: 12 }}>
        <span
          className="font-mono uppercase"
          style={{
            fontSize: 12,
            letterSpacing: "0.14em",
            color: "var(--text-primary)",
          }}
        >
          WRITEUPS ({writeups.length})
        </span>
        <button
          type="button"
          className="font-mono uppercase"
          onClick={() => downloadBundle.mutate()}
          disabled={downloadBundle.isPending || writeups.length === 0}
          style={{
            ...BTN_PRIMARY,
            opacity: downloadBundle.isPending || writeups.length === 0 ? 0.55 : 1,
          }}
          aria-label="Download all write-ups as a bundle"
        >
          {downloadBundle.isPending ? "EXPORTING…" : "DOWNLOAD ALL (BUNDLE)"}
        </button>
      </div>

      <div className="space-y-2">
        {writeups.map((w) => {
          const inv = w.investigation_id ? invById.get(w.investigation_id) : null;
          const isOpen = !!expanded[w.id];
          return (
            <WriteUpCard
              key={w.id}
              projectId={projectId}
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
    </div>
  );
}

// --- per-writeup card ------------------------------------------------------

function WriteUpCard({
  projectId,
  writeup,
  investigation,
  open,
  onToggle,
  onDownload,
  downloading,
  onDelete,
  deleting,
}: {
  projectId: string;
  writeup: WriteUpItem;
  investigation: InvestigationSummary | null | undefined;
  open: boolean;
  onToggle: () => void;
  onDownload: () => void;
  downloading: boolean;
  onDelete: () => void;
  deleting: boolean;
}) {
  const preview = useMemo(() => {
    const stripped = (writeup.content_markdown || "")
      .replace(/^#{1,6}\s+/gm, "")
      .replace(/[*_`>]/g, "")
      .replace(/\n{2,}/g, " \u00b7 ")
      .replace(/\s+/g, " ")
      .trim();
    return truncate(stripped, 220);
  }, [writeup.content_markdown]);

  const invShort = shortId(writeup.investigation_id);
  const cardShort = shortId(writeup.id);
  const title = writeup.title || `writeup ${cardShort}`;
  const stampStr = stamp(writeup.created_at);
  const status = `${stampStr}${stampStr && writeup.investigation_id ? " ; " : ""}${writeup.investigation_id ? `investigation ${invShort}` : ""}`;

  const handleDelete = () => {
    if (deleting) return;
    if (window.confirm(`Delete write-up "${title}"?`)) {
      onDelete();
    }
  };

  return (
    <WindowPanel
      title={title}
      tone="info"
      status={status || undefined}
      actions={
        <div className="flex items-center" style={{ gap: 6 }}>
          <button
            type="button"
            className="font-mono uppercase"
            onClick={onDownload}
            disabled={downloading}
            style={{ ...BTN_TITLEBAR, opacity: downloading ? 0.55 : 1 }}
            title="Download markdown"
            aria-label="Download write-up as markdown"
          >
            {downloading ? "…" : "DOWNLOAD.MD"}
          </button>
          <button
            type="button"
            className="font-mono uppercase"
            onClick={handleDelete}
            disabled={deleting}
            style={{ ...BTN_TITLEBAR_DANGER, opacity: deleting ? 0.55 : 1 }}
            title={`Delete "${title}"`}
            aria-label="Delete write-up"
          >
            {deleting ? "…" : "DELETE"}
          </button>
        </div>
      }
    >
      <div className="space-y-2">
        <div className="flex items-start justify-between" style={{ gap: 10 }}>
          <div className="min-w-0 flex-1">
            {investigation && writeup.investigation_id ? (
              <div
                className="flex items-center flex-wrap"
                style={{ gap: 8, fontSize: 10 }}
              >
                <MonoBadge tone="info">INV</MonoBadge>
                <Link
                  to={`/forensics/projects/${projectId}/investigations/${writeup.investigation_id}`}
                  className="font-mono"
                  style={{
                    color: "var(--accent)",
                    textDecoration: "underline",
                    textUnderlineOffset: 2,
                    textDecorationStyle: "dotted",
                  }}
                  title={investigation.question}
                >
                  {truncate(investigation.question, 90)}
                </Link>
                <span
                  className="font-mono"
                  style={{ color: "var(--text-faint)" }}
                >
                  {invShort}
                </span>
              </div>
            ) : writeup.investigation_id ? (
              <div
                className="flex items-center flex-wrap"
                style={{ gap: 8, fontSize: 10 }}
              >
                <MonoBadge tone="info">INV</MonoBadge>
                <Link
                  to={`/forensics/projects/${projectId}/investigations/${writeup.investigation_id}`}
                  className="font-mono"
                  style={{
                    color: "var(--accent)",
                    textDecoration: "underline",
                    textUnderlineOffset: 2,
                    textDecorationStyle: "dotted",
                  }}
                >
                  {invShort}
                </Link>
                <span
                  className="font-mono"
                  style={{ color: "var(--text-faint)", fontStyle: "italic" }}
                >
                  (investigation not on record)
                </span>
              </div>
            ) : (
              <span
                className="font-mono"
                style={{ fontSize: 10, color: "var(--text-faint)", fontStyle: "italic" }}
              >
                project-wide write-up (no single investigation)
              </span>
            )}
            {writeup.artifacts_referenced.length > 0 && (
              <div
                className="font-mono"
                style={{ marginTop: 4, fontSize: 10, color: "var(--text-muted)" }}
              >
                {writeup.artifacts_referenced.length} artifact ref
                {writeup.artifacts_referenced.length === 1 ? "" : "s"}
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={open}
            className="font-mono uppercase inline-flex items-center shrink-0"
            style={{ ...BTN_TITLEBAR, gap: 6 }}
          >
            <PixelIcon name={open ? "down" : "arrow"} size={10} />
            {open ? "collapse" : "expand"}
          </button>
        </div>

        {open ? (
          <>
            {writeup.methodology && (
              <div
                style={{
                  padding: "8px 10px",
                  background: "var(--surface-sunk)",
                  border: "1px solid var(--border-faint)",
                  borderRadius: 3,
                }}
              >
                <div
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.12em",
                    color: "var(--text-faint)",
                    marginBottom: 3,
                  }}
                >
                  Methodology
                </div>
                <p
                  className="whitespace-pre-wrap"
                  style={{ fontSize: 12, color: "var(--text-primary)" }}
                >
                  {writeup.methodology}
                </p>
              </div>
            )}

            <div
              className="prose-mock font-mono"
              style={{
                fontSize: 12,
                lineHeight: 1.6,
                color: "var(--text-primary)",
              }}
              dangerouslySetInnerHTML={{
                __html: renderMarkdown(writeup.content_markdown || ""),
              }}
            />

            {writeup.artifacts_referenced.length > 0 && (
              <div
                className="flex items-center flex-wrap"
                style={{
                  gap: 6,
                  paddingTop: 8,
                  borderTop: "1px solid var(--border-faint)",
                }}
              >
                <span
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.12em",
                    color: "var(--text-faint)",
                  }}
                >
                  referenced artifacts:
                </span>
                {writeup.artifacts_referenced.map((id) => (
                  <span
                    key={id}
                    className="font-mono"
                    style={{
                      padding: "1px 6px",
                      fontSize: 10,
                      color: "var(--text-muted)",
                      background: "var(--surface-sunk)",
                      border: "1px solid var(--border-faint)",
                      borderRadius: 2,
                    }}
                    title={id}
                  >
                    {shortId(id)}
                  </span>
                ))}
              </div>
            )}
          </>
        ) : preview ? (
          <p
            className="font-mono line-clamp-2"
            style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.5 }}
          >
            {preview}
          </p>
        ) : null}
      </div>
    </WindowPanel>
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
        `<pre style="padding:8px 10px;background:var(--surface-sunk);border:1px solid var(--border-faint);border-radius:3px;overflow-x:auto;font-size:11px;font-family:var(--font-mono);margin:8px 0;"><code>${body}</code></pre>`,
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
          ? "font-size:18px;font-weight:600;margin:14px 0 6px;"
          : level === 2
            ? "font-size:15px;font-weight:600;margin:12px 0 5px;"
            : "font-size:13px;font-weight:600;margin:10px 0 4px;";
      rendered.push(
        `<h${level} style="${size}color:var(--text-primary);">${inline(heading[2])}</h${level}>`,
      );
      continue;
    }

    // Unordered list -- all lines start with - or *
    const ulLines = block.split("\n");
    if (ulLines.every((l) => /^[-*]\s+/.test(l))) {
      const items = ulLines
        .map((l) => `<li>${inline(l.replace(/^[-*]\s+/, ""))}</li>`)
        .join("");
      rendered.push(
        `<ul style="list-style:disc;margin:6px 0 6px 20px;">${items}</ul>`,
      );
      continue;
    }

    // Ordered list
    if (ulLines.every((l) => /^\d+\.\s+/.test(l))) {
      const items = ulLines
        .map((l) => `<li>${inline(l.replace(/^\d+\.\s+/, ""))}</li>`)
        .join("");
      rendered.push(
        `<ol style="list-style:decimal;margin:6px 0 6px 20px;">${items}</ol>`,
      );
      continue;
    }

    // Blockquote
    if (ulLines.every((l) => /^&gt;\s?/.test(l))) {
      const inner = ulLines
        .map((l) => inline(l.replace(/^&gt;\s?/, "")))
        .join("<br />");
      rendered.push(
        `<blockquote style="border-left:3px solid var(--border-soft);padding-left:10px;color:var(--text-muted);font-style:italic;margin:8px 0;">${inner}</blockquote>`,
      );
      continue;
    }

    // Horizontal rule
    if (/^---+$/.test(block.trim())) {
      rendered.push(
        `<hr style="margin:12px 0;border:0;border-top:1px solid var(--border-faint);" />`,
      );
      continue;
    }

    // Paragraph -- keep internal single newlines as <br />
    const paragraph = block.split("\n").map(inline).join("<br />");
    rendered.push(
      `<p style="margin:6px 0;line-height:1.6;">${paragraph}</p>`,
    );
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
      '<code style="padding:1px 5px;background:var(--surface-sunk);border:1px solid var(--border-faint);border-radius:2px;font-size:10px;font-family:var(--font-mono);">$1</code>',
    )
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.+?)\*/g, "<em>$1</em>")
    .replace(
      /\[([^\]]+)\]\(([^)]+)\)/g,
      (_m, label, url) =>
        `<a href="${safeHref(url)}" style="color:var(--accent);text-decoration:underline;text-underline-offset:2px;text-decoration-style:dotted;" target="_blank" rel="noopener noreferrer">${label}</a>`,
    );
}
