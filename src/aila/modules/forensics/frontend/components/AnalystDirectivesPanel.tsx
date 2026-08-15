import { useState } from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge } from "@/components/aila/mock";

import { useDirectives } from "../queries";
import {
  useCreateDirective,
  useDeleteDirective,
  useDownloadDirectives,
} from "../mutations";
import type { AnalystDirective } from "../types";

interface Props {
  projectId: string;
  /**
   * When provided, the panel composes new directives scoped to that
   * investigation by default and the list mixes project-wide entries
   * (always rendered first) with investigation-scoped ones.
   * Omit for the project-dashboard usage.
   */
  investigationId?: string;
  /** Compact mode for the dashboard (smaller heading, fewer entries). */
  compact?: boolean;
}

// Mock language button + textarea styles.
const TEXTAREA_STYLE: React.CSSProperties = {
  width: "100%",
  padding: "8px 10px",
  fontSize: 11,
  lineHeight: 1.55,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
  resize: "vertical",
};

const ACCENT_BTN: React.CSSProperties = {
  height: 26,
  padding: "0 12px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-on-accent)",
  background: "var(--accent)",
  border: "1px solid var(--accent)",
  borderRadius: 3,
  cursor: "pointer",
  boxShadow: "var(--bevel-key)",
};

const CHROME_BTN: React.CSSProperties = {
  height: 24,
  padding: "0 10px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

export function AnalystDirectivesPanel({
  projectId,
  investigationId,
  compact = false,
}: Props) {
  const [text, setText] = useState("");
  const [scope, setScope] = useState<"project" | "investigation">(
    investigationId ? "investigation" : "project",
  );
  const [expanded, setExpanded] = useState(false);

  const directivesQ = useDirectives(projectId, investigationId);
  const createMut = useCreateDirective(projectId);
  const deleteMut = useDeleteDirective(projectId);
  const downloadMut = useDownloadDirectives(projectId);

  const items: AnalystDirective[] = directivesQ.data ?? [];
  const projectScoped = items.filter((d) => d.investigation_id === null);
  const investigationScoped = items.filter((d) => d.investigation_id !== null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = text.trim();
    if (!trimmed) return;
    await createMut.mutateAsync({
      text: trimmed,
      investigation_id:
        scope === "investigation" && investigationId ? investigationId : null,
    });
    setText("");
  };

  const title = compact
    ? "analyst directives"
    : "analyst directives -- guide aila";
  const placeholder =
    "Optional directives to guide the investigator (focus areas, files to extract, hypotheses to pursue).";

  return (
    <WindowPanel
      title={title}
      status={`forensics ; ${items.length} active`}
      actions={
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            downloadMut.mutate({
              investigationId: investigationId ?? null,
            });
          }}
          disabled={downloadMut.isPending || items.length === 0}
          title="Download directives as Markdown"
          className="font-mono uppercase"
          style={CHROME_BTN}
        >
          {downloadMut.isPending ? "\u2026" : ".md"}
        </button>
      }
    >
      <div>
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="flex items-center font-mono w-full text-left"
          aria-expanded={expanded}
          title={expanded ? "Collapse" : "Expand"}
          style={{
            gap: 8,
            padding: "4px 0",
            background: "transparent",
            border: 0,
            cursor: "pointer",
            fontSize: 11,
            color: "var(--text-primary)",
          }}
        >
          <span
            aria-hidden="true"
            style={{
              width: 12,
              color: "var(--text-faint)",
              display: "inline-block",
            }}
          >
            {expanded ? "\u25be" : "\u25b8"}
          </span>
          <span style={{ flex: 1 }}>{title}</span>
          <span style={{ color: "var(--text-faint)", fontSize: 10 }}>
            {items.length} active
          </span>
        </button>

        {!expanded ? null : (
          <>
            <form
              onSubmit={onSubmit}
              className="space-y-2"
              style={{ marginTop: 12, marginBottom: 16 }}
            >
              <textarea
                aria-label="New analyst directive"
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder={placeholder}
                rows={compact ? 2 : 3}
                disabled={createMut.isPending}
                className="font-mono"
                style={TEXTAREA_STYLE}
              />
              <div className="flex items-center justify-between" style={{ gap: 8 }}>
                {investigationId ? (
                  <fieldset className="border-0 p-0 m-0">
                    <legend className="sr-only">Directive scope</legend>
                    <div
                      className="flex items-center font-mono"
                      style={{
                        gap: 10,
                        fontSize: 10.5,
                        color: "var(--text-muted)",
                      }}
                    >
                      <label
                        className="flex items-center cursor-pointer"
                        style={{ gap: 4 }}
                      >
                        <input
                          type="radio"
                          name="analyst-directive-scope"
                          checked={scope === "investigation"}
                          onChange={() => setScope("investigation")}
                        />
                        <span>This investigation only</span>
                      </label>
                      <label
                        className="flex items-center cursor-pointer"
                        style={{ gap: 4 }}
                      >
                        <input
                          type="radio"
                          name="analyst-directive-scope"
                          checked={scope === "project"}
                          onChange={() => setScope("project")}
                        />
                        <span>Project-wide</span>
                      </label>
                    </div>
                  </fieldset>
                ) : (
                  <span
                    className="font-mono"
                    style={{ fontSize: 10.5, color: "var(--text-faint)" }}
                  >
                    Project-wide -- applies to every investigation
                  </span>
                )}
                <button
                  type="submit"
                  disabled={!text.trim() || createMut.isPending}
                  className="font-mono uppercase"
                  style={{
                    ...ACCENT_BTN,
                    opacity: !text.trim() || createMut.isPending ? 0.5 : 1,
                    cursor:
                      !text.trim() || createMut.isPending
                        ? "not-allowed"
                        : "pointer",
                  }}
                >
                  {createMut.isPending ? "adding\u2026" : "add directive"}
                </button>
              </div>
            </form>

            {directivesQ.isLoading ? (
              <LoadingSkeleton size="sm" width="full" />
            ) : items.length === 0 ? (
              <p
                className="font-mono"
                style={{
                  fontSize: 10.5,
                  color: "var(--text-faint)",
                  textAlign: "center",
                  padding: "16px 0",
                }}
              >
                No directives yet. AILA will run on its own. Add a directive
                above to steer the next turn.
              </p>
            ) : (
              <div className="space-y-3">
                {projectScoped.length > 0 && (
                  <DirectiveGroup
                    label="Project-wide"
                    badge="P"
                    items={projectScoped}
                    onDelete={(id) => deleteMut.mutate(id)}
                    compact={compact}
                  />
                )}
                {investigationScoped.length > 0 && (
                  <DirectiveGroup
                    label="This investigation"
                    badge="I"
                    items={investigationScoped}
                    onDelete={(id) => deleteMut.mutate(id)}
                    compact={compact}
                  />
                )}
              </div>
            )}
          </>
        )}
      </div>
    </WindowPanel>
  );
}

function DirectiveGroup({
  label,
  badge,
  items,
  onDelete,
  compact,
}: {
  label: string;
  badge: "P" | "I";
  items: AnalystDirective[];
  onDelete: (id: string) => void;
  compact: boolean;
}) {
  const visible = compact ? items.slice(-5).reverse() : [...items].reverse();
  return (
    <div>
      <div
        className="font-mono uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
          marginBottom: 6,
        }}
      >
        {label}
      </div>
      <ul className="space-y-1">
        {visible.map((d) => (
          <li
            key={d.id}
            className="flex items-start"
            style={{
              gap: 8,
              padding: 8,
              border: "1px solid var(--border-faint)",
              background: "var(--surface-card)",
              borderRadius: 3,
            }}
          >
            <MonoBadge tone={badge === "P" ? "info" : "medium"}>
              {badge}
            </MonoBadge>
            <div className="flex-1 min-w-0">
              <p
                className="font-mono whitespace-pre-wrap break-words"
                style={{
                  fontSize: 11,
                  color: "var(--text-primary)",
                  lineHeight: 1.55,
                }}
              >
                {d.text}
              </p>
              <p
                className="font-mono"
                style={{
                  fontSize: 9.5,
                  color: "var(--text-faint)",
                  marginTop: 3,
                }}
              >
                {d.created_by ? `${d.created_by} \u00b7 ` : ""}
                {(() => {
                  const iso = d.created_at;
                  if (!iso) return "";
                  try {
                    const dt = new Date(iso);
                    return `${dt.toLocaleDateString()} ${dt.toLocaleTimeString(
                      [],
                      { hour: "2-digit", minute: "2-digit" },
                    )}`;
                  } catch {
                    return iso;
                  }
                })()}
              </p>
            </div>
            <button
              type="button"
              onClick={() => onDelete(d.id)}
              title="Remove"
              className="font-mono"
              style={{
                background: "transparent",
                border: 0,
                color: "var(--text-faint)",
                fontSize: 12,
                cursor: "pointer",
                padding: "0 4px",
              }}
              aria-label="Remove directive"
            >
              {"\u00d7"}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
