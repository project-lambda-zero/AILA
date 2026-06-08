import { useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";

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

const formatStamp = (iso: string): string => {
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

export function AnalystDirectivesPanel({
  projectId,
  investigationId,
  compact = false,
}: Props) {
  const [text, setText] = useState("");
  const [scope, setScope] = useState<"project" | "investigation">(
    investigationId ? "investigation" : "project"
  );
  const [expanded, setExpanded] = useState(false);

  const directivesQ = useDirectives(projectId, investigationId);
  const createMut = useCreateDirective(projectId);
  const deleteMut = useDeleteDirective(projectId);
  const downloadMut = useDownloadDirectives(projectId);

  const items: AnalystDirective[] = directivesQ.data ?? [];
  const projectScoped = items.filter((d) => d.investigation_id === null);
  const investigationScoped = items.filter(
    (d) => d.investigation_id !== null
  );

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

  const heading = compact ? "Analyst Directives" : "Analyst Directives — guide AILA";
  const placeholder =
    "Optional directives to guide the investigator (focus areas, files to extract, hypotheses to pursue).";

  return (
    <AilaCard  techBorder glow><div className="flex items-center justify-between gap-2">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="flex items-center gap-2 text-left flex-1 min-w-0"
        aria-expanded={expanded}
        title={expanded ? "Collapse" : "Expand"}
      >
        <span
          className="text-text-muted text-xs w-3 inline-block"
          aria-hidden="true"
        >
          {expanded ? "▾" : "▸"}
        </span>
        <h3 className="text-sm font-semibold text-foreground truncate">
          {heading}
        </h3>
        <span className="text-xs text-text-muted">
          {items.length} active
        </span>
      </button>
      <Button
        type="button"
        size="sm"
        variant="secondary"
        onClick={(e) => {
          e.stopPropagation();
          downloadMut.mutate({
            investigationId: investigationId ?? null,
          });
        }}
        disabled={downloadMut.isPending || items.length === 0}
        title="Download directives as Markdown"
      >
        {downloadMut.isPending ? "…" : ".md"}
      </Button>
    </div>
    
    {!expanded ? null : (
    <>
    <form onSubmit={onSubmit} className="space-y-2 mb-4 mt-3">
      <Textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={placeholder}
        rows={compact ? 2 : 3}
        className="text-sm"
        disabled={createMut.isPending}
      />
      <div className="flex items-center justify-between gap-2">
        {investigationId ? (
          <div className="flex items-center gap-2 text-xs">
            <label className="flex items-center gap-1 cursor-pointer">
              <input
                type="radio"
                checked={scope === "investigation"}
                onChange={() => setScope("investigation")}
              />
              <span>This investigation only</span>
            </label>
            <label className="flex items-center gap-1 cursor-pointer">
              <input
                type="radio"
                checked={scope === "project"}
                onChange={() => setScope("project")}
              />
              <span>Project-wide</span>
            </label>
          </div>
        ) : (
          <span className="text-xs text-text-muted">
            Project-wide — applies to every investigation
          </span>
        )}
        <Button
          type="submit"
          size="sm"
          disabled={!text.trim() || createMut.isPending}
        >
          {createMut.isPending ? "Adding…" : "Add Directive"}
        </Button>
      </div>
    </form>
    
    {directivesQ.isLoading ? (
      <LoadingSkeleton size="sm" width="full" />
    ) : items.length === 0 ? (
      <p className="text-xs text-text-muted text-center py-4">
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
    )}</AilaCard>
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
      <div className="text-2xs uppercase tracking-wide text-text-muted mb-1">
        {label}
      </div>
      <ul className="space-y-1">
        {visible.map((d) => (
          <li
            key={d.id}
            className="flex items-start gap-2 text-sm border border-border rounded p-2"
          >
            <AilaBadge severity={badge === "P" ? "info" : "medium"} size="sm">
              {badge}
            </AilaBadge>
            <div className="flex-1 min-w-0">
              <p className="whitespace-pre-wrap break-words text-foreground">
                {d.text}
              </p>
              <p className="text-2xs text-text-muted mt-0.5">
                {d.created_by ? `${d.created_by} · ` : ""}
                {formatStamp(d.created_at)}
              </p>
            </div>
            <button
              type="button"
              onClick={() => onDelete(d.id)}
              className="text-xs text-text-muted hover:text-foreground"
              title="Remove"
            >
              ×
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
