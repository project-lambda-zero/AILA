/**
 * VRNarrativeControls -- panel for the long-form narrative writeup on
 * a VR investigation.
 *
 * A single manual artifact separate from the structured panel
 * synthesis: an operator picks a voice (blog / incident_report /
 * thriller / academic / casual) and a length tier (short / standard /
 * long), optionally names a focus, and dispatches the narrative task.
 * The task walks the branches, personas, tool-driven audit chain, and
 * final verdict, then persists the writeup under
 * `payload.investigation_narrative` on the primary outcome (alongside,
 * never replacing, the existing `panel_summary`).
 *
 * Lives on the InvestigationDetailPage right under the primary outcome
 * card so the operator can generate + re-generate without scrolling
 * away from the outcome context.
 */
import { useState } from "react";
import { ArrowsClockwise } from "@phosphor-icons/react/dist/csr/ArrowsClockwise";
import { BookOpen } from "@phosphor-icons/react/dist/csr/BookOpen";
import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { CaretRight } from "@phosphor-icons/react/dist/csr/CaretRight";
import { X } from "@phosphor-icons/react/dist/csr/X";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { AilaBadge } from "@/components/aila/AilaBadge";

import {
  useGenerateVRNarrative,
  type NarrativeLength,
  type NarrativeTone,
} from "../mutations";

/** Stored narrative shape on `payload.investigation_narrative`.
 *  Backend contract (see run_vr_narrative): title, body (markdown),
 *  chapter_outline, tone_used (echo of the requested tone), an
 *  ISO8601 generated_at, and narrative_words as a cheap word count. */
export interface InvestigationNarrative {
  title: string;
  body: string;
  chapter_outline: string[];
  tone_used: string;
  generated_at: string;
  narrative_words: number;
}

interface Props {
  investigationId: string;
  /** Existing narrative on the canonical outcome's payload, if any.
   *  Passed by the detail page after reading via `readNarrative`. */
  narrative: InvestigationNarrative | null;
}

const NARRATIVE_TONES: {
  value: NarrativeTone;
  label: string;
  hint: string;
}[] = [
  { value: "blog", label: "Blog", hint: "Mid-friction tech blog voice (default)" },
  {
    value: "incident_report",
    label: "Incident report",
    hint: "Ticket writeup, chronological, evidence-cited",
  },
  {
    value: "thriller",
    label: "Thriller",
    hint: "Pulpy vuln-research long-read, tension + reveal beats",
  },
  {
    value: "academic",
    label: "Academic",
    hint: "Conference-paper voice, passive + citation-dense",
  },
  { value: "casual", label: "Casual", hint: "Discord / Mastodon thread voice" },
];

const NARRATIVE_LENGTHS: {
  value: NarrativeLength;
  label: string;
  hint: string;
}[] = [
  { value: "short", label: "Short", hint: "~600-1200 words, 3-5 sections" },
  { value: "standard", label: "Standard", hint: "~1500-3000 words, 5-9 sections" },
  {
    value: "long",
    label: "Long",
    hint: "~4000-8000 words, 8-15 sections (archival)",
  },
];

function formatRelative(iso: string | null): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "unknown";
  const diff = Date.now() - d.getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function VRNarrativeControls({ investigationId, narrative }: Props) {
  const [formOpen, setFormOpen] = useState(false);
  const [tone, setTone] = useState<NarrativeTone>("blog");
  const [length, setLength] = useState<NarrativeLength>("standard");
  const [focus, setFocus] = useState("");
  const [viewerOpen, setViewerOpen] = useState(false);

  const narrativeMut = useGenerateVRNarrative(investigationId);

  const submitNarrative = () => {
    narrativeMut.mutate({
      force: true,
      tone,
      length,
      operator_focus: focus.trim() || undefined,
    });
    setFormOpen(false);
  };

  return (
    <WindowPanel
      title="narrative writeup"
      tone="muted"
      actions={
        <span className="text-3xs font-mono text-text-muted">
          last narrative: {formatRelative(narrative?.generated_at ?? null)}
        </span>
      }
    >
      <h2 className="sr-only">Narrative writeup</h2>
      <div className="space-y-3">
        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => setFormOpen((v) => !v)}
            className="inline-flex items-center gap-2 px-3 py-1.5 text-xs rounded-md border border-border bg-elevated/40 text-foreground hover:border-accent hover:bg-elevated/70 transition-colors"
          >
            {formOpen ? (
              <CaretDown weight="bold" size={12} />
            ) : (
              <CaretRight weight="bold" size={12} />
            )}
            {narrative ? (
              <ArrowsClockwise weight="regular" size={14} />
            ) : (
              <BookOpen weight="regular" size={14} />
            )}
            <span>
              {narrative ? "Regenerate narrative" : "Generate narrative"}
            </span>
            {narrativeMut.isPending && (
              <span className="ml-1 text-3xs font-mono uppercase tracking-wide text-text-muted">
                queued{"\u2026"}
              </span>
            )}
          </button>

          {narrative && (
            <button
              type="button"
              onClick={() => setViewerOpen(true)}
              className="inline-flex items-center gap-2 px-3 py-1.5 text-xs rounded-md border border-accent/60 bg-accent/10 text-accent hover:bg-accent/20 transition-colors"
            >
              <BookOpen weight="fill" size={14} />
              <span>Open narrative</span>
              <AilaBadge severity="info" size="sm">
                {formatRelative(narrative.generated_at)}
              </AilaBadge>
            </button>
          )}
        </div>

        {formOpen && (
          <div className="rounded-md border border-border/60 bg-elevated/30 p-3 space-y-3">
            <DropdownRow
              label="Tone"
              value={tone}
              options={NARRATIVE_TONES}
              onChange={(v) => setTone(v as NarrativeTone)}
            />
            <DropdownRow
              label="Length"
              value={length}
              options={NARRATIVE_LENGTHS}
              onChange={(v) => setLength(v as NarrativeLength)}
            />
            <FocusField
              value={focus}
              onChange={setFocus}
              placeholder="optional: lead with the taint-flow finding, frame around the patch-present verdict, etc."
            />
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={submitNarrative}
                disabled={narrativeMut.isPending}
                className="px-3 py-1.5 text-xs rounded-md border border-accent bg-accent/15 text-accent hover:bg-accent/25 transition-colors disabled:opacity-50"
              >
                {narrativeMut.isPending
                  ? `Queueing${"\u2026"}`
                  : "Generate narrative"}
              </button>
              <button
                type="button"
                onClick={() => setFormOpen(false)}
                className="px-3 py-1.5 text-xs rounded-md border border-border text-text-muted hover:text-foreground"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {viewerOpen && narrative && (
        <NarrativeViewer
          narrative={narrative}
          onClose={() => setViewerOpen(false)}
        />
      )}
    </WindowPanel>
  );
}

interface DropdownOption {
  value: string;
  label: string;
  hint: string;
}

function DropdownRow({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: DropdownOption[];
  onChange: (value: string) => void;
}) {
  const current = options.find((o) => o.value === value);
  return (
    <div className="flex items-start gap-3">
      <label className="text-2xs font-mono uppercase tracking-wide text-text-muted pt-1.5 w-16 flex-shrink-0">
        {label}
      </label>
      <div className="flex-1 min-w-0">
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full px-2 py-1 text-xs rounded-md border border-border bg-elevated text-foreground focus:border-accent focus:outline-none"
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label} -- {o.hint}
            </option>
          ))}
        </select>
        {current && (
          <p className="mt-1 text-3xs font-mono text-text-muted">
            {current.hint}
          </p>
        )}
      </div>
    </div>
  );
}

function FocusField({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
}) {
  return (
    <div className="flex items-start gap-3">
      <label className="text-2xs font-mono uppercase tracking-wide text-text-muted pt-1.5 w-16 flex-shrink-0">
        Focus
      </label>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        rows={2}
        maxLength={2000}
        placeholder={placeholder}
        className="flex-1 px-2 py-1.5 text-xs font-mono rounded-md border border-border bg-elevated text-foreground focus:border-accent focus:outline-none resize-y"
      />
    </div>
  );
}

function NarrativeViewer({
  narrative,
  onClose,
}: {
  narrative: InvestigationNarrative;
  onClose: () => void;
}) {
  const wordCount =
    narrative.narrative_words > 0
      ? narrative.narrative_words
      : narrative.body.split(/\s+/).filter(Boolean).length;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center backdrop-blur-sm p-4"
      style={{ background: "color-mix(in srgb, var(--surface-sunk) 78%, transparent)" }}
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="relative max-w-4xl w-full max-h-[90vh] overflow-hidden rounded-lg border border-accent bg-background shadow-cyber-lg flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-3 border-b border-border px-5 py-3 bg-elevated/40">
          <div className="min-w-0 flex-1">
            <div className="text-3xs font-mono uppercase tracking-cyber-sm text-accent mb-1">
              Investigation narrative {"\u00b7"} {narrative.tone_used}
            </div>
            <h2 className="text-base font-semibold text-foreground truncate">
              {narrative.title}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-md text-text-muted hover:text-foreground hover:bg-elevated/70 transition-colors"
            aria-label="Close narrative"
          >
            <X weight="bold" size={16} />
          </button>
        </div>

        <div className="overflow-y-auto px-5 py-4 flex-1 min-h-0">
          {narrative.chapter_outline.length > 0 && (
            <details className="mb-4 rounded-md border border-border/60 bg-elevated/30 px-3 py-2">
              <summary className="cursor-pointer text-2xs font-mono uppercase tracking-wide text-text-muted">
                Table of contents ({narrative.chapter_outline.length})
              </summary>
              <ul className="mt-2 space-y-1">
                {narrative.chapter_outline.map((chapter, i) => (
                  <li key={i} className="text-xs text-text-muted font-mono">
                    {i + 1}. {chapter}
                  </li>
                ))}
              </ul>
            </details>
          )}

          <article className="prose prose-invert prose-sm max-w-none whitespace-pre-wrap break-words text-foreground/90 leading-relaxed">
            {narrative.body}
          </article>
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-border px-5 py-2 bg-elevated/40 text-3xs font-mono text-text-muted">
          <span>{wordCount} words</span>
          <span>generated {formatRelative(narrative.generated_at)}</span>
          <button
            type="button"
            onClick={() => navigator.clipboard.writeText(narrative.body)}
            className="px-2 py-1 rounded border border-border hover:border-accent hover:text-foreground transition-colors"
          >
            Copy markdown
          </button>
        </div>
      </div>
    </div>
  );
}
