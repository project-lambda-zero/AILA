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
import { MonoBadge, Segmented } from "@/components/aila/mock";

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

const NARRATIVE_TONES: { value: NarrativeTone; label: string; hint: string }[] = [
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

const NARRATIVE_LENGTHS: { value: NarrativeLength; label: string; hint: string }[] = [
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

  const currentToneHint = NARRATIVE_TONES.find((t) => t.value === tone)?.hint ?? "";
  const currentLengthHint = NARRATIVE_LENGTHS.find((l) => l.value === length)?.hint ?? "";

  return (
    <WindowPanel
      title="narrative writeup"
      tone="info"
      actions={
        <span
          className="font-mono"
          style={{
            fontSize: 9.5,
            color: "var(--text-faint)",
            letterSpacing: "0.06em",
          }}
        >
          last: {formatRelative(narrative?.generated_at ?? null)}
        </span>
      }
    >
      <h2 className="sr-only">Narrative writeup</h2>
      <div style={{ display: "flex", flexDirection: "column", gap: 10, padding: 10 }}>
        <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
          <button
            type="button"
            onClick={() => setFormOpen((v) => !v)}
            className="font-mono uppercase inline-flex items-center"
            style={{
              height: 26,
              padding: "0 12px",
              gap: 6,
              fontSize: 9.5,
              letterSpacing: "0.08em",
              color: "var(--text-muted)",
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              borderRadius: 2,
              cursor: "pointer",
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.color = "var(--text-primary)";
              e.currentTarget.style.borderColor = "var(--accent)";
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.color = "var(--text-muted)";
              e.currentTarget.style.borderColor = "var(--border-soft)";
            }}
          >
            {formOpen ? (
              <CaretDown weight="bold" size={11} />
            ) : (
              <CaretRight weight="bold" size={11} />
            )}
            {narrative ? (
              <ArrowsClockwise weight="regular" size={12} />
            ) : (
              <BookOpen weight="regular" size={12} />
            )}
            <span>{narrative ? "regenerate narrative" : "generate narrative"}</span>
            {narrativeMut.isPending && (
              <span
                style={{
                  marginLeft: 3,
                  fontSize: 9,
                  color: "var(--text-faint)",
                  letterSpacing: "0.08em",
                }}
              >
                queued…
              </span>
            )}
          </button>

          {narrative && (
            <button
              type="button"
              onClick={() => setViewerOpen(true)}
              className="font-mono uppercase inline-flex items-center"
              style={{
                height: 26,
                padding: "0 12px",
                gap: 6,
                fontSize: 9.5,
                letterSpacing: "0.08em",
                color: "var(--accent)",
                background: "color-mix(in srgb, var(--accent) 12%, transparent)",
                border: "1px solid var(--accent)",
                borderRadius: 2,
                cursor: "pointer",
              }}
            >
              <BookOpen weight="fill" size={12} />
              <span>open narrative</span>
              <MonoBadge tone="info">{formatRelative(narrative.generated_at)}</MonoBadge>
            </button>
          )}
        </div>

        {formOpen && (
          <div
            style={{
              padding: 12,
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              borderRadius: 2,
              display: "flex",
              flexDirection: "column",
              gap: 12,
            }}
          >
            <SegRow label="tone" hint={currentToneHint}>
              <Segmented<NarrativeTone>
                options={NARRATIVE_TONES.map((t) => ({ value: t.value, label: t.label }))}
                value={tone}
                onChange={setTone}
              />
            </SegRow>
            <SegRow label="length" hint={currentLengthHint}>
              <Segmented<NarrativeLength>
                options={NARRATIVE_LENGTHS.map((l) => ({ value: l.value, label: l.label }))}
                value={length}
                onChange={setLength}
              />
            </SegRow>
            <FocusField
              value={focus}
              onChange={setFocus}
              placeholder="optional: lead with the taint-flow finding, frame around the patch-present verdict, etc."
            />
            <div className="flex items-center" style={{ gap: 6 }}>
              <button
                type="button"
                onClick={submitNarrative}
                disabled={narrativeMut.isPending}
                className="font-mono uppercase"
                style={{
                  height: 26,
                  padding: "0 12px",
                  fontSize: 9.5,
                  letterSpacing: "0.08em",
                  color: "var(--text-on-accent)",
                  background: "var(--accent)",
                  border: "1px solid var(--accent)",
                  borderRadius: 2,
                  cursor: "pointer",
                  opacity: narrativeMut.isPending ? 0.5 : 1,
                }}
              >
                {narrativeMut.isPending ? "queueing…" : "generate narrative"}
              </button>
              <button
                type="button"
                onClick={() => setFormOpen(false)}
                className="font-mono uppercase"
                style={{
                  height: 26,
                  padding: "0 12px",
                  fontSize: 9.5,
                  letterSpacing: "0.08em",
                  color: "var(--text-muted)",
                  background: "transparent",
                  border: "1px solid var(--border-soft)",
                  borderRadius: 2,
                  cursor: "pointer",
                }}
              >
                cancel
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

function SegRow({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      <div className="flex items-center" style={{ gap: 10 }}>
        <span
          className="font-mono uppercase"
          style={{
            width: 60,
            flex: "0 0 auto",
            fontSize: 9,
            letterSpacing: "0.1em",
            color: "var(--text-faint)",
          }}
        >
          {label}
        </span>
        <div style={{ minWidth: 0 }}>{children}</div>
      </div>
      {hint && (
        <span
          className="font-mono"
          style={{
            marginLeft: 70,
            fontSize: 9.5,
            color: "var(--text-faint)",
            letterSpacing: "0.04em",
          }}
        >
          {hint}
        </span>
      )}
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
    <div className="flex items-start" style={{ gap: 10 }}>
      <label
        className="font-mono uppercase"
        style={{
          width: 60,
          flex: "0 0 auto",
          paddingTop: 6,
          fontSize: 9,
          letterSpacing: "0.1em",
          color: "var(--text-faint)",
        }}
      >
        focus
      </label>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        rows={2}
        maxLength={2000}
        placeholder={placeholder}
        className="font-mono"
        style={{
          flex: 1,
          padding: "6px 8px",
          fontSize: 11,
          lineHeight: 1.45,
          color: "var(--text-primary)",
          background: "var(--surface-page)",
          border: "1px solid var(--border-soft)",
          borderRadius: 2,
          outline: "none",
          resize: "vertical",
        }}
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
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{
        padding: 16,
        background: "color-mix(in srgb, var(--surface-sunk) 78%, transparent)",
        backdropFilter: "blur(6px)",
      }}
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        style={{
          position: "relative",
          maxWidth: "56rem",
          width: "100%",
          maxHeight: "90vh",
          overflow: "hidden",
          background: "var(--surface-card)",
          border: "1px solid var(--accent)",
          borderRadius: 3,
          boxShadow: "var(--bevel-raised)",
          display: "flex",
          flexDirection: "column",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center justify-between"
          style={{
            gap: 12,
            padding: "10px 16px",
            background: "var(--surface-chrome)",
            backgroundImage: "var(--hatch)",
            borderBottom: "1px solid var(--border-soft)",
          }}
        >
          <div style={{ minWidth: 0, flex: 1 }}>
            <div
              className="font-mono uppercase"
              style={{
                fontSize: 9,
                marginBottom: 3,
                letterSpacing: "0.14em",
                color: "var(--accent)",
              }}
            >
              investigation narrative · {narrative.tone_used}
            </div>
            <h2
              style={{
                fontFamily: "var(--font-display)",
                fontWeight: 300,
                fontSize: 18,
                letterSpacing: "-0.01em",
                color: "var(--text-primary)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {narrative.title}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex items-center justify-center"
            style={{
              width: 26,
              height: 26,
              color: "var(--text-muted)",
              background: "transparent",
              border: "1px solid var(--border-soft)",
              borderRadius: 2,
              cursor: "pointer",
            }}
            aria-label="Close narrative"
          >
            <X weight="bold" size={14} />
          </button>
        </div>

        <div
          style={{
            overflowY: "auto",
            padding: "14px 18px",
            flex: 1,
            minHeight: 0,
          }}
        >
          {narrative.chapter_outline.length > 0 && (
            <details
              style={{
                marginBottom: 14,
                padding: "8px 10px",
                background: "var(--surface-sunk)",
                border: "1px solid var(--border-soft)",
                borderRadius: 2,
              }}
            >
              <summary
                className="font-mono uppercase"
                style={{
                  cursor: "pointer",
                  fontSize: 9,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                }}
              >
                table of contents ({narrative.chapter_outline.length})
              </summary>
              <ul
                style={{
                  marginTop: 6,
                  display: "flex",
                  flexDirection: "column",
                  gap: 3,
                }}
              >
                {narrative.chapter_outline.map((chapter, i) => (
                  <li
                    key={i}
                    className="font-mono"
                    style={{
                      fontSize: 10.5,
                      color: "var(--text-muted)",
                      letterSpacing: "0.04em",
                    }}
                  >
                    {i + 1}. {chapter}
                  </li>
                ))}
              </ul>
            </details>
          )}

          <article
            style={{
              fontFamily: "var(--font-sans)",
              fontSize: 13,
              lineHeight: 1.65,
              color: "var(--text-primary)",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              maxWidth: "none",
            }}
          >
            {narrative.body}
          </article>
        </div>

        <div
          className="flex items-center justify-between font-mono"
          style={{
            gap: 12,
            padding: "8px 16px",
            fontSize: 9.5,
            color: "var(--text-faint)",
            letterSpacing: "0.06em",
            background: "var(--surface-chrome)",
            borderTop: "1px solid var(--border-soft)",
          }}
        >
          <span>{wordCount} words</span>
          <span>generated {formatRelative(narrative.generated_at)}</span>
          <button
            type="button"
            onClick={() => navigator.clipboard.writeText(narrative.body)}
            className="font-mono uppercase"
            style={{
              height: 24,
              padding: "0 10px",
              fontSize: 9.5,
              letterSpacing: "0.08em",
              color: "var(--text-muted)",
              background: "transparent",
              border: "1px solid var(--border-soft)",
              borderRadius: 2,
              cursor: "pointer",
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.color = "var(--accent)";
              e.currentTarget.style.borderColor = "var(--accent)";
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.color = "var(--text-muted)";
              e.currentTarget.style.borderColor = "var(--border-soft)";
            }}
          >
            copy markdown
          </button>
        </div>
      </div>
    </div>
  );
}
