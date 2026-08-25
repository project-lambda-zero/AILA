/**
 * Merged in-window drill-down for a fuzz campaign row: keyboard-operable
 * accordion with two sections -- the proposals for the target that owns the
 * campaign, and the crashes recorded against the campaign itself.
 *
 * Renders inline the same envelope + typography the rest of the console uses
 * (css() helper + CSS vars from frontend/src/styles/globals.css). Both
 * sections are collapsed by default; the button header carries aria-expanded
 * and toggles on click / Enter / Space (button defaults handle both keys).
 */

import { useState } from "react";
import type { CSSProperties, JSX, KeyboardEvent } from "react";

import {
  useFuzzCrashes,
  useFuzzProposals,
  type FuzzCrashRow,
  type FuzzProposalRow,
} from "../../api/fuzz";
import { css } from "../css";

export interface FuzzCampaignDetailProps {
  campaignId: string;
  targetId: string;
}

type SectionKey = "proposals" | "crashes";

const HEADER_CSS: CSSProperties = css(
  "display:flex;align-items:center;gap:8px;width:100%;padding:8px 10px;border:0;border-bottom:1px solid var(--border-faint);background:var(--surface-2);color:var(--text-primary);font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;text-align:left;",
);

const CHEVRON_CSS: CSSProperties = css(
  "flex:0 0 auto;display:inline-block;width:10px;color:var(--text-faint);font-size:10px;",
);

const SECTION_BODY_CSS: CSSProperties = css(
  "display:flex;flex-direction:column;gap:10px;padding:10px 12px;background:var(--surface-1);",
);

const ROW_CSS: CSSProperties = css(
  "display:flex;flex-direction:column;gap:6px;padding:8px 10px;border:1px solid var(--border-faint);background:var(--surface-0);border-radius:2px;",
);

const META_LINE_CSS: CSSProperties = css(
  "display:flex;flex-wrap:wrap;gap:10px;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);",
);

const KEY_CSS: CSSProperties = css(
  "font-size:8px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin-right:4px;",
);

const CODE_LABEL_CSS: CSSProperties = css(
  "font-size:8px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);",
);

const CODE_BLOCK_CSS: CSSProperties = css(
  "max-height:220px;overflow:auto;padding:8px 10px;border:1px solid var(--border-faint);background:var(--surface-2);color:var(--text-primary);font-family:var(--font-mono);font-size:10px;white-space:pre;",
);

const HEX_BLOCK_CSS: CSSProperties = css(
  "max-height:120px;overflow:auto;padding:8px 10px;border:1px solid var(--border-faint);background:var(--surface-2);color:var(--text-primary);font-family:var(--font-mono);font-size:10px;word-break:break-all;",
);

const STATUS_LINE_CSS: CSSProperties = css(
  "font-family:var(--font-mono);font-size:10px;color:var(--text-faint);padding:8px 10px;",
);

const EMPTY_CSS: CSSProperties = css(
  "font-family:var(--font-mono);font-size:10px;color:var(--text-faint);padding:8px 10px;",
);

function metaChip(label: string, value: string | number | null | undefined): JSX.Element | null {
  if (value === null || value === undefined || value === "") return null;
  return (
    <span key={label}>
      <span style={KEY_CSS}>{label}</span>
      <span>{String(value)}</span>
    </span>
  );
}

function ProposalCard({ row }: { row: FuzzProposalRow }): JSX.Element {
  return (
    <div style={ROW_CSS}>
      <div style={META_LINE_CSS}>
        {metaChip("profile", row.profile)}
        {metaChip("confidence", row.confidence)}
        {metaChip("status", row.status)}
        {metaChip("language", row.harness_language)}
        {metaChip("engine", row.suggested_engine_id)}
        {metaChip("strategy", row.suggested_strategy_id)}
      </div>
      {row.harness_build_command ? (
        <div>
          <div style={CODE_LABEL_CSS}>build command</div>
          <div style={CODE_BLOCK_CSS}>{row.harness_build_command}</div>
        </div>
      ) : null}
      {row.harness_source ? (
        <div>
          <div style={CODE_LABEL_CSS}>
            harness source{row.harness_target_path ? ` \u00b7 ${row.harness_target_path}` : ""}
          </div>
          <div style={CODE_BLOCK_CSS}>{row.harness_source}</div>
        </div>
      ) : null}
      {row.rationale ? (
        <div style={css("font-family:var(--font-mono);font-size:10px;color:var(--text-muted);")}>{row.rationale}</div>
      ) : null}
    </div>
  );
}

function CrashCard({ row }: { row: FuzzCrashRow }): JSX.Element {
  const hexNote =
    row.reproducer_head_truncated_size !== null && row.reproducer_head_truncated_size !== undefined
      ? ` (first ${row.reproducer_head_truncated_size} bytes)`
      : "";
  return (
    <div style={ROW_CSS}>
      <div style={META_LINE_CSS}>
        {metaChip("stack_hash", row.stack_hash)}
        {metaChip("verdict", row.verdict)}
        {metaChip("severity", row.severity)}
      </div>
      {row.stack_trace ? (
        <div>
          <div style={CODE_LABEL_CSS}>stack trace</div>
          <div style={CODE_BLOCK_CSS}>{row.stack_trace}</div>
        </div>
      ) : null}
      {row.reproducer_head_hex ? (
        <div>
          <div style={CODE_LABEL_CSS}>reproducer head (hex){hexNote}</div>
          <div style={HEX_BLOCK_CSS}>{row.reproducer_head_hex}</div>
        </div>
      ) : null}
    </div>
  );
}

interface SectionProps {
  sectionKey: SectionKey;
  label: string;
  count: number | null;
  expanded: boolean;
  onToggle: () => void;
  children: JSX.Element;
}

function Section({ sectionKey, label, count, expanded, onToggle, children }: SectionProps): JSX.Element {
  const bodyId = `fuzz-detail-${sectionKey}-body`;
  const onKey = (e: KeyboardEvent<HTMLButtonElement>): void => {
    // <button> already handles Enter/Space activation; keep the handler for
    // clarity + to guard against user-agent quirks that swallow one of them.
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onToggle();
    }
  };
  return (
    <div style={css("display:flex;flex-direction:column;border:1px solid var(--border-faint);background:var(--surface-1);")}>
      <button
        type="button"
        aria-expanded={expanded}
        aria-controls={bodyId}
        onClick={onToggle}
        onKeyDown={onKey}
        style={HEADER_CSS}
      >
        <span style={CHEVRON_CSS}>{expanded ? "\u25be" : "\u25b8"}</span>
        <span style={css("flex:1;")}>{label}</span>
        {count !== null ? (
          <span style={css("font-size:9px;color:var(--text-faint);")}>{count}</span>
        ) : null}
      </button>
      {expanded ? (
        <div id={bodyId} style={SECTION_BODY_CSS}>
          {children}
        </div>
      ) : null}
    </div>
  );
}

export default function FuzzCampaignDetail({ campaignId, targetId }: FuzzCampaignDetailProps): JSX.Element {
  const [open, setOpen] = useState<Record<SectionKey, boolean>>({ proposals: false, crashes: false });
  const toggle = (k: SectionKey): void => setOpen((prev) => ({ ...prev, [k]: !prev[k] }));

  const proposalsQ = useFuzzProposals(targetId);
  const crashesQ = useFuzzCrashes(campaignId);

  const proposals = proposalsQ.data ?? [];
  const crashes = crashesQ.data ?? [];

  const proposalsBody = ((): JSX.Element => {
    if (!targetId) return <div style={EMPTY_CSS}>no target bound to this campaign.</div>;
    if (proposalsQ.isLoading) return <div style={STATUS_LINE_CSS}>loading proposals&#8230;</div>;
    if (proposalsQ.isError) {
      const msg = proposalsQ.error instanceof Error ? proposalsQ.error.message : "request failed";
      return (
        <div style={css("font-family:var(--font-mono);font-size:10px;color:var(--status-warn);padding:8px 10px;")}>
          could not load proposals &mdash; {msg}
        </div>
      );
    }
    if (proposals.length === 0) {
      return <div style={EMPTY_CSS}>no fuzz proposals for this target yet.</div>;
    }
    return (
      <>
        {proposals.map((p) => (
          <ProposalCard key={p.id} row={p} />
        ))}
      </>
    );
  })();

  const crashesBody = ((): JSX.Element => {
    if (!campaignId) return <div style={EMPTY_CSS}>no campaign selected.</div>;
    if (crashesQ.isLoading) return <div style={STATUS_LINE_CSS}>loading crashes&#8230;</div>;
    if (crashesQ.isError) {
      const msg = crashesQ.error instanceof Error ? crashesQ.error.message : "request failed";
      return (
        <div style={css("font-family:var(--font-mono);font-size:10px;color:var(--status-warn);padding:8px 10px;")}>
          could not load crashes &mdash; {msg}
        </div>
      );
    }
    if (crashes.length === 0) {
      return <div style={EMPTY_CSS}>no crashes recorded for this campaign yet.</div>;
    }
    return (
      <>
        {crashes.map((c) => (
          <CrashCard key={c.id} row={c} />
        ))}
      </>
    );
  })();

  const proposalsCount = proposalsQ.isSuccess ? proposals.length : null;
  const crashesCount = crashesQ.isSuccess ? crashes.length : null;

  return (
    <div style={css("grid-column:1/-1;display:flex;flex-direction:column;gap:8px;min-width:0;")}>
      <Section
        sectionKey="proposals"
        label="proposals"
        count={proposalsCount}
        expanded={open.proposals}
        onToggle={() => toggle("proposals")}
      >
        {proposalsBody}
      </Section>
      <Section
        sectionKey="crashes"
        label="crashes"
        count={crashesCount}
        expanded={open.crashes}
        onToggle={() => toggle("crashes")}
      >
        {crashesBody}
      </Section>
    </div>
  );
}
