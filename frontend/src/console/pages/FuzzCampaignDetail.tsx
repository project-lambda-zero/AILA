/**
 * Merged in-window drill-down for a fuzz campaign row: keyboard-operable
 * accordion with three sections -- the campaign's telemetry chart, the
 * proposals for the target that owns the campaign (pending ones carry
 * accept/reject controls), and the crashes recorded against the campaign
 * itself (each with a triage control that appends to its triage chain).
 *
 * Renders inline the same envelope + typography the rest of the console uses
 * (css() helper + CSS vars from frontend/src/styles/globals.css). All
 * sections are collapsed by default; the button header carries aria-expanded
 * and toggles on click / Enter / Space (button defaults handle both keys).
 */

import { useState } from "react";
import type { CSSProperties, JSX, KeyboardEvent } from "react";

import { useAuth } from "../../api/auth";
import {
  CRASH_TRIAGE_VERDICTS,
  useAcceptFuzzProposal,
  useFuzzCrashes,
  useFuzzProposals,
  useRejectFuzzProposal,
  useTriageFuzzCrash,
  type CrashTriageVerdict,
  type FuzzCrashRow,
  type FuzzProposalAcceptBody,
  type FuzzProposalRow,
} from "../../api/fuzz";
import { asRecord } from "../../api/parse";
import { css } from "../css";
import { toast } from "../toast";
import FuzzTelemetryChart from "./FuzzTelemetryChart";

export interface FuzzCampaignDetailProps {
  campaignId: string;
  targetId: string;
  /** Campaign status from the list row; telemetry polls while "running". */
  campaignStatus: string;
}

type SectionKey = "telemetry" | "proposals" | "crashes";

const HEADER_CSS: CSSProperties = css(
  "display:flex;align-items:center;gap:8px;width:100%;padding:8px 10px;border:0;border-bottom:1px solid var(--border-faint);background:var(--surface-2);color:var(--text-primary);font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;text-align:left;",
);

const CHEVRON_CSS: CSSProperties = css(
  "flex:0 0 auto;display:inline-block;width:10px;color:var(--text-faint);font-size:11px;",
);

const SECTION_BODY_CSS: CSSProperties = css(
  "display:flex;flex-direction:column;gap:10px;padding:10px 12px;background:var(--surface-1);",
);

const ROW_CSS: CSSProperties = css(
  "display:flex;flex-direction:column;gap:6px;padding:8px 10px;border:1px solid var(--border-faint);background:var(--surface-0);border-radius:2px;",
);

const META_LINE_CSS: CSSProperties = css(
  "display:flex;flex-wrap:wrap;gap:10px;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);",
);

const KEY_CSS: CSSProperties = css(
  "font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin-right:4px;",
);

const CODE_LABEL_CSS: CSSProperties = css(
  "font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);",
);

const CODE_BLOCK_CSS: CSSProperties = css(
  "max-height:220px;overflow:auto;padding:8px 10px;border:1px solid var(--border-faint);background:var(--surface-2);color:var(--text-primary);font-family:var(--font-mono);font-size:11px;white-space:pre;",
);

const HEX_BLOCK_CSS: CSSProperties = css(
  "max-height:120px;overflow:auto;padding:8px 10px;border:1px solid var(--border-faint);background:var(--surface-2);color:var(--text-primary);font-family:var(--font-mono);font-size:11px;word-break:break-all;",
);

const STATUS_LINE_CSS: CSSProperties = css(
  "font-family:var(--font-mono);font-size:11px;color:var(--text-faint);padding:8px 10px;",
);

const EMPTY_CSS: CSSProperties = css(
  "font-family:var(--font-mono);font-size:11px;color:var(--text-faint);padding:8px 10px;",
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

const INPUT_CSS: CSSProperties = css(
  "min-height:28px;padding:4px 8px;border:1px solid var(--border-faint);background:var(--surface-0);color:var(--text-primary);font-family:var(--font-mono);font-size:11px;border-radius:2px;min-width:0;",
);

const FIELD_LABEL_CSS: CSSProperties = css(
  "display:flex;flex-direction:column;gap:3px;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);",
);

const BTN_CSS: CSSProperties = css(
  "min-height:28px;padding:0 12px;border:1px solid var(--border-soft);background:var(--surface-2);color:var(--text-primary);font-family:var(--font-mono);font-size:11px;cursor:pointer;border-radius:2px;",
);

const BTN_PRIMARY_CSS: CSSProperties = css(
  "min-height:28px;padding:0 12px;border:1px solid var(--accent);background:var(--surface-2);color:var(--accent);font-family:var(--font-mono);font-size:11px;cursor:pointer;border-radius:2px;",
);

const BTN_WARN_CSS: CSSProperties = css(
  "min-height:28px;padding:0 12px;border:1px solid var(--status-warn);background:var(--surface-2);color:var(--status-warn);font-family:var(--font-mono);font-size:11px;cursor:pointer;border-radius:2px;",
);

const PANEL_CSS: CSSProperties = css(
  "display:flex;flex-direction:column;gap:8px;padding:10px;border:1px solid var(--border-soft);background:var(--surface-1);border-radius:2px;",
);

const FORM_GRID_CSS: CSSProperties = css(
  "display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;",
);

/** Parse an optional JSON-object textarea. Empty -> undefined; anything but a
 * JSON object -> an error string for the inline validation line. */
function parseJsonObject(text: string, label: string): Record<string, unknown> | undefined | string {
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return `${label} is not valid JSON`;
  }
  const obj = asRecord(parsed);
  return obj ?? `${label} must be a JSON object`;
}

/** Inclusive integer range check for optional numeric overrides. Empty ->
 * undefined; out of range / non-integer -> error string. */
function parseIntField(text: string, label: string, min: number, max: number): number | undefined | string {
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  const n = Number(trimmed);
  if (!Number.isInteger(n) || n < min || n > max) return `${label} must be an integer ${min}..${max}`;
  return n;
}

function AcceptProposalForm({
  row,
  targetId,
  onClose,
}: {
  row: FuzzProposalRow;
  targetId: string;
  onClose: () => void;
}): JSX.Element {
  const accept = useAcceptFuzzProposal(targetId);
  const [name, setName] = useState("");
  const [engineId, setEngineId] = useState("");
  const [strategyId, setStrategyId] = useState("");
  const [duration, setDuration] = useState("");
  const [systemId, setSystemId] = useState("");
  const [engineConfig, setEngineConfig] = useState("");
  const [strategyConfig, setStrategyConfig] = useState("");
  const [autoLaunch, setAutoLaunch] = useState(true);
  const [skipPrepare, setSkipPrepare] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  const submit = (): void => {
    const body: FuzzProposalAcceptBody = { auto_launch: autoLaunch, skip_prepare: skipPrepare };
    if (name.trim()) body.name = name.trim();
    if (engineId.trim()) body.engine_id = engineId.trim();
    if (strategyId.trim()) body.strategy_id = strategyId.trim();
    if (reason.trim()) body.decision_reason = reason.trim();
    const dur = parseIntField(duration, "duration hours", 1, 720);
    const sys = parseIntField(systemId, "analysis system id", 1, Number.MAX_SAFE_INTEGER);
    const ec = parseJsonObject(engineConfig, "engine config");
    const sc = parseJsonObject(strategyConfig, "strategy config");
    for (const v of [dur, sys, ec, sc]) {
      if (typeof v === "string") {
        setError(v);
        return;
      }
    }
    if (typeof dur === "number") body.duration_hours = dur;
    if (typeof sys === "number") body.analysis_system_id = sys;
    if (ec && typeof ec === "object") body.engine_config = ec;
    if (sc && typeof sc === "object") body.strategy_config = sc;
    setError(null);
    accept.mutate(
      { proposalId: row.id, body },
      {
        onSuccess: (res) => {
          toast.success(
            `proposal accepted · campaign ${res.campaign_id.slice(0, 8)} ${res.auto_launched ? "launched" : "created"}`,
          );
          onClose();
        },
        onError: (e) => toast.fail("accept proposal", e),
      },
    );
  };

  return (
    <div role="group" aria-label="accept proposal" style={PANEL_CSS}>
      <div style={FIELD_LABEL_CSS}>accept &mdash; blank fields use the proposal / target / project defaults</div>
      <div style={FORM_GRID_CSS}>
        <label style={FIELD_LABEL_CSS}>
          campaign name
          <input style={INPUT_CSS} value={name} maxLength={255} onChange={(e) => setName(e.target.value)} />
        </label>
        <label style={FIELD_LABEL_CSS}>
          engine id
          <input
            style={INPUT_CSS}
            value={engineId}
            maxLength={32}
            placeholder={row.suggested_engine_id ?? ""}
            onChange={(e) => setEngineId(e.target.value)}
          />
        </label>
        <label style={FIELD_LABEL_CSS}>
          strategy id
          <input
            style={INPUT_CSS}
            value={strategyId}
            maxLength={32}
            placeholder={row.suggested_strategy_id ?? ""}
            onChange={(e) => setStrategyId(e.target.value)}
          />
        </label>
        <label style={FIELD_LABEL_CSS}>
          duration hours (1-720)
          <input
            style={INPUT_CSS}
            type="number"
            min={1}
            max={720}
            value={duration}
            placeholder={row.suggested_duration_hours !== null ? String(row.suggested_duration_hours) : ""}
            onChange={(e) => setDuration(e.target.value)}
          />
        </label>
        <label style={FIELD_LABEL_CSS}>
          analysis system id
          <input
            style={INPUT_CSS}
            type="number"
            min={1}
            value={systemId}
            placeholder="project default"
            onChange={(e) => setSystemId(e.target.value)}
          />
        </label>
      </div>
      <div style={FORM_GRID_CSS}>
        <label style={FIELD_LABEL_CSS}>
          engine config (JSON object)
          <textarea style={{ ...INPUT_CSS, minHeight: 56, resize: "vertical" }} value={engineConfig} onChange={(e) => setEngineConfig(e.target.value)} />
        </label>
        <label style={FIELD_LABEL_CSS}>
          strategy config (JSON object)
          <textarea style={{ ...INPUT_CSS, minHeight: 56, resize: "vertical" }} value={strategyConfig} onChange={(e) => setStrategyConfig(e.target.value)} />
        </label>
      </div>
      <label style={FIELD_LABEL_CSS}>
        decision reason
        <textarea
          style={{ ...INPUT_CSS, minHeight: 48, resize: "vertical" }}
          value={reason}
          maxLength={2048}
          onChange={(e) => setReason(e.target.value)}
        />
      </label>
      <div style={css("display:flex;flex-wrap:wrap;align-items:center;gap:14px;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);")}>
        <label style={css("display:flex;align-items:center;gap:6px;cursor:pointer;")}>
          <input type="checkbox" checked={autoLaunch} onChange={(e) => setAutoLaunch(e.target.checked)} />
          auto-launch after prepare
        </label>
        <label style={css("display:flex;align-items:center;gap:6px;cursor:pointer;")}>
          <input type="checkbox" checked={skipPrepare} onChange={(e) => setSkipPrepare(e.target.checked)} />
          skip prepare (harness already on the workstation)
        </label>
      </div>
      {error ? <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--status-warn);")}>{error}</div> : null}
      <div style={css("display:flex;gap:8px;justify-content:flex-end;")}>
        <button type="button" style={BTN_CSS} onClick={onClose} disabled={accept.isPending}>
          cancel
        </button>
        <button type="button" style={BTN_PRIMARY_CSS} onClick={submit} disabled={accept.isPending}>
          {accept.isPending ? "preparing…" : "accept"}
        </button>
      </div>
    </div>
  );
}

function RejectProposalForm({
  row,
  targetId,
  onClose,
}: {
  row: FuzzProposalRow;
  targetId: string;
  onClose: () => void;
}): JSX.Element {
  const reject = useRejectFuzzProposal(targetId);
  const [reason, setReason] = useState("");
  const trimmed = reason.trim();
  const submit = (): void => {
    reject.mutate(
      { proposalId: row.id, decisionReason: trimmed },
      {
        onSuccess: () => {
          toast.success("proposal rejected");
          onClose();
        },
        onError: (e) => toast.fail("reject proposal", e),
      },
    );
  };
  return (
    <div role="group" aria-label="reject proposal" style={PANEL_CSS}>
      <label style={FIELD_LABEL_CSS}>
        reason (required)
        <textarea
          style={{ ...INPUT_CSS, minHeight: 48, resize: "vertical" }}
          value={reason}
          maxLength={2048}
          onChange={(e) => setReason(e.target.value)}
        />
      </label>
      <div style={css("display:flex;gap:8px;justify-content:flex-end;")}>
        <button type="button" style={BTN_CSS} onClick={onClose} disabled={reject.isPending}>
          cancel
        </button>
        <button type="button" style={BTN_WARN_CSS} onClick={submit} disabled={reject.isPending || !trimmed}>
          {reject.isPending ? "rejecting…" : "reject"}
        </button>
      </div>
    </div>
  );
}

function ProposalCard({ row, targetId }: { row: FuzzProposalRow; targetId: string }): JSX.Element {
  const [decision, setDecision] = useState<"accept" | "reject" | null>(null);
  const pending = row.status === "pending";
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
        <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-muted);")}>{row.rationale}</div>
      ) : null}
      {row.accepted_campaign_id ? (
        <div style={META_LINE_CSS}>{metaChip("campaign", row.accepted_campaign_id)}</div>
      ) : null}
      {pending && decision === null ? (
        <div style={css("display:flex;gap:8px;")}>
          <button type="button" style={BTN_PRIMARY_CSS} onClick={() => setDecision("accept")}>
            accept&#8230;
          </button>
          <button type="button" style={BTN_WARN_CSS} onClick={() => setDecision("reject")}>
            reject&#8230;
          </button>
        </div>
      ) : null}
      {pending && decision === "accept" ? (
        <AcceptProposalForm row={row} targetId={targetId} onClose={() => setDecision(null)} />
      ) : null}
      {pending && decision === "reject" ? (
        <RejectProposalForm row={row} targetId={targetId} onClose={() => setDecision(null)} />
      ) : null}
    </div>
  );
}

const VERDICT_LABEL = {
  untriaged: "untriaged",
  security_relevant: "security relevant",
  likely_harmless: "likely harmless",
  duplicate: "duplicate",
  needs_manual_review: "needs manual review",
} satisfies Record<CrashTriageVerdict, string>;

function isVerdict(v: string): v is CrashTriageVerdict {
  return CRASH_TRIAGE_VERDICTS.some((k) => k === v);
}

function CrashTriageControl({ row }: { row: FuzzCrashRow }): JSX.Element {
  const triage = useTriageFuzzCrash(row.campaign_id);
  const actor = useAuth((s) => s.user?.username ?? s.user?.id ?? "");
  const [verdict, setVerdict] = useState<CrashTriageVerdict>(row.triage_verdict);
  const [reason, setReason] = useState("");
  const [notes, setNotes] = useState("");
  const submit = (): void => {
    triage.mutate(
      {
        crashId: row.id,
        event: { at: new Date().toISOString(), actor, verdict, reason: reason.trim(), notes: notes.trim() },
      },
      {
        onSuccess: () => {
          toast.success(`crash triaged · ${VERDICT_LABEL[verdict]}`);
          setReason("");
          setNotes("");
        },
        onError: (e) => toast.fail("triage crash", e),
      },
    );
  };
  return (
    <div role="group" aria-label="triage crash" style={PANEL_CSS}>
      <div style={FORM_GRID_CSS}>
        <label style={FIELD_LABEL_CSS}>
          verdict
          <select
            style={INPUT_CSS}
            value={verdict}
            onChange={(e) => {
              if (isVerdict(e.target.value)) setVerdict(e.target.value);
            }}
          >
            {CRASH_TRIAGE_VERDICTS.map((v) => (
              <option key={v} value={v}>
                {VERDICT_LABEL[v]}
              </option>
            ))}
          </select>
        </label>
        <label style={FIELD_LABEL_CSS}>
          reason
          <input style={INPUT_CSS} value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
      </div>
      <label style={FIELD_LABEL_CSS}>
        notes
        <textarea
          style={{ ...INPUT_CSS, minHeight: 40, resize: "vertical" }}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
        />
      </label>
      <div style={css("display:flex;justify-content:flex-end;")}>
        <button type="button" style={BTN_PRIMARY_CSS} onClick={submit} disabled={triage.isPending || !actor}>
          {triage.isPending ? "saving…" : "record triage"}
        </button>
      </div>
    </div>
  );
}

function CrashCard({ row }: { row: FuzzCrashRow }): JSX.Element {
  const [triageOpen, setTriageOpen] = useState(false);
  const hexNote =
    row.reproducer_head_truncated_size !== null && row.reproducer_head_truncated_size !== undefined
      ? ` (first ${row.reproducer_head_truncated_size} bytes)`
      : "";
  return (
    <div style={ROW_CSS}>
      <div style={META_LINE_CSS}>
        {metaChip("stack_hash", row.stack_hash)}
        {metaChip("type", row.crash_type)}
        {metaChip("verdict", VERDICT_LABEL[row.triage_verdict])}
        {metaChip("severity", row.severity)}
      </div>
      {row.triage_reason ? (
        <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-muted);")}>{row.triage_reason}</div>
      ) : null}
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
      {row.triage_chain.length > 0 ? (
        <div>
          <div style={CODE_LABEL_CSS}>triage chain</div>
          <ol style={css("margin:0;padding-left:18px;display:flex;flex-direction:column;gap:2px;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);")}>
            {row.triage_chain.map((ev, i) => (
              <li key={`${ev.at}-${i}`}>
                {new Date(ev.at).toLocaleString()} · {ev.actor} · {VERDICT_LABEL[ev.verdict]}
                {ev.reason ? ` · ${ev.reason}` : ""}
                {ev.notes ? ` · ${ev.notes}` : ""}
              </li>
            ))}
          </ol>
        </div>
      ) : null}
      <div>
        <button type="button" style={BTN_CSS} aria-expanded={triageOpen} onClick={() => setTriageOpen((v) => !v)}>
          {triageOpen ? "close triage" : "triage…"}
        </button>
      </div>
      {triageOpen ? <CrashTriageControl row={row} /> : null}
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
          <span style={css("font-size:11px;color:var(--text-faint);")}>{count}</span>
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

export default function FuzzCampaignDetail({ campaignId, targetId, campaignStatus }: FuzzCampaignDetailProps): JSX.Element {
  const [open, setOpen] = useState<Record<SectionKey, boolean>>({ telemetry: false, proposals: false, crashes: false });
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
        <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--status-warn);padding:8px 10px;")}>
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
          <ProposalCard key={p.id} row={p} targetId={targetId} />
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
        <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--status-warn);padding:8px 10px;")}>
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
        sectionKey="telemetry"
        label="telemetry"
        count={null}
        expanded={open.telemetry}
        onToggle={() => toggle("telemetry")}
      >
        {campaignId ? (
          <FuzzTelemetryChart campaignId={campaignId} live={campaignStatus === "running"} />
        ) : (
          <div style={EMPTY_CSS}>no campaign selected.</div>
        )}
      </Section>
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
