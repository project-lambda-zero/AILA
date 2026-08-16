import { useState } from "react";
import { Link, useParams } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge, SectionHeader } from "@/components/aila/mock";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

import { HexView } from "../components/HexView";
import { useAppendCrashTriage } from "../mutations";
import { useFuzzCrash } from "../queries";
import type { CrashSeverity, CrashTriageVerdict } from "../types";

// ─────────────────────────────────────────────────────────────────────
// Vocabulary
// ─────────────────────────────────────────────────────────────────────
const TRIAGE_VERDICT_VALUES: readonly CrashTriageVerdict[] = [
  "untriaged",
  "security_relevant",
  "likely_harmless",
  "duplicate",
  "needs_manual_review",
];

const VERDICT_TONE: Record<CrashTriageVerdict, string> = {
  untriaged: "muted",
  security_relevant: "critical",
  likely_harmless: "ok",
  duplicate: "info",
  needs_manual_review: "warn",
};

const SEVERITY_TONE: Record<CrashSeverity, string> = {
  critical: "critical",
  high: "warn",
  medium: "info",
  low: "ok",
  informational: "muted",
  unknown: "muted",
};

// ─────────────────────────────────────────────────────────────────────
// Shared control styles
// ─────────────────────────────────────────────────────────────────────
const CTRL: React.CSSProperties = {
  padding: "6px 8px",
  fontSize: 11,
  letterSpacing: "0.04em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

const PRIMARY_BTN: React.CSSProperties = {
  height: 28,
  padding: "0 12px",
  fontSize: 10,
  letterSpacing: "0.08em",
  background: "var(--accent)",
  border: "1px solid var(--accent)",
  color: "var(--text-on-accent)",
  borderRadius: 3,
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
};

// ─────────────────────────────────────────────────────────────────────
// Brief row (mirrors ProjectDetailPage's local helper).
// ─────────────────────────────────────────────────────────────────────
function BriefRow({
  label,
  children,
}: {
  label: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 3,
        padding: "8px 0",
        borderBottom: "1px solid var(--border-faint)",
      }}
    >
      <span
        className="font-mono uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: 11,
          color: "var(--text-primary)",
          minHeight: 14,
          overflowWrap: "anywhere",
        }}
      >
        {children}
      </span>
    </div>
  );
}

function formatDateTime(value?: string | null): string {
  if (!value) return "--";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

// ─────────────────────────────────────────────────────────────────────
// ClickableStackTrace -- fires a global custom event with the clicked
// frame name; parent apps can pick that up and jump to a target's
// Functions-of-interest tab (v0.6 wiring).
// ─────────────────────────────────────────────────────────────────────
function ClickableStackTrace({ raw }: { raw: string }) {
  const lines = raw.split("\n");
  return (
    <pre
      className="font-mono"
      style={{
        margin: 0,
        padding: 12,
        fontSize: 11,
        lineHeight: 1.55,
        color: "var(--text-primary)",
        background: "var(--surface-sunk)",
        border: "1px solid var(--border-soft)",
        borderRadius: 3,
        overflow: "auto",
        maxHeight: 400,
        whiteSpace: "pre",
      }}
    >
      {lines.map((line, i) => {
        const m = line.match(/(\b[A-Za-z_][A-Za-z0-9_:.@$]*)/);
        if (!m) return <div key={i}>{line || "\u00a0"}</div>;
        const fn = m[1];
        const before = line.slice(0, m.index ?? 0);
        const after = line.slice((m.index ?? 0) + fn.length);
        return (
          <div key={i}>
            <span style={{ color: "var(--text-muted)" }}>{before}</span>
            <button
              type="button"
              title={`locate ${fn} in this target's functions-of-interest tab`}
              onClick={() => {
                window.dispatchEvent(
                  new CustomEvent("vr-stack-frame-click", { detail: { fn } }),
                );
              }}
              style={{
                background: "transparent",
                border: "none",
                padding: 0,
                margin: 0,
                fontFamily: "inherit",
                fontSize: "inherit",
                color: "var(--accent)",
                textDecoration: "underline dotted",
                cursor: "pointer",
              }}
            >
              {fn}
            </button>
            <span>{after}</span>
          </div>
        );
      })}
    </pre>
  );
}

// ─────────────────────────────────────────────────────────────────────
// FuzzCrashDetailPage
// ─────────────────────────────────────────────────────────────────────
export function FuzzCrashDetailPage() {
  const { crashId } = useParams<{ crashId: string }>();
  const cid = crashId ?? "";
  const { data: crash, isLoading, isError } = useFuzzCrash(cid);

  useUpdatePageHeader({
    title: crash?.crash_type ?? (crash ? "Crash" : undefined),
    subtitle: crash ? `stack ${crash.stack_hash.slice(0, 12)}\u2026` : undefined,
    status: null,
  });

  if (isLoading) {
    return (
      <WindowPanel title="fuzz crash" tone="muted">
        <LoadingSkeleton size="lg" width="full" />
      </WindowPanel>
    );
  }
  if (isError || !crash) {
    return (
      <WindowPanel title="fuzz crash" tone="accent">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--accent)" }}
        >
          failed to load fuzz crash.
        </p>
      </WindowPanel>
    );
  }

  const headerTitle =
    crash.crash_type ??
    `crash \u00b7 ${crash.stack_hash.slice(0, 12)}\u2026`;

  const triageChain = crash.triage_chain ?? [];

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader icon="\u25c8" title={headerTitle} />

      {/* Chip row: verdict / severity / type / duplicate-of / promoted */}
      <div className="flex" style={{ gap: 8, flexWrap: "wrap" }}>
        <MonoBadge tone={VERDICT_TONE[crash.triage_verdict] ?? "muted"}>
          {crash.triage_verdict}
        </MonoBadge>
        <MonoBadge tone={SEVERITY_TONE[crash.severity] ?? "muted"}>
          severity \u00b7 {crash.severity}
        </MonoBadge>
        {crash.crash_type ? (
          <MonoBadge tone="warn">type \u00b7 {crash.crash_type}</MonoBadge>
        ) : null}
        {crash.duplicate_of_crash_id ? (
          <Link
            to={`/vr/fuzz/crashes/${crash.duplicate_of_crash_id}`}
            style={{ textDecoration: "none" }}
          >
            <MonoBadge tone="info">
              duplicate of earlier crash \u2192
            </MonoBadge>
          </Link>
        ) : null}
        {crash.promoted_to_finding_id ? (
          <MonoBadge tone="ok">promoted to finding</MonoBadge>
        ) : null}
      </div>

      {/* Triage brief */}
      <WindowPanel title="triage" tone="accent">
        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            columnGap: 18,
            rowGap: 0,
          }}
        >
          <BriefRow label="stack hash">{crash.stack_hash}</BriefRow>
          <BriefRow label="triage reason">
            {crash.triage_reason ?? "--"}
          </BriefRow>
          <BriefRow label="signature">
            {crash.crash_signature ?? "--"}
          </BriefRow>
          <BriefRow label="campaign">
            {crash.campaign_id ? (
              <Link
                to={`/vr/fuzz/campaigns/${crash.campaign_id}`}
                style={{
                  color: "var(--accent)",
                  textDecoration: "none",
                }}
              >
                {crash.campaign_id.slice(0, 12)}\u2026
              </Link>
            ) : (
              "--"
            )}
          </BriefRow>
          <BriefRow label="discovered">
            {formatDateTime(crash.discovered_at)}
          </BriefRow>
          <BriefRow label="llm summary">
            {crash.llm_summary ?? crash.triage_reason ?? "--"}
          </BriefRow>
        </div>
      </WindowPanel>

      {/* Triage chain -- numbered mono ordered list */}
      <WindowPanel
        title="triage chain"
        tone="info"
        actions={
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.12em",
              color: "var(--text-faint)",
            }}
          >
            {1 + triageChain.length + (crash.promoted_to_finding_id ? 1 : 0)}{" "}
            steps
          </span>
        }
      >
        <ol
          style={{
            listStyle: "none",
            padding: 0,
            margin: 0,
            display: "flex",
            flexDirection: "column",
            gap: 6,
          }}
        >
          <ChainStep step={1} tone="info" action="crash_register">
            bucket created (stack hash matched) on{" "}
            {formatDateTime(crash.discovered_at)}
          </ChainStep>
          {triageChain.map((entry, i) => {
            const verdict = typeof entry.verdict === "string"
              ? (entry.verdict as CrashTriageVerdict)
              : undefined;
            const tone = verdict
              ? (VERDICT_TONE[verdict] ?? "muted")
              : "muted";
            return (
              <ChainStep
                key={`triage-${i}`}
                step={2 + i}
                tone={tone}
                action="crash_triage"
                meta={
                  <>
                    {verdict ? (
                      <span style={{ color: "var(--text-muted)" }}>
                        verdict:{" "}
                        <span style={{ color: "var(--text-primary)" }}>
                          {verdict}
                        </span>
                      </span>
                    ) : null}
                    {entry.actor ? (
                      <span style={{ color: "var(--text-muted)" }}>
                        by{" "}
                        <span
                          className="font-mono"
                          style={{ color: "var(--text-primary)" }}
                        >
                          {entry.actor}
                        </span>
                      </span>
                    ) : null}
                    {entry.ts ? (
                      <span style={{ color: "var(--text-faint)" }}>
                        {formatDateTime(entry.ts)}
                      </span>
                    ) : null}
                  </>
                }
              >
                {entry.reason || entry.notes ? (
                  <>
                    {entry.reason ? (
                      <span style={{ color: "var(--text-muted)" }}>
                        {entry.reason}
                      </span>
                    ) : null}
                    {entry.reason && entry.notes ? (
                      <span style={{ color: "var(--text-faint)" }}>
                        {" "}\u00b7{" "}
                      </span>
                    ) : null}
                    {entry.notes ? (
                      <span
                        style={{
                          color: "var(--text-muted)",
                          fontStyle: "italic",
                        }}
                      >
                        {entry.notes}
                      </span>
                    ) : null}
                  </>
                ) : null}
              </ChainStep>
            );
          })}
          {crash.promoted_to_finding_id ? (
            <ChainStep
              step={2 + triageChain.length}
              tone="ok"
              action="promote_to_finding"
            >
              exploitability confirmed
            </ChainStep>
          ) : null}
        </ol>
        <p
          className="font-mono"
          style={{
            marginTop: 10,
            marginBottom: 0,
            fontSize: 10,
            color: "var(--text-faint)",
            letterSpacing: "0.04em",
          }}
        >
          per-turn reasoning rows (decompile_function / data_flow_trace /
          hypothesis_create / exploitability_assess) still require a crash
          {" "}\u2192 reasoning-turn join table -- backend pending.
        </p>
        <div
          style={{
            marginTop: 14,
            paddingTop: 12,
            borderTop: "1px solid var(--border-faint)",
          }}
        >
          <TriageEventForm crashId={cid} />
        </div>
      </WindowPanel>

      {/* Minimised input -- HexView from the head-hex bytes */}
      <WindowPanel
        title="minimised input"
        tone="muted"
        actions={
          <button
            type="button"
            disabled
            title="re-run reproducer on workstation -- backend pending"
            className="font-mono uppercase"
            style={{
              ...PRIMARY_BTN,
              opacity: 0.4,
              cursor: "not-allowed",
            }}
          >
            re-run (pending)
          </button>
        }
      >
        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            columnGap: 18,
            rowGap: 0,
            marginBottom: 10,
          }}
        >
          <BriefRow label="path on worker host">
            {crash.reproducer_path ?? "--"}
          </BriefRow>
          <BriefRow label="size">
            {crash.reproducer_size_bytes != null
              ? `${crash.reproducer_size_bytes.toLocaleString()} bytes`
              : "--"}
          </BriefRow>
        </div>
        <HexView
          data={crash.reproducer_head_hex ?? null}
          filename={crash.reproducer_path?.split(/[\\/]/).pop() ?? null}
        />
      </WindowPanel>

      {/* Stack trace / ASAN excerpt -- mono pre */}
      <WindowPanel title="stack trace" tone="warn">
        {crash.stack_trace ? (
          <ClickableStackTrace raw={crash.stack_trace} />
        ) : (
          <p
            className="font-mono"
            style={{ margin: 0, fontSize: 11, color: "var(--text-muted)" }}
          >
            no stack trace provided.
          </p>
        )}
      </WindowPanel>

      {/* Linked artefacts */}
      <WindowPanel title="linked artefacts" tone="info">
        <ul
          style={{
            listStyle: "none",
            padding: 0,
            margin: 0,
            display: "flex",
            flexDirection: "column",
            gap: 4,
          }}
        >
          {crash.campaign_id ? (
            <li>
              <Link
                to={`/vr/fuzz/campaigns/${crash.campaign_id}`}
                className="font-mono"
                style={{
                  color: "var(--accent)",
                  fontSize: 11,
                  textDecoration: "none",
                  letterSpacing: "0.04em",
                }}
              >
                \u2190 campaign that found this crash
              </Link>
            </li>
          ) : null}
          {crash.duplicate_of_crash_id ? (
            <li>
              <Link
                to={`/vr/fuzz/crashes/${crash.duplicate_of_crash_id}`}
                className="font-mono"
                style={{
                  color: "var(--accent)",
                  fontSize: 11,
                  textDecoration: "none",
                  letterSpacing: "0.04em",
                }}
              >
                duplicate-of: earlier crash \u2192
              </Link>
            </li>
          ) : null}
          {crash.promoted_to_finding_id ? (
            <li
              className="font-mono"
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                letterSpacing: "0.04em",
              }}
            >
              promoted to finding:{" "}
              <span style={{ color: "var(--text-primary)" }}>
                {crash.promoted_to_finding_id.slice(0, 12)}\u2026
              </span>
            </li>
          ) : null}
          {!crash.campaign_id &&
          !crash.duplicate_of_crash_id &&
          !crash.promoted_to_finding_id ? (
            <li
              className="font-mono"
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                letterSpacing: "0.04em",
              }}
            >
              no cross-references yet.
            </li>
          ) : null}
        </ul>
      </WindowPanel>

      {/* Extra fields JSON (mono pre) */}
      {Object.keys(crash.extra).length > 0 ? (
        <WindowPanel title="extra fields" tone="muted">
          <pre
            className="font-mono"
            style={{
              margin: 0,
              padding: 12,
              fontSize: 11,
              lineHeight: 1.5,
              color: "var(--text-primary)",
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              borderRadius: 3,
              overflow: "auto",
              maxHeight: 400,
              whiteSpace: "pre",
            }}
          >
            {JSON.stringify(crash.extra, null, 2)}
          </pre>
        </WindowPanel>
      ) : null}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// ChainStep -- one numbered mono row inside the triage-chain list.
// ─────────────────────────────────────────────────────────────────────
function ChainStep({
  step,
  tone,
  action,
  meta,
  children,
}: {
  step: number;
  tone: string;
  action: string;
  meta?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <li
      style={{
        border: "1px solid var(--border-faint)",
        borderRadius: 3,
        padding: "8px 10px",
        background: "var(--surface-sunk)",
      }}
    >
      <div
        className="flex items-center"
        style={{ gap: 8, flexWrap: "wrap" }}
      >
        <MonoBadge tone={tone}>step {step}</MonoBadge>
        <span
          className="font-mono"
          style={{
            fontSize: 11,
            color: "var(--text-primary)",
            letterSpacing: "0.04em",
          }}
        >
          {action}
        </span>
        {meta ? (
          <span
            className="flex items-center font-mono"
            style={{
              gap: 8,
              fontSize: 10.5,
              flexWrap: "wrap",
            }}
          >
            {meta}
          </span>
        ) : null}
      </div>
      {children ? (
        <div
          className="font-mono"
          style={{
            marginTop: 6,
            fontSize: 10.5,
            color: "var(--text-muted)",
            lineHeight: 1.55,
            letterSpacing: "0.02em",
          }}
        >
          {children}
        </div>
      ) : null}
    </li>
  );
}

// ─────────────────────────────────────────────────────────────────────
// TriageEventForm -- append a triage event; POST /vr/fuzz/crashes/:id/triage.
// ─────────────────────────────────────────────────────────────────────
function TriageEventForm({ crashId }: { crashId: string }) {
  const [verdict, setVerdict] = useState<CrashTriageVerdict>(
    "needs_manual_review",
  );
  const [reason, setReason] = useState("");
  const [notes, setNotes] = useState("");
  const triageMut = useAppendCrashTriage(crashId);

  const disabled = triageMut.isPending || reason.trim().length === 0;

  return (
    <form
      style={{ display: "flex", flexDirection: "column", gap: 8 }}
      onSubmit={(e) => {
        e.preventDefault();
        if (disabled) return;
        triageMut.mutate(
          {
            at: new Date().toISOString(),
            actor: "operator",
            verdict,
            reason: reason.trim(),
            notes: notes.trim(),
          },
          {
            onSuccess: () => {
              setReason("");
              setNotes("");
            },
          },
        );
      }}
    >
      <div
        className="font-mono uppercase"
        style={{
          fontSize: 10,
          letterSpacing: "0.12em",
          color: "var(--text-primary)",
        }}
      >
        add triage event
      </div>
      <div
        className="flex items-center"
        style={{ gap: 8, flexWrap: "wrap" }}
      >
        <label
          className="font-mono uppercase"
          style={{
            fontSize: 9,
            letterSpacing: "0.14em",
            color: "var(--text-faint)",
          }}
          htmlFor={`triage-verdict-${crashId}`}
        >
          verdict
        </label>
        <select
          id={`triage-verdict-${crashId}`}
          value={verdict}
          onChange={(e) => setVerdict(e.target.value as CrashTriageVerdict)}
          aria-label="Triage verdict"
          className="font-mono"
          style={CTRL}
        >
          {TRIAGE_VERDICT_VALUES.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      </div>
      <textarea
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="Reason (required) -- one-liner justifying the verdict change"
        rows={2}
        aria-label="Triage reason"
        className="font-mono"
        style={{ ...CTRL, width: "100%", resize: "vertical" }}
      />
      <textarea
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        placeholder="Notes (optional) -- free-form context, links, follow-ups"
        rows={2}
        aria-label="Triage notes"
        className="font-mono"
        style={{ ...CTRL, width: "100%", resize: "vertical" }}
      />
      <div
        className="flex items-center"
        style={{
          justifyContent: "space-between",
          gap: 10,
          flexWrap: "wrap",
        }}
      >
        <span
          className="font-mono"
          style={{
            fontSize: 10,
            color: "var(--text-faint)",
            letterSpacing: "0.04em",
          }}
        >
          appends to triage_chain and rewrites triage_verdict/triage_reason to
          the latest.
        </span>
        <button
          type="submit"
          disabled={disabled}
          className="font-mono uppercase"
          style={{
            ...PRIMARY_BTN,
            opacity: disabled ? 0.4 : 1,
            cursor: disabled ? "not-allowed" : "pointer",
          }}
        >
          {triageMut.isPending ? "appending\u2026" : "append event"}
        </button>
      </div>
    </form>
  );
}
