/** OnboardingWizard -- first-run platform onboarding (#246).
 *
 * Renders GET /config/platform/schema grouped by category, one step per
 * category plus a finish step. Every writable entry round-trips through
 * PUT /config/platform/<key>; the schema is refetched after each write so the
 * control always shows the value ConfigRegistry resolves (env > db > default).
 * Copy comes from the backend descriptions (PlatformConfigSchema field
 * metadata); nothing here re-authors it. Finishing writes
 * onboarding_completed=true so the console stops auto-opening the wizard. */

import { useState } from "react";
import type { CSSProperties, JSX } from "react";

import type { OnboardingCategory, OnboardingEntry } from "../../api/onboarding";
import { isTruthyConfig, usePlatformSchema, useSetPlatformConfig } from "../../api/onboarding";
import { apiErrDetail } from "../../api/parse";
import { useSandboxProbe } from "../../api/sandbox";
import { useAuth } from "../../api/auth";
import type { PageOpenerProps, WindowChromeProps } from "../contract";
import { css } from "../css";
import { toast } from "../toast";
import { ConsoleWindow } from "../window";
import { WizardShell } from "./WizardShell";
import type { WizardStepDef } from "./types";

const CATEGORY_STEPS = [
  {
    id: "capability",
    title: "capabilities",
    purpose: "Opt-in features. Each is inert until enabled and takes effect on the next turn or request.",
  },
  {
    id: "infra",
    title: "infrastructure",
    purpose: "Features that need a sandbox host, an optional package, or an external API key.",
  },
  {
    id: "operational",
    title: "operational posture",
    purpose: "Runtime posture switches, shown read-only. Change them on the admin config page.",
  },
] satisfies (WizardStepDef & { id: OnboardingCategory })[];

const STEPS: WizardStepDef[] = [
  ...CATEGORY_STEPS,
  { id: "finish", title: "finish", purpose: "Mark onboarding complete. You can reopen this wizard from settings." },
];

const SOURCE_LABEL = {
  env: "environment",
  db: "stored config",
  default: "schema default",
} satisfies Record<OnboardingEntry["effectiveSource"], string>;

const cardStyle = css(
  "border:1px solid var(--border-soft);background:var(--surface-card);border-radius:3px;padding:12px 14px;display:flex;flex-direction:column;gap:8px;",
);
const keyStyle = css("font-size:12px;color:var(--text-primary);letter-spacing:0.02em;");
const metaStyle = css("font-size:11px;color:var(--text-muted);letter-spacing:0.02em;");
const descStyle = css("font-size:11.5px;color:var(--text-faint);line-height:1.45;white-space:pre-line;text-transform:none;");
const linkBtnStyle = css(
  "align-self:flex-start;min-height:28px;padding:0;font-family:var(--font-mono);font-size:11px;color:var(--accent);background:transparent;border:0;cursor:pointer;",
);
const controlRowStyle = css("display:flex;align-items:center;gap:8px;flex-wrap:wrap;");
const inputStyle = css(
  "height:30px;min-width:220px;padding:0 9px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;",
);

function buttonStyle(enabled: boolean, tone: "accent" | "muted"): CSSProperties {
  const color = tone === "accent" ? "var(--accent)" : "var(--text-muted)";
  return css(
    `height:30px;padding:0 12px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;background:transparent;border:1px solid ${enabled ? color : "var(--border-soft)"};color:${enabled ? color : "var(--text-faint)"};border-radius:2px;cursor:${enabled ? "pointer" : "not-allowed"};`,
  );
}

function notice(tone: "ok" | "warn"): CSSProperties {
  const color = tone === "ok" ? "var(--status-ok)" : "var(--status-warn)";
  return css(
    `font-size:11px;line-height:1.4;padding:7px 9px;border-left:2px solid ${color};background:color-mix(in srgb,${color} 8%,transparent);color:var(--text-primary);text-transform:none;`,
  );
}

function SandboxProbeControl(): JSX.Element {
  const probe = useSandboxProbe();
  return (
    <div style={controlRowStyle}>
      <button
        type="button"
        disabled={probe.isPending}
        onClick={() => probe.mutate(undefined, { onError: (e) => toast.error(`sandbox probe failed: ${apiErrDetail(e)}`) })}
        style={buttonStyle(!probe.isPending, "muted")}
      >
        {probe.isPending ? "probing\u2026" : "probe sandbox host"}
      </button>
      {probe.data ? (
        <span style={metaStyle}>
          {probe.data.ok ? "\u2713 " : "\u2717 "}
          {probe.data.detail} ({probe.data.duration_ms} ms)
        </span>
      ) : null}
    </div>
  );
}

function EntryCard(props: { entry: OnboardingEntry; onOpenSandbox: () => void }): JSX.Element {
  const { entry, onOpenSandbox } = props;
  const write = useSetPlatformConfig();
  const [expanded, setExpanded] = useState(false);
  const [secretDraft, setSecretDraft] = useState("");

  const description = entry.description.replace(/``/g, "");
  const [summary] = description.split("\n\n");
  const hasMore = summary.length < description.length;
  const enabled = entry.valueType === "bool" && isTruthyConfig(entry.effectiveValue);
  const prereqBlocksEnable = entry.prerequisite !== null && !entry.prerequisite.ok;
  const isSandboxEntry = entry.key === "sandbox_backend" || entry.key === "dynamic_execution_enabled";

  const submit = (value: string, label: string): void => {
    write.mutate(
      { key: entry.key, value, valueType: entry.valueType },
      {
        onSuccess: (res) => {
          if (res.overriddenByEnv) {
            toast.info(`${entry.key} stored, but ${res.envKey} pins the live value`);
          } else {
            toast.success(`${entry.key} ${label}`);
          }
        },
        onError: (e) => toast.error(`${entry.key} update failed: ${apiErrDetail(e)}`),
      },
    );
  };

  const valueText = entry.secret
    ? entry.isSet
      ? "set"
      : "not set"
    : entry.effectiveValue === ""
      ? "(empty)"
      : entry.effectiveValue ?? "";

  let control: JSX.Element | null = null;
  if (entry.readOnly) {
    control = <span style={metaStyle}>read-only here; change it on the admin config page</span>;
  } else if (entry.secret) {
    control = (
      <div style={controlRowStyle}>
        <input
          type="password"
          autoComplete="new-password"
          aria-label={`${entry.key} value`}
          placeholder={entry.isSet ? "enter a new key to replace" : "enter key"}
          value={secretDraft}
          onChange={(e) => setSecretDraft(e.target.value)}
          style={inputStyle}
        />
        <button
          type="button"
          disabled={write.isPending || secretDraft.trim() === ""}
          onClick={() => {
            submit(secretDraft.trim(), "saved");
            setSecretDraft("");
          }}
          style={buttonStyle(!write.isPending && secretDraft.trim() !== "", "accent")}
        >
          {write.isPending ? "saving\u2026" : "save"}
        </button>
        {entry.isSet ? (
          <button
            type="button"
            disabled={write.isPending}
            onClick={() => submit("", "cleared")}
            style={buttonStyle(!write.isPending, "muted")}
          >
            clear
          </button>
        ) : null}
      </div>
    );
  } else if (entry.choices !== null) {
    control = (
      <div style={controlRowStyle}>
        <select
          aria-label={entry.key}
          value={entry.effectiveValue ?? ""}
          disabled={write.isPending}
          onChange={(e) => submit(e.target.value, `set to ${e.target.value}`)}
          style={inputStyle}
        >
          {entry.choices.map((choice) => (
            <option key={choice} value={choice}>
              {choice}
            </option>
          ))}
        </select>
        {write.isPending ? <span style={metaStyle}>saving{"\u2026"}</span> : null}
      </div>
    );
  } else if (entry.valueType === "bool") {
    const canToggle = !write.isPending && (enabled || !prereqBlocksEnable);
    control = (
      <div style={controlRowStyle}>
        <button
          type="button"
          disabled={!canToggle}
          onClick={() => submit(enabled ? "false" : "true", enabled ? "disabled" : "enabled")}
          style={buttonStyle(canToggle, enabled ? "muted" : "accent")}
        >
          {write.isPending ? "saving\u2026" : enabled ? "disable" : "enable"}
        </button>
        {!enabled && prereqBlocksEnable ? (
          <span style={metaStyle}>enable is blocked until the prerequisite below is met</span>
        ) : null}
      </div>
    );
  }

  return (
    <div style={cardStyle}>
      <div style={css("display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;")}>
        <span style={keyStyle}>{entry.key}</span>
        <span style={css(`font-size:11px;color:${enabled ? "var(--status-ok)" : "var(--text-muted)"};`)}>{valueText}</span>
        <span style={metaStyle}>
          {"via "}
          {SOURCE_LABEL[entry.effectiveSource]}
          {entry.secret || entry.defaultValue === null ? "" : ` \u00b7 default ${entry.defaultValue || "(empty)"}`}
        </span>
      </div>
      <div style={descStyle}>{expanded ? description : summary}</div>
      {hasMore ? (
        <button type="button" onClick={() => setExpanded((v) => !v)} style={linkBtnStyle}>
          {expanded ? "show less" : "show full description"}
        </button>
      ) : null}
      {entry.overriddenByEnv ? (
        <div style={notice("warn")}>
          {`${entry.envKey} is set in the environment and pins the live value. A change here is stored but stays inactive until that variable is removed.`}
        </div>
      ) : null}
      {entry.prerequisite ? (
        <div style={notice(entry.prerequisite.ok ? "ok" : "warn")}>
          {entry.prerequisite.ok ? "\u2713 " : "\u2717 "}
          {`${entry.prerequisite.name}: ${entry.prerequisite.detail}`}
        </div>
      ) : null}
      {control}
      {isSandboxEntry ? (
        <div style={controlRowStyle}>
          <SandboxProbeControl />
          <button type="button" onClick={onOpenSandbox} style={buttonStyle(true, "muted")}>
            open sandbox page
          </button>
        </div>
      ) : null}
    </div>
  );
}

export default function OnboardingWizard(props: WindowChromeProps & PageOpenerProps): JSX.Element {
  const { windowId, title, isFullscreen, isFocused, onFocus, onBack, onMinimize, onToggleFullscreen, onOpenPage } = props;
  const isGodTier = useAuth((s) => s.user?.role === "admin" && !s.user?.team_id);
  const schemaQ = usePlatformSchema(isGodTier);
  const finish = useSetPlatformConfig();
  const [step, setStep] = useState(0);

  const onFinish = (): void => {
    finish.mutate(
      { key: "onboarding_completed", value: "true", valueType: "bool" },
      {
        onSuccess: () => {
          toast.success("platform onboarding complete");
          onBack();
        },
        onError: (e) => toast.error(`finishing onboarding failed: ${apiErrDetail(e)}`),
      },
    );
  };

  let body: JSX.Element;
  if (!isGodTier) {
    body = <span style={metaStyle}>Platform onboarding is restricted to god-tier administrators.</span>;
  } else if (schemaQ.isPending) {
    body = <span style={metaStyle}>loading platform configuration{"\u2026"}</span>;
  } else if (schemaQ.isError) {
    body = (
      <div style={controlRowStyle}>
        <span style={notice("warn")}>{`could not load the platform schema: ${apiErrDetail(schemaQ.error)}`}</span>
        <button type="button" onClick={() => void schemaQ.refetch()} style={buttonStyle(true, "accent")}>
          retry
        </button>
      </div>
    );
  } else {
    const category = CATEGORY_STEPS[step]?.id;
    if (category === undefined) {
      const enabledCount = schemaQ.data.entries.filter(
        (e) => !e.readOnly && e.valueType === "bool" && isTruthyConfig(e.effectiveValue),
      ).length;
      body = (
        <div style={css("display:flex;flex-direction:column;gap:10px;")}>
          <span style={metaStyle}>
            {`${enabledCount} opt-in switch${enabledCount === 1 ? " is" : "es are"} on. Finishing records onboarding as complete; reopen this wizard any time from settings or the admin platform menu.`}
          </span>
          {schemaQ.data.onboardingCompleted ? <span style={notice("ok")}>Onboarding was already completed.</span> : null}
        </div>
      );
    } else {
      const entries = schemaQ.data.entries.filter((e) => e.category === category);
      body = (
        <div style={css("display:flex;flex-direction:column;gap:10px;")}>
          {entries.map((entry) => (
            <EntryCard
              key={entry.key}
              entry={entry}
              onOpenSandbox={() => onOpenPage?.("admin", "sandbox", "sandbox")}
            />
          ))}
        </div>
      );
    }
  }

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={title}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
    >
      <main style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
        <WizardShell
          heading="platform onboarding"
          steps={STEPS}
          current={step}
          issues={[]}
          onBack={() => setStep((s) => Math.max(0, s - 1))}
          onNext={() => setStep((s) => Math.min(STEPS.length - 1, s + 1))}
          onFinish={onFinish}
          finishLabel="finish onboarding"
          busy={finish.isPending}
          showPrimary={isGodTier && schemaQ.isSuccess}
        >
          {body}
        </WizardShell>
      </main>
    </ConsoleWindow>
  );
}
