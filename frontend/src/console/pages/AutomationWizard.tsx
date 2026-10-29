/**
 * AutomationWizard -- the bespoke create surface for admin automation
 * schedules (the action-catalog detail body lives in
 * ./automation/AutomationActionDetail). Opens as a registry window
 * (`admin:new-automation`) from the "+" button on the `admin:automation` list
 * and from the "schedule this action" button on the `admin:automation-actions`
 * catalog detail. Drives `POST /automation/schedules` (routers/automation.py)
 * over five steps:
 *
 *   1. pick an action from the live registry, grouped by module
 *   2. pick a target from the caller's own systems (/systems)
 *   3. schedule (shared preset picker + custom-cron + "next 3 runs" preview)
 *   4. arguments (typed form when the action's `param_schema` declares
 *      `properties`; keyval fallback otherwise -- today every action
 *      returns null and the fallback is what the operator sees)
 *   5. review + submit, then show the created schedule
 *
 * `investigationId` (the shell's generic prefill slot) carries an optional
 * pre-selected `action_id`: when set, step 1 is pre-filled and the wizard
 * opens on step 2. Every field maps 1:1 to the AutomationScheduleCreate
 * contract; there is no fabricated payload.
 */

import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent, JSX } from "react";

import type {
  AutomationSchedule,
  AutomationScheduleCreate,
} from "../../api/automation";
import { useAutomationActions, useCreateAutomationSchedule } from "../../api/automation";
import { useSystems } from "../../api/systems";
import type { EntityBindingProps, WindowChromeProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import {
  apiErrMessage,
  fieldCol,
  helpText,
  labelStyle,
  SchedulePicker,
  selectStyle,
  WizardShell,
  cronFromSchedule,
  initialSchedule,
} from "../wizards";
import type { ScheduleState, WizardFieldIssue, WizardStepDef } from "../wizards";
import { ActionCatalog } from "./automation/ActionCatalog";
import { KeyvalEditor, TypedArgsForm, kvRowsToKwargs, parseParamSchema } from "./automation/args";
import type { KVRow } from "./automation/args";
import { CreatedSchedulePanel, ScheduleReview } from "./automation/review";
import { nextRuns } from "./cronPreview";

/* -------------------------------------------------------------------------- *
 * step chrome -- the five steps as WizardStepDefs the shared WizardShell reads
 * for its `step N of M` strip, purpose line, and progress segments.
 * -------------------------------------------------------------------------- */

const WIZARD_STEPS: WizardStepDef[] = [
  { id: "action", title: "pick action", purpose: "choose a platform-registered operation to schedule." },
  { id: "target", title: "pick target", purpose: "bind the action to one of your registered systems." },
  { id: "schedule", title: "set schedule", purpose: "choose when it fires -- a preset or a raw cron, in utc." },
  { id: "arguments", title: "arguments", purpose: "supply the action's parameters; typed when it declares a schema." },
  { id: "review", title: "review", purpose: "confirm the schedule, then submit it to the automation runner." },
];

export default function AutomationWizard(props: WindowChromeProps & EntityBindingProps): JSX.Element {
  const {
    investigationId,
    onBack,
    onMinimize,
    isFullscreen,
    onToggleFullscreen,
    windowId,
    title: windowTitle,
    isFocused,
    onFocus,
  } = props;

  const prefillActionId = (investigationId ?? "").trim();

  const actionsQ = useAutomationActions();
  const systemsQ = useSystems(1, 200);
  const createSchedule = useCreateAutomationSchedule();

  const actionRows = actionsQ.data ?? [];
  const systemRows = systemsQ.data?.items ?? [];

  const [step, setStep] = useState<number>(prefillActionId ? 2 : 1);
  const [actionId, setActionId] = useState<string>(prefillActionId);
  const [targetName, setTargetName] = useState<string>("");
  const [enabled, setEnabled] = useState<boolean>(true);
  const [schedule, setSchedule] = useState<ScheduleState>(initialSchedule);
  const [typedArgs, setTypedArgs] = useState<Record<string, unknown>>({});
  const [kvRows, setKvRows] = useState<KVRow[]>([]);
  const [created, setCreated] = useState<AutomationSchedule | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedAction = useMemo(
    () => actionRows.find((a) => a.action_id === actionId) ?? null,
    [actionRows, actionId],
  );
  const parsedSchema = useMemo(
    () => parseParamSchema(selectedAction?.param_schema ?? null),
    [selectedAction],
  );

  // Reset typed-args + kv rows when the operator switches action, so a schema
  // shape from action A never leaks into a POST for action B.
  useEffect(() => {
    setTypedArgs({});
    setKvRows([]);
  }, [actionId]);

  // The system picker defaults to the first row once the fetch lands, so
  // step 2 has a sensible pre-filled value the operator can override.
  useEffect(() => {
    if (targetName === "" && systemRows.length > 0) {
      setTargetName(systemRows[0].name);
    }
  }, [systemRows, targetName]);

  const cronExpr = cronFromSchedule(schedule);
  const cronRuns = nextRuns(cronExpr, 3);

  // Per-step validation as the WizardShell contract wants it: an empty list
  // enables the shell's primary control; a non-empty list disables it AND the
  // shell renders each issue by label + reason (no silent disables).
  const stepIssues = (n: number): WizardFieldIssue[] => {
    if (n === 1) {
      return actionId.trim() === ""
        ? [{ label: "action", reason: "pick one from the catalog" }]
        : [];
    }
    if (n === 2) {
      return targetName.trim() === ""
        ? [{ label: "target system", reason: "pick a registered system" }]
        : [];
    }
    if (n === 3) {
      if (cronExpr.trim() === "") return [{ label: "schedule", reason: "choose a preset or type a custom cron" }];
      if (cronRuns.length === 0) {
        return [{ label: "schedule", reason: "no fire time in the next 370 days; adjust the expression" }];
      }
      return [];
    }
    if (n === 4 && parsedSchema) {
      const out: WizardFieldIssue[] = [];
      for (const req of parsedSchema.required) {
        const cur = typedArgs[req];
        if (cur === undefined || cur === null || String(cur).trim() === "") {
          out.push({ label: `argument \`${req}\``, reason: "required" });
        }
      }
      return out;
    }
    return [];
  };

  const issues = stepIssues(step);
  const canAdvance = issues.length === 0;

  const goNext = (): void => {
    if (!canAdvance) return;
    setStep(Math.min(step + 1, 5));
  };
  const goBack = (): void => setStep(Math.max(step - 1, 1));

  const kwargsForSubmit = useMemo<Record<string, unknown>>(() => {
    if (parsedSchema) {
      const out: Record<string, unknown> = {};
      for (const [name, spec] of parsedSchema.props) {
        const cur = typedArgs[name];
        const val = cur === undefined ? spec.default : cur;
        if (val === undefined) continue;
        out[name] = val;
      }
      return out;
    }
    return kvRowsToKwargs(kvRows);
  }, [parsedSchema, typedArgs, kvRows]);

  const canSubmit =
    step === 5 &&
    !created &&
    !createSchedule.isPending &&
    actionId.trim() !== "" &&
    targetName.trim() !== "" &&
    cronExpr.trim() !== "";

  async function onSubmit(): Promise<void> {
    if (!canSubmit) return;
    setError(null);
    const body: AutomationScheduleCreate = {
      action_id: actionId.trim(),
      target_name: targetName.trim(),
      cron_expression: cronExpr.trim(),
      enabled,
    };
    if (Object.keys(kwargsForSubmit).length > 0) {
      body.action_kwargs = kwargsForSubmit;
    }
    try {
      const result = await createSchedule.mutateAsync(body);
      setCreated(result);
    } catch (err) {
      setError(apiErrMessage(err));
    }
  }

  /* ---- per-step body ---------------------------------------------------- */

  const step1 = (
    <ActionCatalog
      actions={actionRows}
      loading={actionsQ.isLoading}
      selectedId={actionId}
      onPick={(id) => setActionId(id)}
    />
  );

  const step2 = (() => {
    if (systemsQ.isLoading) {
      return <span style={css("font-size:11px;color:var(--text-faint);")}>{"loading systems\u2026"}</span>;
    }
    if (systemRows.length === 0) {
      return (
        <span style={css("font-size:11px;color:var(--status-warn);")}>
          {"no systems registered -- add one from admin \u00b7 systems first, then return here."}
        </span>
      );
    }
    return (
      <div style={css("display:flex;flex-direction:column;gap:12px;")}>
        <p style={helpText}>
          {"the target is the system the action runs against. picking a row fills `target_name` with that system's registered name so the server-side ownership check succeeds; the server rejects unowned names with 403."}
        </p>
        <label style={fieldCol}>
          <span style={labelStyle}>target system</span>
          <select
            value={targetName}
            onChange={(e: ChangeEvent<HTMLSelectElement>): void => setTargetName(e.target.value)}
            style={selectStyle}
          >
            {systemRows.map((s) => (
              <option key={s.id} value={s.name}>
                {`${s.name} \u2014 ${s.host}${s.distro ? ` (${s.distro})` : ""}`}
              </option>
            ))}
          </select>
        </label>
      </div>
    );
  })();

  const step3 = (
    <SchedulePicker
      st={schedule}
      onChange={(patch) => setSchedule((s) => ({ ...s, ...patch }))}
    />
  );

  const step4 = parsedSchema ? (
    <TypedArgsForm
      schema={parsedSchema}
      values={typedArgs}
      onChange={(name, value) => setTypedArgs((s) => ({ ...s, [name]: value }))}
    />
  ) : (
    <KeyvalEditor rows={kvRows} onChange={setKvRows} />
  );

  const kwargsPreview = Object.keys(kwargsForSubmit).length > 0
    ? JSON.stringify(kwargsForSubmit, null, 2)
    : "(none)";

  const step5 = (
    <ScheduleReview
      actionId={actionId}
      selectedAction={selectedAction}
      targetName={targetName}
      cronExpr={cronExpr}
      cronRuns={cronRuns}
      kwargsPreview={kwargsPreview}
      enabled={enabled}
      onToggleEnabled={setEnabled}
    />
  );

  const stepBodies = [step1, step2, step3, step4, step5];

  /* ---- render ----------------------------------------------------------- */

  const statusStrip = (
    <>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          background: "var(--accent)",
          color: "var(--text-on-accent)",
          fontWeight: 700,
          letterSpacing: "0.14em",
        }}
      >
        {"admin \u00b7 new automation"}
      </span>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          textTransform: "none",
          letterSpacing: "0.03em",
          color: "var(--text-muted)",
        }}
      >
        POST /automation/schedules
      </span>
      <span style={{ flex: 1 }} />
    </>
  );

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={windowTitle}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
      footerExtras={statusStrip}
    >
      {created ? (
        <main
          style={{
            flex: 1,
            minHeight: 0,
            display: "flex",
            flexDirection: "column",
            gap: 14,
            overflow: "auto",
            padding: 18,
          }}
        >
          <CreatedSchedulePanel created={created} />
          <div>
            <button
              type="button"
              onClick={onBack}
              style={css(
                "padding:0 14px;height:30px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-muted);background:transparent;border:1px solid var(--border-soft);border-radius:2px;cursor:pointer;",
              )}
            >
              close
            </button>
          </div>
        </main>
      ) : (
        <main style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
          <div style={{ flex: 1, minHeight: 0 }}>
            <WizardShell
              heading="new automation"
              steps={WIZARD_STEPS}
              current={step - 1}
              issues={issues}
              onBack={goBack}
              onNext={goNext}
              onFinish={(): void => void onSubmit()}
              finishLabel="create schedule"
              busy={createSchedule.isPending}
              error={error}
              onRetry={(): void => void onSubmit()}
            >
              {stepBodies[step - 1]}
            </WizardShell>
          </div>
        </main>
      )}
    </ConsoleWindow>
  );
}
