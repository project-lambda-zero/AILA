/**
 * ScheduledReportWizard -- the bespoke create surface for admin scheduled
 * reports (the detail-panel body the `admin:scheduled-reports` DataPage uses
 * lives in ./scheduledReport/ScheduledReportDetail). The scheduled-reports
 * slice owns its whole bespoke frontend across the ./scheduledReport/ files.
 *
 * The wizard opens as a registry window and drives `POST /scheduled-reports`
 * (routers/scheduled_reports.py) over five steps:
 *
 *   1. name the report + pick a report kind from the live catalog
 *      (GET /scheduled-reports/kinds -- today exactly one kind, fleet_health,
 *      but the step renders whatever the registry returns)
 *   2. configure the kind's options (typed form when `config_schema` is
 *      declared, key/value editor otherwise)
 *   3. recipients (one valid email per chip)
 *   4. schedule (shared preset picker + custom-cron + live "next 3 runs" preview)
 *   5. review + submit, then show the created report
 */

import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent, JSX } from "react";

import type { ScheduledReportCreate, ScheduledReportRow } from "../../api/scheduledReports";
import { useCreateScheduledReport, useScheduledReportKinds } from "../../api/scheduledReports";
import type { WindowChromeProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import {
  apiErrMessage,
  fieldCol,
  inputStyle,
  labelStyle,
  SchedulePicker,
  WizardShell,
  cronFromSchedule,
  initialSchedule,
} from "../wizards";
import type { ScheduleState, WizardFieldIssue, WizardStepDef } from "../wizards";
import { nextRuns } from "./cronPreview";
import { KeyvalEditor, KindCatalog, TypedOptionsForm, kvObjectFromRows, optionInitialValue } from "./scheduledReport/fields";
import type { KVRow } from "./scheduledReport/fields";
import { RecipientsEditor } from "./scheduledReport/RecipientsEditor";
import { CreatedPanel, ReportReview } from "./scheduledReport/review";

/* -------------------------------------------------------------------------- *
 * step chrome -- the five steps as WizardStepDefs the shared WizardShell reads
 * for its `step N of M` strip, purpose line, and progress segments.
 * -------------------------------------------------------------------------- */

const WIZARD_STEPS: WizardStepDef[] = [
  { id: "kind", title: "pick kind", purpose: "name the report and choose which report kind it generates." },
  { id: "options", title: "options", purpose: "configure the kind's options; kinds without declared options take a raw key/value editor." },
  { id: "recipients", title: "recipients", purpose: "recipients receive the generated report on every fire -- one valid email per chip." },
  { id: "schedule", title: "set schedule", purpose: "choose when it fires -- a preset or a raw cron, in utc; the server validates on submit." },
  { id: "review", title: "review", purpose: "confirm the report, then submit it to the scheduler." },
];

export default function ScheduledReportWizard(props: WindowChromeProps): JSX.Element {
  const {
    onBack,
    onMinimize,
    isFullscreen,
    onToggleFullscreen,
    windowId,
    title: windowTitle,
    isFocused,
    onFocus,
  } = props;

  const kindsQ = useScheduledReportKinds();
  const createReport = useCreateScheduledReport();

  const kindsRows = kindsQ.data ?? [];
  const kindsErr = kindsQ.error ? apiErrMessage(kindsQ.error) : null;

  const [step, setStep] = useState<number>(1);
  const [name, setName] = useState<string>("");
  const [reportType, setReportType] = useState<string>("");
  const [typedOptions, setTypedOptions] = useState<Record<string, string | boolean>>({});
  const [kvRows, setKvRows] = useState<KVRow[]>([]);
  const [recipients, setRecipients] = useState<string[]>([]);
  const [schedule, setSchedule] = useState<ScheduleState>(initialSchedule);
  const [isActive, setIsActive] = useState<boolean>(true);
  const [created, setCreated] = useState<ScheduledReportRow | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedKind = useMemo(
    () => kindsRows.find((k) => k.report_type === reportType) ?? null,
    [kindsRows, reportType],
  );

  // Seed the typed options from the selected kind's schema (defaults / first
  // option) and reset the key/value rows whenever the kind changes, so option
  // values from kind A never leak into a POST for kind B.
  useEffect(() => {
    const schema = selectedKind?.config_schema ?? [];
    const next: Record<string, string | boolean> = {};
    for (const opt of schema) next[opt.key] = optionInitialValue(opt);
    setTypedOptions(next);
    setKvRows([]);
  }, [selectedKind]);

  const cronExpr = cronFromSchedule(schedule);
  const cronRuns = nextRuns(cronExpr, 3);

  // Per-step validation as the WizardShell contract wants it: an empty list
  // enables the shell's primary control; a non-empty list disables it AND the
  // shell renders each issue by label + reason (no silent disables).
  const stepIssues = (n: number): WizardFieldIssue[] => {
    if (n === 1) {
      const out: WizardFieldIssue[] = [];
      if (name.trim() === "") out.push({ label: "report name", reason: "required" });
      if (kindsQ.isLoading) out.push({ label: "report kinds", reason: "loading catalog" });
      if (reportType.trim() === "") out.push({ label: "report kind", reason: "pick one to continue" });
      return out;
    }
    if (n === 2 && selectedKind && selectedKind.config_schema.length > 0) {
      const out: WizardFieldIssue[] = [];
      for (const opt of selectedKind.config_schema) {
        if (!opt.required) continue;
        const cur = typedOptions[opt.key];
        if (cur === undefined || String(cur).trim() === "") {
          out.push({ label: opt.label, reason: "required" });
        }
      }
      return out;
    }
    if (n === 3) {
      return recipients.length === 0
        ? [{ label: "recipients", reason: "add at least one email" }]
        : [];
    }
    if (n === 4) {
      if (cronExpr.trim() === "") {
        return [{ label: "schedule", reason: "invalid cron or no fire time in the horizon" }];
      }
      if (nextRuns(cronExpr, 1).length === 0) {
        return [{ label: "schedule", reason: "invalid cron or no fire time in the horizon" }];
      }
      return [];
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

  const configForSubmit = useMemo<Record<string, unknown>>(() => {
    if (selectedKind && selectedKind.config_schema.length > 0) {
      const out: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(typedOptions)) out[key] = val;
      return out;
    }
    return kvObjectFromRows(kvRows);
  }, [selectedKind, typedOptions, kvRows]);

  const canSubmit =
    step === 5 &&
    !created &&
    !createReport.isPending &&
    name.trim() !== "" &&
    reportType.trim() !== "" &&
    cronExpr.trim() !== "" &&
    recipients.length > 0;

  async function onSubmit(): Promise<void> {
    if (!canSubmit) return;
    setError(null);
    const body: ScheduledReportCreate = {
      name: name.trim(),
      report_type: reportType.trim(),
      cron_expression: cronExpr.trim(),
      recipient_emails_json: JSON.stringify(recipients),
      config_json: JSON.stringify(configForSubmit),
      is_active: isActive,
    };
    try {
      const result = await createReport.mutateAsync(body);
      setCreated(result);
    } catch (err) {
      setError(apiErrMessage(err));
    }
  }

  /* ---- per-step body ---------------------------------------------------- */

  const step1 = (
    <div style={css("display:flex;flex-direction:column;gap:12px;")}>
      <label style={fieldCol}>
        <span style={labelStyle}>report name</span>
        <input
          style={inputStyle}
          value={name}
          placeholder="fleet weekly summary"
          onChange={(e: ChangeEvent<HTMLInputElement>): void => setName(e.target.value)}
        />
      </label>
      <KindCatalog
        kinds={kindsRows}
        loading={kindsQ.isLoading}
        error={kindsErr}
        selectedType={reportType}
        onPick={(t) => setReportType(t)}
      />
    </div>
  );

  const step2 = selectedKind && selectedKind.config_schema.length > 0 ? (
    <TypedOptionsForm
      schema={selectedKind.config_schema}
      values={typedOptions}
      onChange={(key, value) => setTypedOptions((s) => ({ ...s, [key]: value }))}
    />
  ) : (
    <KeyvalEditor rows={kvRows} onChange={setKvRows} />
  );

  const step3 = (
    <RecipientsEditor recipients={recipients} onChange={setRecipients} />
  );

  const step4 = (
    <SchedulePicker st={schedule} onChange={(patch) => setSchedule((s) => ({ ...s, ...patch }))} />
  );

  const step5 = (
    <ReportReview
      name={name}
      selectedKind={selectedKind}
      typedOptions={typedOptions}
      kvRows={kvRows}
      recipients={recipients}
      cronExpr={cronExpr}
      cronRuns={cronRuns}
      isActive={isActive}
      onToggleActive={setIsActive}
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
        {"admin \u00b7 new scheduled report"}
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
        POST /scheduled-reports
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
          <CreatedPanel created={created} recipients={recipients} />
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
              heading="new scheduled report"
              steps={WIZARD_STEPS}
              current={step - 1}
              issues={issues}
              onBack={goBack}
              onNext={goNext}
              onFinish={(): void => void onSubmit()}
              finishLabel="create report"
              busy={createReport.isPending}
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
