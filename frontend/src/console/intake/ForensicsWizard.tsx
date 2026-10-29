/** The forensics intake flow: configure -> readiness -> confirm. The backend
 * creates the project and runs a real readiness check before the confirm
 * summary; the operator never opens a case the backend did not clear. */

import { useEffect, useState } from "react";
import type { JSX } from "react";

import type { ApiError } from "../../api/client";
import { apiFetch } from "../../api/client";
import type { IntakeWizardProps } from "../contract";
import { css } from "../css";
import { WizardShell } from "../wizards";
import type { WizardFieldIssue, WizardStepDef } from "../wizards";
import type { ForensicsCfg } from "./config";
import { INTAKE } from "./config";

export function ForensicsWizard({ onBind }: { onBind: IntakeWizardProps["onBind"] }): JSX.Element {
  const cfg: ForensicsCfg = INTAKE.forensics;

  const [step, setStep] = useState<number>(0);
  const [kind, setKind] = useState<string | null>("disk_evidence");
  const [desc, setDesc] = useState<Record<string, string>>({ analyzer_os: "linux" });

  // Real system registry rows for the analyzer select, plus the live create +
  // readiness-check result. `fxBusy` gates the launch button; the readiness
  // stages come from the backend result, not a local animation.
  const [fxSystems, setFxSystems] = useState<Array<{ id: number; name: string; host: string; distro: string }>>([]);
  const [fxBusy, setFxBusy] = useState<boolean>(false);
  const [fxProjectId, setFxProjectId] = useState<string | null>(null);
  const [fxResult, setFxResult] = useState<{
    ready: boolean;
    system_name: string;
    analyzer_os: string;
    tools: Array<{ tool_name: string; required: boolean; status: string; version: string | null; message: string | null }>;
    message: string;
  } | null>(null);
  const [fxError, setFxError] = useState<string | null>(null);

  // The analyzer select needs real registered systems (the backend requires a
  // numeric system_id, not a display label). Fetch once on mount.
  useEffect(() => {
    let live = true;
    apiFetch<{ items?: Array<{ id: number; name: string; host: string; distro: string }> }>("/systems?page_size=100")
      .then((data) => {
        if (live) setFxSystems(data.items ?? []);
      })
      .catch(() => {
        if (live) setFxSystems([]);
      });
    return () => {
      live = false;
    };
  }, []);

  const setDescField = (name: string, value: string): void => {
    setDesc((d) => ({ ...d, [name]: value }));
  };

  const projectName = desc["project_name"] ?? "";
  const description = desc["description"] ?? "";
  const machineId = desc["analyzer_machine"] ?? "";
  const evdir = desc["evidence_directory"] ?? "";
  const analyzerOs = desc["analyzer_os"] ?? "linux";
  const currentKind = kind ?? "disk_evidence";
  const fxReady = projectName.trim() !== "" && machineId.trim() !== "" && evdir.trim() !== "";

  const activePk = cfg.projectKinds.find((p) => p.k === currentKind) ?? cfg.projectKinds[0];
  const activeOs = cfg.osKinds.find((o) => o.k === analyzerOs) ?? cfg.osKinds[0];

  const onCheck = (): void => {
    if (!fxReady || fxBusy) return;
    const systemId = Number(machineId);
    if (!Number.isFinite(systemId) || systemId <= 0) {
      setFxError("pick an analyzer machine first");
      return;
    }
    setFxBusy(true);
    setFxError(null);
    setStep(1);
    // Real create, then a real readiness check. The readiness stages the
    // wizard used to animate are replaced by the backend's tool checks.
    // apiFetch already strips the {data:...} DataEnvelope, so read the
    // unwrapped object directly -- NOT `.data.id` / `.data`.
    apiFetch<{ id: string; name: string }>("/forensics/projects", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: projectName,
        description,
        system_id: systemId,
        evidence_directory: evdir,
        analyzer_os: analyzerOs,
        project_kind: currentKind,
      }),
    })
      .then(async (created) => {
        const projectId = created.id;
        setFxProjectId(projectId);
        const res = await apiFetch<{
          ready: boolean;
          system_name: string;
          analyzer_os: string;
          tools: Array<{ tool_name: string; required: boolean; status: string; version: string | null; message: string | null }>;
          message: string;
        }>(`/forensics/projects/${projectId}/readiness-check`, { method: "POST" });
        setFxResult(res);
        // AC6: advance to confirm ONLY when the backend confirms the
        // analyzer is ready. A not-ready result keeps the operator on the
        // readiness step with the backend message surfaced as fxError and
        // Retry (WizardShell's error row) re-runs onCheck.
        if (res.ready) {
          setStep(2);
        } else {
          setFxError(res.message || "analyzer not ready");
          setStep(1);
        }
      })
      .catch((err: unknown) => {
        setFxError(
          (err && typeof err === "object" && "message" in err
            ? String(/* SAFETY: err is the mutation rejection, an ApiError with a server message. */ (err as ApiError).message || "").slice(0, 400)
            : "") || "create failed",
        );
        // Stay on the readiness step so the shell's Retry rerun applies
        // without bouncing the operator back to the configure form.
        setStep(1);
      })
      .finally(() => setFxBusy(false));
  };
  const onConfirm = (): void => {
    if (!fxProjectId) return;
    // AC6: never open the case unless the backend confirmed readiness.
    if (fxResult?.ready !== true) return;
    onBind({ id: fxProjectId, title: projectName });
  };

  // Steps + issue lists that drive WizardShell. AC4: any disabled primary
  // is accompanied by a named field+reason list; no silent disables.
  const fxSteps: WizardStepDef[] = [
    { id: "configure", title: "configure evidence", purpose: "pick the analyzer machine, evidence directory, and project kind." },
    { id: "readiness", title: "check analyzer readiness", purpose: "the backend creates the project and confirms every required tool is online." },
    { id: "confirm", title: "confirm + open", purpose: "review the summary and open the case." },
  ];
  const machineNum = Number(machineId);
  const machineIsPositive = machineId.trim() !== "" && Number.isFinite(machineNum) && machineNum > 0;
  const fxIssues: WizardFieldIssue[] = [];
  if (step === 0) {
    if (projectName.trim() === "") fxIssues.push({ label: "project name", reason: "required" });
    if (evdir.trim() === "") fxIssues.push({ label: "evidence directory", reason: "required" });
    if (machineId.trim() === "") {
      fxIssues.push({ label: "analyzer machine", reason: "pick a registered system" });
    } else if (!machineIsPositive) {
      fxIssues.push({ label: "analyzer machine", reason: "must be a positive number" });
    }
  } else if (step === 2 && fxResult?.ready !== true) {
    fxIssues.push({ label: "readiness", reason: "analyzer not ready" });
  }
  const fxCurrent = Math.max(0, Math.min(step, 2));

  return (
    <WizardShell
      heading={cfg.title}
      steps={fxSteps}
      current={fxCurrent}
      issues={fxIssues}
      onBack={(): void => setStep((s) => Math.max(0, s - 1))}
      onNext={onCheck}
      onFinish={onConfirm}
      nextLabel={"create & check \u25b8"}
      finishLabel={"open case \u25b8"}
      busy={fxBusy}
      error={step === 1 ? fxError : null}
      onRetry={onCheck}
      showPrimary={step !== 1}
    >
      {step === 0 && (
        <div style={css("display:flex;flex-direction:column;gap:14px;")}>
          <label style={css("display:flex;flex-direction:column;gap:5px;")}>
            <span style={css("font-size:12px;color:var(--text-primary);font-family:var(--font-sans,system-ui);")}>Project Name</span>
            <input
              value={projectName}
              onChange={(e): void => setDescField("project_name", e.target.value)}
              placeholder="Project name"
              style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:9px 11px;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;border-radius:3px;")}
            />
          </label>
          <label style={css("display:flex;flex-direction:column;gap:5px;")}>
            <span style={css("font-size:12px;color:var(--text-primary);font-family:var(--font-sans,system-ui);")}>Description</span>
            <textarea
              value={description}
              onChange={(e): void => setDescField("description", e.target.value)}
              placeholder={"Brief description of the investigation\u2026"}
              rows={3}
              style={css("resize:none;background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:9px 11px;color:var(--text-primary);font-family:var(--font-sans,system-ui);font-size:12.5px;line-height:1.45;border-radius:3px;")}
            />
          </label>
          <label style={css("display:flex;flex-direction:column;gap:5px;")}>
            <span style={css("font-size:12px;color:var(--text-primary);font-family:var(--font-sans,system-ui);")}>Analyzer Machine</span>
            <select
              value={machineId}
              onChange={(e): void => setDescField("analyzer_machine", e.target.value)}
              style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:9px 11px;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;border-radius:3px;")}
            >
              <option value="">{"Select a system\u2026"}</option>
              {fxSystems.map((s) => (
                <option key={s.id} value={String(s.id)}>{s.name}{" \u00b7 "}{s.distro || s.host}</option>
              ))}
            </select>
            {fxSystems.length === 0 ? (
              <span style={css("font-size:11px;color:var(--text-faint);")}>no systems registered {"\u2014"} add one on the systems page first</span>
            ) : null}
          </label>
          <div>
            <span style={css("font-size:12px;color:var(--text-primary);font-family:var(--font-sans,system-ui);")}>Project Kind</span>
            <div style={css("display:flex;gap:8px;margin-top:6px;")}>
              {cfg.projectKinds.map((p) => {
                const on = currentKind === p.k;
                return (
                  <button
                    key={p.k}
                    type="button"
                    onClick={(): void => setKind(p.k)}
                    style={css(
                      `flex:1;display:flex;flex-direction:column;gap:4px;padding:11px 12px;text-align:left;cursor:pointer;border-radius:3px;border:1px solid ${
                        on ? "var(--accent)" : "var(--border-soft)"
                      };background:${
                        on ? "color-mix(in srgb,var(--accent) 8%,transparent)" : "var(--surface-card)"
                      };`,
                    )}
                  >
                    <span style={css(`font-family:var(--font-sans,system-ui);font-size:13px;color:${on ? "var(--accent)" : "var(--text-primary)"};`)}>{p.l}</span>
                    <span style={css("font-size:11px;color:var(--text-faint);")}>{p.sub}</span>
                  </button>
                );
              })}
            </div>
            <div style={css("margin-top:7px;font-size:11px;line-height:1.5;color:var(--text-muted);")}>
              {activePk?.l ?? ""}: {activePk?.explain ?? ""}
            </div>
          </div>
          <div>
            <span style={css("font-size:12px;color:var(--text-primary);font-family:var(--font-sans,system-ui);")}>Analyzer OS</span>
            <div style={css("display:flex;gap:8px;margin-top:6px;")}>
              {cfg.osKinds.map((o) => {
                const on = analyzerOs === o.k;
                return (
                  <button
                    key={o.k}
                    type="button"
                    onClick={(): void => setDescField("analyzer_os", o.k)}
                    style={css(
                      `flex:1;display:flex;align-items:center;justify-content:center;padding:16px;cursor:pointer;border-radius:3px;border:1px solid ${
                        on ? "var(--accent)" : "var(--border-soft)"
                      };background:${
                        on ? "color-mix(in srgb,var(--accent) 8%,transparent)" : "var(--surface-card)"
                      };color:${on ? "var(--accent)" : "var(--text-muted)"};font-family:var(--font-sans,system-ui);font-size:13px;`,
                    )}
                  >
                    {o.l}
                  </button>
                );
              })}
            </div>
            <div style={css("margin-top:7px;font-size:11px;line-height:1.5;color:var(--text-muted);")}>
              {activeOs?.explain ?? ""}
            </div>
          </div>
          <label style={css("display:flex;flex-direction:column;gap:5px;")}>
            <span style={css("font-size:12px;color:var(--text-primary);font-family:var(--font-sans,system-ui);")}>Evidence Directory</span>
            <input
              value={evdir}
              onChange={(e): void => setDescField("evidence_directory", e.target.value)}
              placeholder="Absolute path on the analyzer"
              style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:9px 11px;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;border-radius:3px;")}
            />
          </label>
        </div>
      )}

      {step === 1 && (
        <div style={css("display:flex;flex-direction:column;gap:9px;")}>
          <div style={css("font-size:11px;color:var(--text-muted);")}>
            {fxBusy ? `creating project + checking readiness on system ${machineId} \u2014 ${evdir}` : ""}
          </div>
          {fxError ? (
            <div style={css("padding:9px 11px;border:1px solid var(--status-err, #d64545);background:color-mix(in srgb,var(--status-err, #d64545) 8%,transparent);border-radius:3px;font-size:11px;color:var(--text-primary);")}>
              {fxError}
            </div>
          ) : null}
        </div>
      )}

      {step === 2 && fxResult && (
        <div style={css("display:flex;flex-direction:column;gap:9px;")}>
          <div style={css(`padding:10px 12px;border:1px solid ${fxResult.ready ? "var(--status-ok)" : "var(--status-err, #d64545)"};background:color-mix(in srgb,${fxResult.ready ? "var(--status-ok)" : "var(--status-err, #d64545)"} 7%,transparent);border-radius:3px;`)}>
            <div style={css(`font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:${fxResult.ready ? "var(--status-ok)" : "var(--status-err, #d64545)"};`)}>
              {fxResult.ready ? "readiness passed \u00b7 case ready" : "readiness failed \u2014 project created, fix the analyzer and re-check"}
            </div>
            <div style={css("margin-top:7px;display:grid;grid-template-columns:96px 1fr;gap:5px 10px;font-size:11px;")}>
              <span style={css("color:var(--text-faint);")}>project</span>
              <span style={css("color:var(--text-primary);")}>{projectName}</span>
              <span style={css("color:var(--text-faint);")}>kind</span>
              <span style={css("color:var(--text-primary);")}>{activePk?.l ?? ""}</span>
              <span style={css("color:var(--text-faint);")}>analyzer</span>
              <span style={css("color:var(--text-primary);")}>
                {fxResult.system_name} {"\u00b7"} {activeOs?.l ?? ""}
              </span>
              <span style={css("color:var(--text-faint);")}>evidence</span>
              <span style={css("color:var(--text-primary);word-break:break-all;")}>{evdir}</span>
            </div>
            {fxResult.message ? (
              <div style={css("margin-top:7px;font-size:11px;color:var(--text-muted);line-height:1.45;")}>{fxResult.message}</div>
            ) : null}
          </div>
          <div style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>tool checks</div>
          {fxResult.tools.map((t) => {
            const ok = t.status === "ok" || t.status === "present" || t.status === "available";
            const stStyle = css(
              `font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:${ok ? "var(--status-ok)" : t.status === "missing" || t.status === "absent" ? "var(--status-err, #d64545)" : "var(--text-muted)"};`,
            );
            return (
              <div key={t.tool_name} style={css("display:flex;align-items:center;gap:10px;padding:9px 11px;border:1px solid var(--border-soft);background:var(--surface-sunk);border-radius:3px;")}>
                <span style={css(`width:9px;height:9px;flex:0 0 auto;border-radius:1px;background:${ok ? "var(--status-ok)" : "var(--status-err, #d64545)"};`)} />
                <span style={css("display:flex;flex-direction:column;flex:1;min-width:0;")}>
                  <span style={css("font-size:11.5px;color:var(--text-primary);")}>{t.tool_name}{t.required ? "" : " (opt)"}</span>
                  <span style={css("font-size:11px;color:var(--text-faint);")}>{t.version || t.message || ""}</span>
                </span>
                <span style={stStyle}>{t.status}</span>
              </div>
            );
          })}
        </div>
      )}
    </WizardShell>
  );
}
