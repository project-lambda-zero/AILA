/** The generic intake flow (vr / malware): kind grid, pick a registered
 * target, review (initial question + investigation kind + auto-pilot +
 * budget), then a staged animation that runs alongside the real
 * POST /{module}/investigations mutation and binds on success. */

import { useEffect, useRef, useState } from "react";
import type { JSX } from "react";

import type { ApiError } from "../../api/client";
import {
  useCreateMalwareInvestigation,
  useCreateVrInvestigation,
  useTargets,
  useWorkspaces,
} from "../../api/intake";
import type {
  MalwareInvestigationKind,
  TargetRow,
  VRInvestigationKind,
} from "../../api/intake";
import type { IntakeWizardProps } from "../contract";
import { css } from "../css";
import { WizardShell } from "../wizards";
import type { WizardFieldIssue, WizardStepDef } from "../wizards";
import type { GenericCfg } from "./config";
import { INTAKE } from "./config";
import { TargetSteps } from "./targetSteps";

export function TargetWizard({
  moduleId,
  onBind,
  onRequestUpload,
  prefill,
}: {
  moduleId: "vr" | "malware";
  onBind: IntakeWizardProps["onBind"];
  onRequestUpload?: IntakeWizardProps["onRequestUpload"];
  prefill?: IntakeWizardProps["prefill"];
}): JSX.Element {
  const cfg: GenericCfg = moduleId === "malware" ? INTAKE.malware : INTAKE.vr;

  const [step, setStep] = useState<number>(0);
  const [kind, setKind] = useState<string | null>(null);
  const [question, setQuestion] = useState<string>("");
  const [invKind, setInvKind] = useState<string>(
    moduleId === "malware" ? "full_analysis" : "discovery",
  );
  const [auto, setAuto] = useState<boolean>(true);
  const [budget, setBudget] = useState<number>(50);
  const [stage, setStage] = useState<number>(-1);

  // Investigation-flow state. Held always so hook order and reconciliation
  // remain stable across module switches.
  const [targetId, setTargetId] = useState<string | null>(null);
  const [targetName, setTargetName] = useState<string>("");
  const [workspaceFilter, setWorkspaceFilter] = useState<string>("");
  const [launchError, setLaunchError] = useState<string | null>(null);

  const workspaces = useWorkspaces(moduleId);
  const targetsQuery = useTargets(moduleId, {
    workspaceId: workspaceFilter || null,
  });

  const createVrInv = useCreateVrInvestigation();
  const createMalInv = useCreateMalwareInvestigation();
  const creating = createVrInv.isPending || createMalInv.isPending;

  // window.setInterval returns a `number` handle in the DOM lib.
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      window.clearInterval(timerRef.current ?? undefined);
    };
  }, []);

  // Preselect a target passed in via `prefill.targetId` once the targets query
  // has loaded and the id matches a row. Best-effort: a miss leaves the picker
  // empty. `kind` also flips to that target's kind so it appears in `matches`.
  const prefillTargetId = prefill?.targetId ?? null;
  useEffect(() => {
    if (!prefillTargetId) return;
    if (targetId === prefillTargetId) return;
    const rows = targetsQuery.data ?? [];
    const hit = rows.find((t) => t.id === prefillTargetId);
    if (!hit) return;
    setTargetId(hit.id);
    setTargetName(hit.display_name);
    setKind(hit.kind);
  }, [prefillTargetId, targetsQuery.data, targetId]);

  const pickKind = (k: string): void => {
    const d = cfg.kinds.find((x) => x.k === k);
    setKind(k);
    setInvKind(
      d?.inv ?? (moduleId === "malware" ? "full_analysis" : "discovery"),
    );
    setTargetId(null);
    setTargetName("");
    setLaunchError(null);
    setStep(1);
  };

  const pickTarget = (t: TargetRow): void => {
    setTargetId(t.id);
    setTargetName(t.display_name);
    setLaunchError(null);
    setStep(2);
  };

  const runStages = (total: number, perStepMs: number, onDone: () => void): void => {
    setStage(0);
    window.clearInterval(timerRef.current ?? undefined);
    let n = 0;
    timerRef.current = window.setInterval(() => {
      n += 1;
      if (n >= total) {
        window.clearInterval(timerRef.current ?? undefined);
        setStage(total);
        onDone();
        return;
      }
      setStage(n);
    }, perStepMs);
  };

  const kd = kind ? cfg.kinds.find((x) => x.k === kind) ?? null : null;
  const hasInv = cfg.invKinds.length > 0;

  // Steps + issue lists that drive WizardShell. Step 1 picks a registered
  // target of the chosen kind; step 3 is the terminal animation that runs
  // alongside the create mutation and hides the shell's primary via
  // showPrimary=false.
  const genSteps: WizardStepDef[] = [
    { id: "kind", title: "pick kind", purpose: "pick what to investigate." },
    { id: "target", title: "pick target", purpose: "pick a registered target of this kind." },
    { id: "review", title: "review + launch", purpose: "name the initial question and configure the run." },
  ];
  const genIssues: WizardFieldIssue[] = [];
  if (step === 0) {
    if (kind === null) genIssues.push({ label: "kind", reason: "pick a kind to continue" });
  } else if (step === 1) {
    if (targetId === null) genIssues.push({ label: "target", reason: "pick a target to investigate" });
  } else if (step === 2) {
    if (targetId === null) genIssues.push({ label: "target", reason: "pick a target first" });
    if (question.trim() === "") genIssues.push({ label: "initial question", reason: "required" });
  }

  const autoStyle = css(
    `display:inline-flex;align-items:center;gap:6px;padding:3px 9px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;border:1px solid ${
      auto ? "var(--accent)" : "var(--border-soft)"
    };color:${auto ? "var(--accent)" : "var(--text-muted)"};background:${
      auto ? "color-mix(in srgb,var(--accent) 12%,transparent)" : "transparent"
    };border-radius:2px;`,
  );

  // Review-step target line: the picked target's real display name (or its id
  // as a fallback before the name resolves).
  const targetLine = targetName || (targetId ? targetId : "no target picked");

  const onLaunch = (): void => {
    // Belt-and-braces: WizardShell already disables the primary via issues +
    // busy, but a stale focused button on the review step should never fire
    // the launch mutation with a missing target / empty question.
    if (targetId === null || question.trim() === "" || creating) return;
    setLaunchError(null);
    setStep(3);
    setStage(0);

    const q = question.trim();
    const kindLabel = kd?.l ?? "target";
    const derivedTitle = (q || `${invKind} \u00b7 ${targetName || kindLabel}`).slice(0, 255);
    const initialQuestion = q || `Investigate ${targetName || kindLabel} (${invKind}).`;

    // Kick the animation and the mutation together. onBind runs when the
    // mutation succeeds (the parent shell closes the wizard and opens the
    // matching X-Ray); onError surfaces the server detail in-place so the
    // operator can adjust and retry without losing collected fields.
    runStages(cfg.stages.length, 900, () => {
      // animation done -- no auto-close; wait for the mutation to resolve.
    });

    if (moduleId === "vr") {
      createVrInv.mutate(
        {
          title: derivedTitle,
          initial_question: initialQuestion,
          target_id: targetId,
          kind: invKind as VRInvestigationKind,
          auto_pilot: auto,
          cost_budget_usd: budget,
        },
        {
          onSuccess: (created) =>
            onBind({ id: created.id, title: created.title }),
          onError: (err) =>
            setLaunchError(
              (err && typeof err === "object" && "message" in err
                ? String(/* SAFETY: err is the mutation rejection, an ApiError with a server message. */ (err as ApiError).message || "").slice(0, 400)
                : "") || "create failed",
            ),
        },
      );
      return;
    }
    // malware
    createMalInv.mutate(
      {
        title: derivedTitle,
        initial_question: initialQuestion,
        target_id: targetId,
        kind: invKind as MalwareInvestigationKind,
        auto_pilot: auto,
        cost_budget_usd: budget,
      },
      {
        onSuccess: (created) => onBind({ id: created.id, title: created.title }),
        onError: (err) =>
          setLaunchError(
            (err && typeof err === "object" && "message" in err
              ? String(/* SAFETY: err is the mutation rejection, an ApiError with a server message. */ (err as ApiError).message || "").slice(0, 400)
              : "") || "create failed",
          ),
      },
    );
  };

  const allTargets = targetsQuery.data ?? [];
  const matches = kd !== null ? allTargets.filter((t) => t.kind === kd.k) : [];
  const wsRows = workspaces.data ?? [];

  return (
    <WizardShell
      heading={cfg.title}
      steps={genSteps}
      current={Math.min(step, 2)}
      issues={genIssues}
      onBack={(): void => setStep((s) => Math.max(0, s - 1))}
      onNext={(): void => setStep((s) => Math.min(2, s + 1))}
      onFinish={onLaunch}
      finishLabel={cfg.launch}
      busy={creating}
      error={launchError}
      onRetry={onLaunch}
      showPrimary={step < 3}
    >
      <TargetSteps
        cfg={cfg}
        step={step}
        kind={kind}
        kd={kd}
        hasInv={hasInv}
        invKind={invKind}
        setInvKind={setInvKind}
        auto={auto}
        setAuto={setAuto}
        budget={budget}
        setBudget={setBudget}
        question={question}
        setQuestion={setQuestion}
        targetId={targetId}
        targetName={targetName}
        targetLine={targetLine}
        workspaceFilter={workspaceFilter}
        setWorkspaceFilter={setWorkspaceFilter}
        workspaceRows={wsRows}
        targetsState={{
          isLoading: targetsQuery.isLoading,
          isError: targetsQuery.isError,
          matches,
        }}
        onPickKind={pickKind}
        onPickTarget={pickTarget}
        onRequestUpload={onRequestUpload}
        autoStyle={autoStyle}
        launchError={launchError}
        stage={stage}
      />
    </WizardShell>
  );
}
