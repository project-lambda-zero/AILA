/**
 * IntakeWizard -- fullscreen overlay ported verbatim from the AILA Console
 * mock (docs/design sys/AILA Console.dc.html). One overlay handles four
 * modules with two distinct flows:
 *
 *  - vr / malware / vulnerability -> generic 3-step intake: kind grid,
 *    per-kind descriptor fields, review (initial question + investigation
 *    kind + auto-pilot + budget), then a staged ingestion animation.
 *  - forensics -> a configure -> readiness -> confirm wizard with its
 *    own header, project-kind and analyzer-OS cards, and a readiness
 *    animation before the confirm summary.
 *
 * Styling copies the mock's inline style strings 1:1 through css().
 * No investigation is fabricated -- when the animation completes we
 * simply onClose(); onBind is left typed but unused until the real
 * create-endpoint is wired.
 */

import React, { useEffect, useRef, useState } from "react";

import type { ApiError } from "../api/client";
import { apiFetch } from "../api/client";
import {
  useCreateMalwareInvestigation,
  useCreateVrInvestigation,
  useTargets,
  useWorkspaces,
} from "../api/intake";
import type {
  MalwareInvestigationKind,
  TargetRow,
  VRInvestigationKind,
} from "../api/intake";
import type { IntakeWizardProps } from "./contract";
import { css } from "./css";
import { FieldHelp, WizardShell } from "./wizards";
import type { WizardFieldIssue, WizardStepDef } from "./wizards";

/* ---------------------------- INTAKE data spine ---------------------------- */
/* Copied verbatim from the mock's <script> block. Grounded in the backend
 * contracts: TargetKind + InvestigationKind for vr, sample TargetKind for
 * malware, evidence intake for forensics, SSH system registration for
 * vulnerability. */

interface KindDef {
  k: string;
  l: string;
  g: string;
  inv?: string;
  /** [name, label, placeholder] */
  fields: Array<[string, string, string]>;
}

interface GenericCfg {
  flow: "target" | "system";
  title: string;
  newLabel: string;
  launch: string;
  invKinds: string[];
  /** [key, note] */
  stages: Array<[string, string]>;
  /** [id, label] */
  groups: Array<[string, string]>;
  kinds: KindDef[];
}

interface ProjectKindDef {
  k: string;
  l: string;
  sub: string;
  explain: string;
}

interface OsKindDef {
  k: string;
  l: string;
  explain: string;
}

interface ForensicsCfg {
  flow: "forensics";
  title: string;
  newLabel: string;
  launch: string;
  stepLabels: [string, string, string];
  header: string;
  tagline: string;
  machines: string[];
  projectKinds: ProjectKindDef[];
  osKinds: OsKindDef[];
  /** [label, note] */
  readiness: Array<[string, string]>;
}

type ModuleCfg = GenericCfg | ForensicsCfg;

const INTAKE: {
  vr: GenericCfg;
  malware: GenericCfg;
  forensics: ForensicsCfg;
  vulnerability: GenericCfg;
} = {
  vr: {
    flow: "target",
    title: "new investigation",
    newLabel: "new investigation",
    launch: "open investigation \u25b8",
    invKinds: [
      "discovery",
      "audit",
      "variant_hunt",
      "triage",
      "n_day",
      "masvs_audit",
      "apk_static_audit",
    ],
    stages: [
      ["ingestion", "clone / upload \u00b7 index_codebase"],
      ["capability_profile", "attack-surface + capability profile"],
      ["function_ranking", "rank candidate functions"],
    ],
    groups: [
      ["source", "source"],
      ["binary", "binary"],
      ["mobile", "mobile"],
      ["nday", "cve / n-day"],
      ["capture", "capture"],
      ["kernel", "kernel \u00b7 hv"],
    ],
    kinds: [
      { k: "source_repo", l: "source repo", g: "source", inv: "discovery", fields: [["repo_url", "repo url", "https://github.com/org/proj"], ["ref", "ref / branch", "main"]] },
      { k: "patch_diff", l: "patch diff", g: "source", inv: "n_day", fields: [["repo_url", "repo url", ""], ["vulnerable_ref", "vulnerable ref", ""], ["patched_ref", "patched ref", ""]] },
      { k: "native_binary", l: "native binary", g: "binary", inv: "discovery", fields: [["binary_path", "binary path / upload", "/firmware/rtspd"]] },
      { k: "jar", l: "jar", g: "binary", inv: "audit", fields: [["jar_path", "jar path / upload", ""]] },
      { k: "dotnet_assembly", l: ".net assembly", g: "binary", inv: "audit", fields: [["assembly_path", "assembly path", ""]] },
      { k: "cve", l: "cve", g: "nday", inv: "n_day", fields: [["cve_id", "cve id", "CVE-2026-1234"], ["vendor", "vendor", ""]] },
      { k: "android_apk", l: "android apk", g: "mobile", inv: "masvs_audit", fields: [["apk_path", "apk path / upload", "app.apk"]] },
      { k: "ipa", l: "ios ipa", g: "mobile", inv: "masvs_audit", fields: [["ipa_path", "ipa path / upload", ""]] },
      { k: "protocol_capture", l: "protocol capture", g: "capture", inv: "discovery", fields: [["pcap_path", "pcap path", ""], ["protocol", "protocol", "rtsp"]] },
      { k: "crash_input", l: "crash input", g: "capture", inv: "triage", fields: [["crash_artifact_path", "crash artifact", ""], ["parent_finding_id", "parent finding", ""]] },
      { k: "kernel_image", l: "kernel image", g: "kernel", inv: "discovery", fields: [["image_path", "image path", ""], ["kernel_version", "version", ""], ["arch", "arch", "x86_64"]] },
      { k: "kernel_module", l: "kernel module", g: "kernel", inv: "discovery", fields: [["ko_path", ".ko path", ""], ["module_name", "module name", ""]] },
      { k: "hypervisor_image", l: "hypervisor image", g: "kernel", inv: "discovery", fields: [["binary_path", "binary path", ""], ["hypervisor_kind", "kind", "kvm"], ["version", "version", ""]] },
    ],
  },
  malware: {
    flow: "target",
    title: "upload sample",
    newLabel: "upload sample",
    launch: "upload + detonate \u25b8",
    invKinds: [
      "full_analysis",
      "triage",
      "unpack_only",
      "config_extract",
      "yara_generate",
      "family_attribute",
    ],
    stages: [
      ["ingestion", "hash \u00b7 type \u00b7 unpack (target_ingestion)"],
      ["static_triage", "imports \u00b7 strings \u00b7 signatures"],
      ["behavior_profile", "detonate + observe (target_analysis)"],
    ],
    groups: [["sample", "sample"]],
    kinds: [
      { k: "pe_sample", l: "pe sample", g: "sample", fields: [["sample_path", "sample path / upload", "loader.exe"], ["archive_password", "archive password (opt)", "infected"]] },
      { k: "elf_sample", l: "elf sample", g: "sample", fields: [["sample_path", "sample path / upload", ""], ["archive_password", "archive password (opt)", ""]] },
      { k: "mach_o_sample", l: "mach-o sample", g: "sample", fields: [["sample_path", "sample path / upload", ""]] },
      { k: "shellcode", l: "shellcode", g: "sample", fields: [["sample_path", "blob path / upload", ""], ["arch", "arch", "x86_64"]] },
      { k: "android_apk", l: "android apk", g: "sample", fields: [["sample_path", "apk path / upload", ""]] },
      { k: "dotnet_assembly", l: ".net assembly", g: "sample", fields: [["sample_path", "assembly path / upload", ""]] },
      { k: "script_sample", l: "script sample", g: "sample", fields: [["sample_path", "script path / upload", ""], ["script_lang", "language", "powershell"]] },
      { k: "document_sample", l: "document sample", g: "sample", fields: [["sample_path", "document path / upload", ""]] },
    ],
  },
  forensics: {
    flow: "forensics",
    title: "spin up a forensic scene",
    newLabel: "new case",
    launch: "create & check readiness \u25b8",
    stepLabels: ["configure", "readiness", "confirm"],
    header: "forensics / new case init",
    tagline: "pick an analyzer, point at evidence, watch tools come online.",
    machines: [
      "frost-01 \u00b7 ubuntu 22.04",
      "frost-02 \u00b7 ubuntu 22.04",
      "win-analyst-03 \u00b7 windows 11",
      "air-gapped-vault \u00b7 debian 12",
    ],
    projectKinds: [
      { k: "disk_evidence", l: "Disk Evidence", sub: "E01 / raw / memory / pcap -- full pipeline runs", explain: "the analyzer runs the standard intake -> collection -> deep_analysis pipeline over disk images / memory dumps / pcaps in the directory." },
      { k: "raw_directory", l: "Raw Directory", sub: "rootfs / loose logs -- intake only, ask directly", explain: "the analyzer runs intake only over a mounted rootfs or loose log set, then answers questions directly against the normalized artifacts." },
    ],
    osKinds: [
      { k: "linux", l: "Linux", explain: "tool checks and commands will use bash, apt, and unix paths." },
      { k: "windows", l: "Windows", explain: "tool checks and commands will use powershell and windows paths." },
    ],
    readiness: [
      ["analyzer reachable", "ssh to the analyzer machine responds"],
      ["evidence dir mounted", "path exists + readable on the analyzer"],
      ["toolchain online", "sleuthkit \u00b7 volatility \u00b7 plaso \u00b7 tshark present"],
      ["workspace prepared", "case workspace + db provisioned"],
    ],
  },
  vulnerability: {
    flow: "system",
    title: "add system",
    newLabel: "add system",
    launch: "add system + scan \u25b8",
    invKinds: [],
    stages: [
      ["ssh_inventory", "ssh \u00b7 uname + package list"],
      ["advisory_match", "match packages -> advisories (osv / secdb)"],
      ["risk_scoring", "dedupe \u00b7 enrich \u00b7 risk-score"],
    ],
    groups: [["system", "system"]],
    kinds: [
      { k: "ubuntu", l: "ubuntu", g: "system", fields: [["host", "host / ip", "10.0.0.4"], ["ssh_user", "ssh user", "root"]] },
      { k: "debian", l: "debian", g: "system", fields: [["host", "host / ip", ""], ["ssh_user", "ssh user", "root"]] },
      { k: "arch", l: "arch", g: "system", fields: [["host", "host / ip", ""], ["ssh_user", "ssh user", "root"]] },
      { k: "alpine", l: "alpine", g: "system", fields: [["host", "host / ip", ""], ["ssh_user", "ssh user", "root"]] },
    ],
  },
};

/** Narrow a runtime string to a known module id without an inline cast. */
function getCfg(moduleId: string): ModuleCfg {
  if (moduleId === "vr") return INTAKE.vr;
  if (moduleId === "malware") return INTAKE.malware;
  if (moduleId === "forensics") return INTAKE.forensics;
  if (moduleId === "vulnerability") return INTAKE.vulnerability;
  return INTAKE.vr;
}

/* ------------------------------- component --------------------------------- */
/* The bespoke overlay wrapper (OVERLAY_STYLE / PANEL_STYLE / *_CONTAINER_STYLE)
 * is gone: App.tsx wraps this wizard in <ConsoleWindow>, and WizardShell owns
 * the header/step strip/footer inside that window. */

function IntakeWizard(
  { moduleId, onClose, onBind, onRequestUpload, prefill }: IntakeWizardProps,
): React.ReactElement {
  const cfg = getCfg(moduleId);
  const isFx = cfg.flow === "forensics";

  // vr / malware run the "pick an existing target + define question ->
  // POST /{module}/investigations" flow. vulnerability keeps the mock's
  // descriptor-collection flow (system registration is not wired here).
  const isInvestigationFlow = moduleId === "vr" || moduleId === "malware";

  const [step, setStep] = useState<number>(0);
  const [kind, setKind] = useState<string | null>(isFx ? "disk_evidence" : null);
  const [desc, setDesc] = useState<Record<string, string>>(
    isFx ? { analyzer_os: "linux" } : {},
  );
  const [question, setQuestion] = useState<string>("");
  const [invKind, setInvKind] = useState<string>(
    moduleId === "malware" ? "full_analysis" : "discovery",
  );
  const [auto, setAuto] = useState<boolean>(true);
  const [budget, setBudget] = useState<number>(50);
  const [stage, setStage] = useState<number>(-1);

  // Investigation-flow state (vr / malware only). Held always so hook order
  // and reconciliation remain stable across module switches.
  const [targetId, setTargetId] = useState<string | null>(null);
  const [targetName, setTargetName] = useState<string>("");
  const [workspaceFilter, setWorkspaceFilter] = useState<string>("");
  const [launchError, setLaunchError] = useState<string | null>(null);

  // Forensics flow state: real system registry rows for the analyzer select,
  // plus the live create + readiness-check result. `fxBusy` gates the launch
  // button; the readiness stages come from the backend result, not a local
  // animation.
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

  // Rules of Hooks: always call these. The `enabled` gate keeps the queries
  // silent when the wizard is on vulnerability / forensics.
  const workspaces = useWorkspaces(moduleId === "malware" ? "malware" : "vr");
  const targetsQuery = useTargets(
    moduleId === "malware" ? "malware" : "vr",
    {
      enabled: isInvestigationFlow,
      workspaceId: workspaceFilter || null,
    },
  );

  const createVrInv = useCreateVrInvestigation();
  const createMalInv = useCreateMalwareInvestigation();
  const creating = createVrInv.isPending || createMalInv.isPending;

  // window.setInterval / window.setTimeout return `number` in the DOM lib and
  // give us a concrete handle type without leaning on `ReturnType<typeof ...>`.
  const timerRef = useRef<number | null>(null);
  const closeTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      window.clearInterval(timerRef.current ?? undefined);
      window.clearTimeout(closeTimerRef.current ?? undefined);
    };
  }, []);

  // Preselect a target passed in via `prefill.targetId` once the targets query
  // has loaded and the id matches a row. Best-effort: a miss leaves the picker
  // empty. `kind` also flips to that target's kind so it appears in `matches`.
  const prefillTargetId = prefill?.targetId ?? null;
  useEffect(() => {
    if (!isInvestigationFlow || !prefillTargetId) return;
    if (targetId === prefillTargetId) return;
    const rows = targetsQuery.data ?? [];
    const hit = rows.find((t) => t.id === prefillTargetId);
    if (!hit) return;
    setTargetId(hit.id);
    setTargetName(hit.display_name);
    setKind(hit.kind);
  }, [isInvestigationFlow, prefillTargetId, targetsQuery.data, targetId]);

  // Forensics analyzer select needs real registered systems (the backend
  // requires a numeric system_id, not a display label). Fetch once when the
  // wizard is on the forensics flow.
  useEffect(() => {
    if (!isFx) return;
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
  }, [isFx]);

  const setDescField = (name: string, value: string): void => {
    setDesc((d) => ({ ...d, [name]: value }));
  };

  const pickKind = (k: string): void => {
    if (cfg.flow === "forensics") return; // forensics has no kind grid
    const d = cfg.kinds.find((x) => x.k === k);
    setKind(k);
    setInvKind(
      d?.inv ?? (moduleId === "malware" ? "full_analysis" : "discovery"),
    );
    setDesc({});
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

  /* ============================== forensics =============================== */

  if (cfg.flow === "forensics") {
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
              ? String((err as ApiError).message || "").slice(0, 400)
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
                    <span style={css("font-size:10px;color:var(--text-faint);")}>no systems registered \u2014 add one on the systems page first</span>
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
                          <span style={css("font-size:10px;color:var(--text-faint);")}>{p.sub}</span>
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
                  <div style={css(`font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:${fxResult.ready ? "var(--status-ok)" : "var(--status-err, #d64545)"};`)}>
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
                    <div style={css("margin-top:7px;font-size:10.5px;color:var(--text-muted);line-height:1.45;")}>{fxResult.message}</div>
                  ) : null}
                </div>
                <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>tool checks</div>
                {fxResult.tools.map((t) => {
                  const ok = t.status === "ok" || t.status === "present" || t.status === "available";
                  const stStyle = css(
                    `font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:${ok ? "var(--status-ok)" : t.status === "missing" || t.status === "absent" ? "var(--status-err, #d64545)" : "var(--text-muted)"};`,
                  );
                  return (
                    <div key={t.tool_name} style={css("display:flex;align-items:center;gap:10px;padding:9px 11px;border:1px solid var(--border-soft);background:var(--surface-sunk);border-radius:3px;")}>
                      <span style={css(`width:9px;height:9px;flex:0 0 auto;border-radius:1px;background:${ok ? "var(--status-ok)" : "var(--status-err, #d64545)"};`)} />
                      <span style={css("display:flex;flex-direction:column;flex:1;min-width:0;")}>
                        <span style={css("font-size:11.5px;color:var(--text-primary);")}>{t.tool_name}{t.required ? "" : " (opt)"}</span>
                        <span style={css("font-size:9px;color:var(--text-faint);")}>{t.version || t.message || ""}</span>
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

  /* =============================== generic ================================ */

  const gcfg: GenericCfg = cfg;
  const kd = kind ? gcfg.kinds.find((x) => x.k === kind) ?? null : null;
  const hasInv = gcfg.invKinds.length > 0;

  // Steps + issue lists that drive WizardShell. Investigation flow (vr/malware)
  // routes through target-picker; descriptor flow (vulnerability) collects
  // per-kind descriptor fields on step 1 instead. Step 3 is the terminal
  // animation and hides the shell's primary via showPrimary=false.
  const genSteps: WizardStepDef[] = [
    { id: "kind", title: "pick kind", purpose: "pick what to investigate." },
    isInvestigationFlow
      ? { id: "target", title: "pick target", purpose: "pick a registered target of this kind." }
      : { id: "descriptor", title: "descriptor fields", purpose: "fill the descriptor for this kind." },
    { id: "review", title: "review + launch", purpose: "name the initial question and configure the run." },
  ];
  const genIssues: WizardFieldIssue[] = [];
  if (step === 0) {
    if (kind === null) genIssues.push({ label: "kind", reason: "pick a kind to continue" });
  } else if (step === 1) {
    if (isInvestigationFlow) {
      if (targetId === null) genIssues.push({ label: "target", reason: "pick a target to investigate" });
    } else if (kd) {
      for (const f of kd.fields) {
        if (f[0] === "parent_finding_id") continue;
        if ((desc[f[0]] ?? "").trim() === "") genIssues.push({ label: f[1], reason: "required" });
      }
    } else {
      genIssues.push({ label: "kind", reason: "pick a kind first" });
    }
  } else if (step === 2) {
    if (isInvestigationFlow && targetId === null) genIssues.push({ label: "target", reason: "pick a target first" });
    if (isInvestigationFlow && question.trim() === "") genIssues.push({ label: "initial question", reason: "required" });
  }

  const autoStyle = css(
    `display:inline-flex;align-items:center;gap:6px;padding:3px 9px;font-family:var(--font-mono);font-size:9px;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;border:1px solid ${
      auto ? "var(--accent)" : "var(--border-soft)"
    };color:${auto ? "var(--accent)" : "var(--text-muted)"};background:${
      auto ? "color-mix(in srgb,var(--accent) 12%,transparent)" : "transparent"
    };border-radius:2px;`,
  );

  // Review-step target line. For vr/malware we show the picked target's real
  // display name; for the descriptor-mode flow (vulnerability) we still join
  // whatever the operator filled in as before.
  const targetLine = isInvestigationFlow
    ? targetName || (targetId ? targetId : "no target picked")
    : kd
      ? kd.fields
          .map((f) => desc[f[0]] ?? "")
          .filter((v) => v.trim() !== "")
          .join(" \u00b7 ") || "no descriptor yet"
      : "";

  const onLaunch = (): void => {
    // Belt-and-braces: WizardShell already disables the primary via issues +
    // busy, but a stale focused button on the review step should never fire
    // the launch mutation with a missing target / empty question.
    if (isInvestigationFlow && (targetId === null || question.trim() === "" || creating)) return;
    setLaunchError(null);
    setStep(3);
    setStage(0);

    if (!isInvestigationFlow) {
      // Vulnerability + any other future generic module: animate + close.
      runStages(gcfg.stages.length, 900, () => {
        closeTimerRef.current = window.setTimeout(() => onClose(), 700);
      });
      return;
    }

    if (targetId === null) return;
    const q = question.trim();
    const kindLabel = kd?.l ?? "target";
    const derivedTitle = (q || `${invKind} \u00b7 ${targetName || kindLabel}`).slice(0, 255);
    const initialQuestion = q || `Investigate ${targetName || kindLabel} (${invKind}).`;

    // Kick the animation and the mutation together. onBind runs when the
    // mutation succeeds (the parent shell closes the wizard and opens the
    // matching X-Ray); onError surfaces the server detail in-place so the
    // operator can adjust and retry without losing collected fields.
    runStages(gcfg.stages.length, 900, () => {
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
                ? String((err as ApiError).message || "").slice(0, 400)
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
              ? String((err as ApiError).message || "").slice(0, 400)
              : "") || "create failed",
          ),
      },
    );
  };

  return (
    <WizardShell
      heading={gcfg.title}
      steps={genSteps}
      current={Math.min(step, 2)}
      issues={genIssues}
      onBack={(): void => setStep((s) => Math.max(0, s - 1))}
      onNext={(): void => setStep((s) => Math.min(2, s + 1))}
      onFinish={onLaunch}
      finishLabel={gcfg.launch}
      busy={creating}
      error={launchError}
      onRetry={onLaunch}
      showPrimary={step < 3}
    >
      {step === 0 && (
            <div style={css("display:flex;flex-direction:column;gap:12px;")}>
              {gcfg.groups.map((g) => {
                const items = gcfg.kinds.filter((k) => k.g === g[0]);
                return (
                  <div key={g[0]}>
                    <div style={css("font-size:9px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-faint);margin-bottom:6px;")}>
                      {g[1]}
                    </div>
                    <div style={css("display:grid;grid-template-columns:repeat(3,1fr);gap:6px;")}>
                      {items.map((k) => (
                        <button
                          key={k.k}
                          type="button"
                          onClick={(): void => pickKind(k.k)}
                          style={css("padding:8px 9px;text-align:left;font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.04em;color:var(--text-primary);background:var(--surface-card);border:1px solid var(--border-soft);border-radius:2px;cursor:pointer;")}
                        >
                          <span>{k.l}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {step === 1 && kd !== null && !isInvestigationFlow && (
            <div style={css("display:flex;flex-direction:column;gap:11px;")}>
              <div style={css("font-size:10px;letter-spacing:0.06em;color:var(--text-muted);")}>
                <span style={css("color:var(--accent);")}>{"kind \u00b7"}</span> {kd.l}
              </div>
              {kd.fields.map((f) => (
                <label key={f[0]} style={css("display:flex;flex-direction:column;gap:4px;")}>
                  <span style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
                    {f[1]}
                  </span>
                  <input
                    value={desc[f[0]] ?? ""}
                    onChange={(e): void => setDescField(f[0], e.target.value)}
                    placeholder={f[2]}
                    style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:7px 9px;color:var(--text-primary);font-family:var(--font-mono);font-size:11.5px;border-radius:2px;")}
                  />
                </label>
              ))}
            </div>
          )}

          {step === 1 && kd !== null && isInvestigationFlow && (() => {
            const allTargets = targetsQuery.data ?? [];
            const matches = allTargets.filter((t) => t.kind === kd.k);
            const wsRows = workspaces.data ?? [];
            return (
              <div style={css("display:flex;flex-direction:column;gap:11px;")}>
                <div style={css("display:flex;align-items:center;gap:10px;")}>
                  <span style={css("font-size:10px;letter-spacing:0.06em;color:var(--text-muted);")}>
                    <span style={css("color:var(--accent);")}>{"kind \u00b7"}</span> {kd.l}
                  </span>
                  <span style={css("flex:1;")} />
                  {wsRows.length > 0 && (
                    <select
                      value={workspaceFilter}
                      onChange={(e): void => setWorkspaceFilter(e.target.value)}
                      style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:4px 7px;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;border-radius:2px;")}
                      title="filter by workspace"
                    >
                      <option value="">all workspaces</option>
                      {wsRows.map((w) => (
                        <option key={w.id} value={w.id}>{w.name}</option>
                      ))}
                    </select>
                  )}
                  {onRequestUpload && (
                    <button
                      type="button"
                      onClick={onRequestUpload}
                      style={css("padding:2px 8px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;")}
                      title="close and open the upload window"
                    >
                      + upload new target
                    </button>
                  )}
                </div>
                {targetsQuery.isLoading ? (
                  <div style={css("padding:22px;text-align:center;font-size:11px;color:var(--text-faint);")}>
                    {"loading targets\u2026"}
                  </div>
                ) : targetsQuery.isError ? (
                  <div style={css("padding:12px;border:1px solid var(--status-warn);color:var(--status-warn);font-size:11px;border-radius:2px;")}>
                    failed to load targets
                  </div>
                ) : matches.length === 0 ? (
                  <div style={css("padding:22px;text-align:center;font-size:11px;color:var(--text-faint);line-height:1.5;")}>
                    no {kd.l} targets yet.
                    {onRequestUpload ? " use \u201c+ upload new target\u201d above to create one." : ""}
                  </div>
                ) : (
                  <div style={css("display:flex;flex-direction:column;gap:5px;max-height:340px;overflow:auto;")}>
                    {matches.map((t) => {
                      const on = t.id === targetId;
                      return (
                        <button
                          key={t.id}
                          type="button"
                          onClick={(): void => pickTarget(t)}
                          style={css(
                            `display:flex;align-items:center;gap:10px;padding:8px 11px;text-align:left;font-family:var(--font-mono);font-size:11px;color:${
                              on ? "var(--accent)" : "var(--text-primary)"
                            };background:${
                              on ? "color-mix(in srgb,var(--accent) 10%,transparent)" : "var(--surface-sunk)"
                            };border:1px solid ${on ? "var(--accent)" : "var(--border-soft)"};border-radius:2px;cursor:pointer;`,
                          )}
                        >
                          <span style={css(`width:6px;height:6px;flex:0 0 auto;border-radius:1px;background:${on ? "var(--accent)" : "var(--text-faint)"};`)} />
                          <span style={css("flex:1;min-width:0;display:flex;flex-direction:column;gap:2px;")}>
                            <span style={css("color:inherit;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{t.display_name}</span>
                            <span style={css("font-size:9px;color:var(--text-faint);letter-spacing:0.06em;")}>
                              {t.workspace_name ?? t.workspace_id ?? ""}
                              {t.analysis_state ? ` \u00b7 ${t.analysis_state}` : ""}
                            </span>
                          </span>
                          <span style={css("font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>{t.kind}</span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })()}

          {step === 2 && (
            <div style={css("display:flex;flex-direction:column;gap:12px;")}>
              <div style={css("padding:9px 11px;border:1px solid var(--border-soft);background:var(--surface-sunk);border-radius:2px;")}>
                <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
                  target
                </div>
                <div style={css("margin-top:4px;font-size:11px;color:var(--text-primary);")}>
                  {kd?.l ?? "\u2014"} <span style={css("color:var(--text-faint);")}>{"\u00b7"}</span> {targetLine}
                </div>
              </div>
              <label style={css("display:flex;flex-direction:column;gap:4px;")}>
                <span style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
                  initial question
                </span>
                <textarea
                  value={question}
                  onChange={(e): void => setQuestion(e.target.value)}
                  placeholder="what should AILA find? e.g. memory-safety bugs reachable pre-auth"
                  rows={2}
                  style={css("resize:none;background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:8px 9px;color:var(--text-primary);font-family:var(--font-sans,system-ui);font-size:12px;line-height:1.4;border-radius:2px;")}
                />
              </label>
              {hasInv && (
                <div>
                  <span style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
                    investigation kind
                  </span>
                  <div style={css("display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;")}>
                    {gcfg.invKinds.map((k) => {
                      const on = k === invKind;
                      return (
                        <button
                          key={k}
                          type="button"
                          onClick={(): void => setInvKind(k)}
                          style={css(
                            `padding:3px 8px;font-family:var(--font-mono);font-size:9px;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;border:1px solid ${
                              on ? "var(--accent)" : "var(--border-soft)"
                            };color:${on ? "var(--accent)" : "var(--text-muted)"};background:${
                              on ? "color-mix(in srgb,var(--accent) 12%,transparent)" : "transparent"
                            };border-radius:2px;`,
                          )}
                        >
                          {k}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
              <div style={css("display:flex;align-items:center;gap:14px;")}>
                <button type="button" onClick={(): void => setAuto((a) => !a)} style={autoStyle}>
                  <span>auto-pilot</span>
                  <span>{auto ? "on" : "off"}</span>
                </button>
                <FieldHelp text="auto-pilot lets AILA plan and run turns without asking for confirmation each step. turn off to step through every turn manually." />
                <label style={css("display:inline-flex;align-items:center;gap:7px;font-size:9px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>
                  budget usd
                  <input
                    value={String(budget)}
                    onChange={(e): void => {
                      const n = Number(e.target.value);
                      setBudget(Number.isFinite(n) ? n : 0);
                    }}
                    style={css("width:70px;background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:5px 8px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;border-radius:2px;")}
                  />
                </label>
                <FieldHelp text="hard ceiling for LLM spend on this investigation in USD. defaults to 50; edit before launching to override." />
              </div>
            </div>
          )}

          {step >= 3 && (
            <div style={css("display:flex;flex-direction:column;gap:9px;")}>
              <div style={css("font-size:10px;letter-spacing:0.06em;color:var(--text-muted);")}>
                {isInvestigationFlow
                  ? `creating investigation \u00b7 ${targetName || kd?.l || ""}`
                  : `ingesting ${kd?.l ?? ""} \u2014 TargetAnalysisService is resolving the target before the panel spawns.`}
              </div>
              {launchError ? (
                <div style={css("padding:8px 10px;border:1px solid var(--status-warn);color:var(--status-warn);font-size:11px;border-radius:2px;background:color-mix(in srgb,var(--status-warn) 8%,transparent);white-space:pre-wrap;word-break:break-word;")}>
                  {launchError}
                </div>
              ) : null}
              {gcfg.stages.map((st, i) => {
                const done = stage > i;
                const run = stage === i;
                const dot = css(
                  `width:9px;height:9px;flex:0 0 auto;border-radius:1px;background:${
                    done ? "var(--status-ok)" : run ? "var(--accent)" : "var(--text-faint)"
                  };${run ? "animation:acbreathe 1s ease-in-out infinite;" : ""}`,
                );
                const textStyle = css(
                  `font-size:11px;letter-spacing:0.04em;color:${done || run ? "var(--text-primary)" : "var(--text-faint)"};`,
                );
                const stStyle = css(
                  `font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:${
                    done ? "var(--status-ok)" : run ? "var(--accent)" : "var(--text-faint)"
                  };`,
                );
                const stTxt = done ? "done" : run ? "running" : "pending";
                return (
                  <div
                    key={st[0]}
                    style={css("display:flex;align-items:center;gap:10px;padding:9px 11px;border:1px solid var(--border-soft);background:var(--surface-sunk);border-radius:2px;")}
                  >
                    <span style={dot} />
                    <span style={css("display:flex;flex-direction:column;flex:1;min-width:0;")}>
                      <span style={textStyle}>{st[0].replace(/_/g, " ")}</span>
                      <span style={css("font-size:9px;color:var(--text-faint);letter-spacing:0.02em;")}>{st[1]}</span>
                    </span>
                    <span style={stStyle}>{stTxt}</span>
                  </div>
                );
              })}
            </div>
          )}

    </WizardShell>
  );
}

export default IntakeWizard;
