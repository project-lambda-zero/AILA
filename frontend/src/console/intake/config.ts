/**
 * IntakeWizard data spine -- the per-module intake configuration copied from
 * the AILA Console mock script block, grounded in the backend contracts:
 * TargetKind + InvestigationKind for vr, sample TargetKind for malware, and
 * evidence intake for forensics.
 */

export interface KindDef {
  k: string;
  l: string;
  g: string;
  inv?: string;
  /** [name, label, placeholder] */
  fields: Array<[string, string, string]>;
}

export interface GenericCfg {
  flow: "target";
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

export interface ProjectKindDef {
  k: string;
  l: string;
  sub: string;
  explain: string;
}

export interface OsKindDef {
  k: string;
  l: string;
  explain: string;
}

export interface ForensicsCfg {
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

export type ModuleCfg = GenericCfg | ForensicsCfg;

export const INTAKE = {
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
      { k: "native_binary", l: "native binary", g: "binary", inv: "discovery", fields: [] },
      { k: "jar", l: "jar", g: "binary", inv: "audit", fields: [] },
      { k: "dotnet_assembly", l: ".net assembly", g: "binary", inv: "audit", fields: [] },
      { k: "cve", l: "cve", g: "nday", inv: "n_day", fields: [["cve_id", "cve id", "CVE-2026-1234"], ["vendor", "vendor", ""]] },
      { k: "android_apk", l: "android apk", g: "mobile", inv: "masvs_audit", fields: [] },
      { k: "ipa", l: "ios ipa", g: "mobile", inv: "masvs_audit", fields: [] },
      { k: "protocol_capture", l: "protocol capture", g: "capture", inv: "discovery", fields: [["protocol", "protocol", "rtsp"]] },
      { k: "crash_input", l: "crash input", g: "capture", inv: "triage", fields: [["parent_finding_id", "parent finding", ""]] },
      { k: "kernel_image", l: "kernel image", g: "kernel", inv: "discovery", fields: [["kernel_version", "version", ""], ["arch", "arch", "x86_64"]] },
      { k: "kernel_module", l: "kernel module", g: "kernel", inv: "discovery", fields: [["module_name", "module name", ""]] },
      { k: "hypervisor_image", l: "hypervisor image", g: "kernel", inv: "discovery", fields: [["hypervisor_kind", "kind", "kvm"], ["version", "version", ""]] },
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
      { k: "pe_sample", l: "pe sample", g: "sample", fields: [["archive_password", "archive password (opt)", "infected"]] },
      { k: "elf_sample", l: "elf sample", g: "sample", fields: [["archive_password", "archive password (opt)", ""]] },
      { k: "mach_o_sample", l: "mach-o sample", g: "sample", fields: [] },
      { k: "shellcode", l: "shellcode", g: "sample", fields: [["arch", "arch", "x86_64"]] },
      { k: "android_apk", l: "android apk", g: "sample", fields: [] },
      { k: "dotnet_assembly", l: ".net assembly", g: "sample", fields: [] },
      { k: "script_sample", l: "script sample", g: "sample", fields: [["script_lang", "language", "powershell"]] },
      { k: "document_sample", l: "document sample", g: "sample", fields: [] },
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
} satisfies {
  vr: GenericCfg;
  malware: GenericCfg;
  forensics: ForensicsCfg;
};

/** Narrow a runtime string to a known module id without an inline cast. */
export function getCfg(moduleId: string): ModuleCfg {
  if (moduleId === "malware") return INTAKE.malware;
  if (moduleId === "forensics") return INTAKE.forensics;
  return INTAKE.vr;
}
