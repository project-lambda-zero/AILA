import type { LayoutPanes } from "../layout";

// Ordered pane ids per layout -- hjkl/jk cycle focus through these (mock's
// LAYOUTS[*].panes). The overview's brief/records/engine/activity are drawers.
export const VR_LAYOUT_PANES = {
  overview: ["transcript", "brief", "records", "engine", "activity"],
  records: ["ledger", "ldetail", "hypotheses", "hdetail"],
  graphs: ["phasegraph"],
  oracle: ["oracle", "dispatch", "mcp", "detail"],
  finding: ["finding", "reach", "poc", "crash"],
} as const satisfies LayoutPanes;

// A VR tool call's one-line summary: the first of these string args present.
export const VR_TOOL_ARG_KEYS = ["query", "file_path", "name", "target", "apk_path"] as const;

export interface PhaseNode {
  id: string;
  label: string;
  stage: "struct" | "recon" | "source" | "binary" | "exploit";
  x: number;
  y: number;
}

// Dispatch-hub phase nodes + topological fixed positions for the GRAPHS view (viewBox 1160x450).
export const HUB = { x: 260, y: 220 } as const satisfies { x: number; y: number };
export const PHASES = [
  // 1. Structural Orchestration (Left)
  { id: "setup", label: "setup \u00b7 ingest", stage: "struct", x: 30, y: 45 },
  { id: "investigation_ledger", label: "ledger \u00b7 audit", stage: "struct", x: 30, y: 145 },
  { id: "oracle", label: "oracle \u00b7 strategy", stage: "struct", x: 30, y: 245 },
  { id: "emit", label: "emit \u00b7 verdict", stage: "struct", x: 30, y: 345 },

  // 2. Reconnaissance & Discovery (Col 1)
  { id: "recon", label: "recon \u00b7 discovery", stage: "recon", x: 400, y: 45 },
  { id: "variant_hunt", label: "variant_hunt", stage: "recon", x: 400, y: 145 },
  { id: "patch_diff_audit", label: "patch_diff_audit", stage: "recon", x: 400, y: 245 },
  { id: "fuzz_targeting", label: "fuzz_targeting", stage: "recon", x: 400, y: 345 },

  // 3. Source & Semantic Audits (Col 2)
  { id: "source_audit", label: "source_audit", stage: "source", x: 590, y: 45 },
  { id: "taint_analysis", label: "taint_analysis", stage: "source", x: 590, y: 91 },
  { id: "injection_audit", label: "injection_audit", stage: "source", x: 590, y: 137 },
  { id: "deserialization_audit", label: "deserialization", stage: "source", x: 590, y: 183 },
  { id: "auth_bypass_audit", label: "auth_bypass", stage: "source", x: 590, y: 229 },
  { id: "concurrency_audit", label: "concurrency_audit", stage: "source", x: 590, y: 275 },
  { id: "protocol_state_audit", label: "protocol_state", stage: "source", x: 590, y: 321 },
  { id: "dependency_audit", label: "dependency_audit", stage: "source", x: 590, y: 367 },

  // 4. Binary, Memory & Low-Level Audits (Col 3)
  { id: "binary_audit", label: "binary_audit", stage: "binary", x: 780, y: 45 },
  { id: "memory_safety_audit", label: "memory_safety", stage: "binary", x: 780, y: 91 },
  { id: "kernel_driver_audit", label: "kernel_driver", stage: "binary", x: 780, y: 137 },
  { id: "compiler_hardening_audit", label: "hardening_audit", stage: "binary", x: 780, y: 183 },
  { id: "sandbox_escape_audit", label: "sandbox_escape", stage: "binary", x: 780, y: 229 },
  { id: "crypto_audit", label: "crypto_audit", stage: "binary", x: 780, y: 275 },
  { id: "side_channel_audit", label: "side_channel", stage: "binary", x: 780, y: 321 },
  { id: "mobile_audit", label: "mobile_audit", stage: "binary", x: 780, y: 367 },

  // 5. Exploit Synthesis & Verification (Col 4)
  { id: "filter_bypass_synthesis", label: "filter_bypass", stage: "exploit", x: 970, y: 100 },
  { id: "exploit_primitive_composition", label: "exploit_compose", stage: "exploit", x: 970, y: 205 },
  { id: "poc_development", label: "poc_development", stage: "exploit", x: 970, y: 310 },
] as const satisfies readonly PhaseNode[];
