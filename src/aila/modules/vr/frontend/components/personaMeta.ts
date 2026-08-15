/**
 * Persona hue + initial map, shared across VR components (TurnCard,
 * OperatorAvatar, LiveRunPanel, InvestigationDetailPage, branch lists).
 *
 * Every persona badge / logo tile in the VR module resolves through
 * `personaMeta(voice)` so a researcher reads the same hue everywhere.
 * Colours are mock-token strings (never raw hex, never palette classes).
 */

export const PERSONA_HUE: Record<string, string> = {
  halvar: "var(--accent)",
  maddie: "var(--status-info)",
  renzo: "var(--status-ok)",
  yuki: "var(--status-signal)",
  noor: "var(--status-warn)",
  wei: "color-mix(in srgb, var(--accent) 55%, var(--status-warn))",
  snake: "var(--status-ok)",
  jak: "var(--status-warn)",
  kratos: "var(--accent)",
  lara: "var(--status-info)",
};

export const PERSONA_INITIAL: Record<string, string> = {
  halvar: "H",
  maddie: "M",
  renzo: "R",
  yuki: "Y",
  noor: "N",
  wei: "W",
  snake: "S",
  jak: "J",
  kratos: "K",
  lara: "L",
};

export interface PersonaMeta {
  hue: string;
  initial: string;
  label: string;
}

export function personaMeta(voice?: string | null): PersonaMeta {
  const key = (voice || "").toLowerCase();
  return {
    hue: PERSONA_HUE[key] ?? "var(--text-faint)",
    initial: PERSONA_INITIAL[key] ?? "?",
    label: key ? key.charAt(0).toUpperCase() + key.slice(1) : "Branch",
  };
}
