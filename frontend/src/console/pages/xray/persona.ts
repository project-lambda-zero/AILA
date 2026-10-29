import type { Branch, Message } from "../../../api/types";
import { H } from "./theme";

// Display identity of a message's author: upper-cased name, role tag, accent tone.
export interface Persona {
  readonly name: string;
  readonly role: string;
  readonly tone: string;
}

// Per-module author resolution.
// messageVoice: true -> the message-carried `persona_voice` wins over the
//   branch row; false -> the branch row is the only voice source.
// roles: lower-cased persona voice -> role label.
export interface PersonaRules {
  readonly messageVoice: boolean;
  readonly roles: Readonly<Record<string, string>>;
}

// Mirrors the VR persona -> role roster in
// src/aila/modules/vr/agents/persona_router.py (persona_role_map). The role
// is an attribute of the persona voice, not the investigation strategy.
export const VR_PERSONA_RULES = {
  messageVoice: true,
  roles: {
    halvar: "researcher",
    noor: "researcher",
    renzo: "implementer",
    wei: "implementer",
    maddie: "critic",
    yuki: "critic",
  },
} satisfies PersonaRules;

// Malware: same roster as VR plus the malware-specific "unspecified" default
// the API assigns when a branch has no operator-set voice.
export const MALWARE_PERSONA_RULES = {
  messageVoice: false,
  roles: {
    ...VR_PERSONA_RULES.roles,
    unspecified: "engine",
  },
} satisfies PersonaRules;

export const PERSONA_TONES = [H.mint, H.amber, H.lav, H.sig, H.cream, H.acc] as const;

export function personaTone(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return PERSONA_TONES[h % PERSONA_TONES.length];
}

export function personaOf(m: Message, branchMap: ReadonlyMap<string, Branch>, rules: PersonaRules): Persona {
  const branch = m.branch_id ? branchMap.get(m.branch_id) : undefined;
  let voice: string;
  let name: string;
  if (rules.messageVoice) {
    // Message-carried persona wins: the branch may be abandoned (completed
    // investigation) and therefore absent from the branch list, so the
    // summary resolves it server-side. Fall back to the branch row, then
    // to sender kind.
    voice = (m.persona_voice ?? branch?.persona_voice ?? "").toLowerCase();
    name = (
      m.persona_voice ??
      branch?.persona_voice ??
      (m.sender_kind === "operator" ? "you" : "engine")
    ).toUpperCase();
  } else {
    // Branch row only; the message-carried voice is not consulted.
    voice = (branch?.persona_voice ?? "").toLowerCase();
    name = (branch?.persona_voice ?? (m.sender_kind === "operator" ? "you" : "engine")).toUpperCase();
  }
  const roleRaw = rules.roles[voice] ?? branch?.strategy_family ?? m.sender_kind ?? "";
  const role = (roleRaw.split(".").pop() ?? roleRaw).replace(/_/g, " ").toUpperCase();
  return { name, role, tone: personaTone(name) };
}
