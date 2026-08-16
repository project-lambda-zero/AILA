/** The design page labels a bound case with a short reference id (e.g. VR-2291),
 * not the full title. Real investigations carry a UUID and a descriptive title,
 * so we derive a stable short id -- a module code plus the first hex quartet of
 * the UUID (like a git short hash). Deterministic: the same investigation always
 * renders the same code. */

const MODULE_CODE: Record<string, string> = {
  vr: "VR",
  vulnerability: "VULN",
  forensics: "DFIR",
  malware: "MAL",
};

export function shortCaseId(moduleId: string, id: string): string {
  const code = MODULE_CODE[moduleId] ?? moduleId.slice(0, 3).toUpperCase();
  const hex = id.replace(/[^0-9a-fA-F]/g, "").slice(0, 4).toUpperCase();
  return hex ? `${code}-${hex}` : code;
}
