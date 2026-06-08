import { AilaBadge } from "@/components/aila/AilaBadge";

/** Mitigations ribbon from 08_FRONTEND_UX.md §1.4 / VR_FRONTEND_UX_DISCUSSION.md.
 *
 *  Renders one badge per protection (NX/ASLR/PIE/Canary/CFI/CET/RELRO)
 *  with green/red/gray tone reflecting present/absent/unknown. Hover
 *  reveals provenance ("from checksec" / "from IDA structures pass" /
 *  "inferred from imports"). Operator-friendly — every label is plain
 *  English with the technical token in parentheses. */
export interface MitigationFlags {
  nx?: boolean | null;
  aslr?: boolean | null;
  pie?: boolean | null;
  canary?: boolean | null;
  cfi?: boolean | null;
  cet?: boolean | null;
  relro_partial?: boolean | null;
  relro_full?: boolean | null;
  sanitizers?: string[];
  source?: string | null; // e.g. "checksec", "ida_structures", "import_inference"
  notes?: string | null;
}

const SPEC: ReadonlyArray<{
  key: keyof MitigationFlags;
  label: string;
  short: string;
}> = [
  { key: "nx",     label: "Non-Executable Stack/Heap", short: "NX" },
  { key: "aslr",   label: "Address Space Randomisation", short: "ASLR" },
  { key: "pie",    label: "Position-Independent Executable", short: "PIE" },
  { key: "canary", label: "Stack Canaries", short: "Canary" },
  { key: "cfi",    label: "Control-Flow Integrity", short: "CFI" },
  { key: "cet",    label: "Intel CET (Shadow Stack / IBT)", short: "CET" },
];

function flagTone(v: unknown): {
  severity: "low" | "high" | "info";
  text: string;
} {
  if (v === true) return { severity: "low", text: "ON" };
  if (v === false) return { severity: "high", text: "OFF" };
  return { severity: "info", text: "?" };
}

export function MitigationsRibbon({
  mitigations,
  className = "",
}: {
  mitigations: MitigationFlags | null | undefined;
  className?: string;
}) {
  const m = mitigations ?? {};
  const source = m.source ?? "unknown";
  return (
    <div className={`flex flex-wrap items-center gap-1.5 ${className}`}>
      {SPEC.map((spec) => {
        const t = flagTone(m[spec.key]);
        return (
          <AilaBadge
            key={spec.key}
            severity={t.severity}
            size="sm"
            title={`${spec.label} — ${t.text} (source: ${source})`}
          >
            {spec.short}: {t.text}
          </AilaBadge>
        );
      })}
      {(m.relro_full || m.relro_partial) && (
        <AilaBadge severity="low" size="sm" title={`RELRO source: ${source}`}>
          RELRO: {m.relro_full ? "full" : "partial"}
        </AilaBadge>
      )}
      {(m.sanitizers ?? []).map((s) => (
        <AilaBadge
          key={s}
          severity="medium"
          size="sm"
          title={`Sanitizer enabled in build (source: ${source})`}
        >
          {s}
        </AilaBadge>
      ))}
      {m.notes && (
        <span className="text-3xs text-text-muted italic ml-2">
          {m.notes}
        </span>
      )}
    </div>
  );
}
