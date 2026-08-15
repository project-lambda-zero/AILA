import { MonoBadge } from "@/components/aila/mock";

/** Mitigations ribbon from 08_FRONTEND_UX.md §1.4 /
 *
 *  Renders one badge per protection (NX/ASLR/PIE/Canary/CFI/CET/RELRO)
 *  with green/red/gray tone reflecting present/absent/unknown. Hover
 *  reveals provenance ("from checksec" / "from IDA structures pass" /
 *  "inferred from imports"). Operator-friendly -- every label is plain
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
  tone: "low" | "high" | "info";
  text: string;
} {
  if (v === true) return { tone: "low", text: "ON" };
  if (v === false) return { tone: "high", text: "OFF" };
  return { tone: "info", text: "?" };
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
          <MonoBadge
            key={spec.key}
            tone={t.tone}
            title={`${spec.label} -- ${t.text} (source: ${source})`}
          >
            {spec.short}: {t.text}
          </MonoBadge>
        );
      })}
      {(m.relro_full || m.relro_partial) && (
        <MonoBadge tone="low" title={`RELRO source: ${source}`}>
          RELRO: {m.relro_full ? "full" : "partial"}
        </MonoBadge>
      )}
      {(m.sanitizers ?? []).map((s) => (
        <MonoBadge
          key={s}
          tone="medium"
          title={`Sanitizer enabled in build (source: ${source})`}
        >
          {s}
        </MonoBadge>
      ))}
      {m.notes && (
        <span
          className="font-mono italic"
          style={{ marginLeft: 8, fontSize: 10, color: "var(--text-faint)" }}
        >
          {m.notes}
        </span>
      )}
    </div>
  );
}
