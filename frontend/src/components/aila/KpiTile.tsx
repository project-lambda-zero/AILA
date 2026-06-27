/**
 * KpiTile -- single metric tile with severity-tinted left stripe + icon
 * badge. Use 4-up in a hero row at the top of list pages. Pairs with
 * AilaCard for grouped surfaces; this is the standalone "single number
 * with context" primitive.
 *
 * Example:
 *   <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
 *     <KpiTile label="Active" value={42} icon={<Pulse />} tone="accent" />
 *     <KpiTile label="Failed" value={3} hint="2 since yesterday" tone="warn" icon={<Warning />} />
 *   </div>
 */
import * as React from "react"

export type KpiTone = "neutral" | "accent" | "warn" | "ok" | "crit"

export interface KpiTileProps {
  label: string
  value: string | number
  hint?: React.ReactNode
  icon: React.ReactNode
  tone?: KpiTone
  /** Click handler turns the tile into a button (drill-down). */
  onClick?: () => void
  className?: string
}

const TONE_STYLES: Record<KpiTone, { bar: string; iconBg: string; iconText: string }> = {
  neutral: {
    bar: "linear-gradient(180deg, color-mix(in srgb, var(--color-text-muted) 50%, transparent), transparent)",
    iconBg: "color-mix(in srgb, var(--color-text-muted) 8%, transparent)",
    iconText: "var(--color-text-muted)",
  },
  accent: {
    bar: "linear-gradient(180deg, var(--color-accent), color-mix(in srgb, var(--color-accent) 0%, transparent))",
    iconBg: "color-mix(in srgb, var(--color-accent) 12%, transparent)",
    iconText: "var(--color-accent)",
  },
  warn: {
    bar: "linear-gradient(180deg, #f0a8c7, color-mix(in srgb, #f0a8c7 0%, transparent))",
    iconBg: "color-mix(in srgb, #f0a8c7 14%, transparent)",
    iconText: "#f0a8c7",
  },
  ok: {
    bar: "linear-gradient(180deg, #97dbbe, color-mix(in srgb, #97dbbe 0%, transparent))",
    iconBg: "color-mix(in srgb, #97dbbe 14%, transparent)",
    iconText: "#97dbbe",
  },
  crit: {
    bar: "linear-gradient(180deg, var(--color-accent), color-mix(in srgb, var(--color-accent) 0%, transparent))",
    iconBg: "color-mix(in srgb, var(--color-accent) 18%, transparent)",
    iconText: "var(--color-accent)",
  },
}

export function KpiTile({
  label,
  value,
  hint,
  icon,
  tone = "neutral",
  onClick,
  className,
}: KpiTileProps) {
  const s = TONE_STYLES[tone]
  const Element = onClick ? "button" : "div"
  return (
    <Element
      type={onClick ? "button" : undefined}
      onClick={onClick}
      className={`group relative overflow-hidden rounded-md border border-border bg-surface px-5 py-4 text-left ${onClick ? "transition-all hover:border-accent/40 hover:-translate-y-0.5 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent" : ""} ${className ?? ""}`}
      style={{
        boxShadow: "inset 0 1px 0 0 color-mix(in srgb, var(--color-text) 6%, transparent)",
      }}
    >
      {/* Left accent stripe -- vertical 3px bar */}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-y-0 left-0 w-[3px]"
        style={{ background: s.bar }}
      />
      <div className="flex items-start gap-3">
        <div
          className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded"
          style={{ background: s.iconBg, color: s.iconText }}
        >
          <span className="[&_svg]:h-5 [&_svg]:w-5">{icon}</span>
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-[10px] font-mono uppercase tracking-[0.14em] text-text-muted">
            {label}
          </p>
          <p className="mt-0.5 font-display text-3xl font-semibold text-foreground leading-none">
            {value}
          </p>
          {hint && (
            <p className="mt-1.5 text-[11px] font-mono text-text-muted truncate">
              {hint}
            </p>
          )}
        </div>
      </div>
    </Element>
  )
}
