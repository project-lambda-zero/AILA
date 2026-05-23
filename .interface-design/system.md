# AILA Design System

Adapted from Dammyjay93/interface-design `system-precision.md` (Precision &
Density direction), reconciled with AILA's existing midnight-cloud-8 theme +
cyber-tech accent treatment.

## Direction

**Personality:** Precision & Density (developer tool, high-information research surface)
**Foundation:** Warm charcoal (midnight-cloud-8 default), theme-switchable
**Depth:** Borders-only — flat, no dramatic shadows, no card lift

## Tokens

All resolved at runtime via CSS custom properties on `[data-theme]`. Never hardcode hex except for severity-specific channels (#97dbbe ok, #f0a8c7 warn, etc.).

### Spacing — 4px base, multiplicative
- micro:  4, 8         (icon gaps, badge padding, control padding-y)
- comp:   12, 16       (within cards, between paired controls)
- sect:   24, 32       (between sections of a page)
- major:  48           (rare, page-hero only)

### Typography — three-axis hierarchy
- Display: `var(--font-display)` — page titles + section headers ONLY
- Sans:    `var(--font-sans)`    — body, controls, labels
- Mono:    `var(--font-mono)`    — data, IDs, code, metrics with `tabular-nums`

Sizes: 10, 11, 12, 13 (base), 14, 16, 18, 20, 24, 30, 36
Weights: 400 regular, 500 medium, 600 semibold (no 700+ in normal flow)

### Text hierarchy — four levels, USE ALL FOUR
- `text-foreground`       — primary text (page titles, row titles, KPI numbers)
- `text-text`             — body (paragraphs, descriptions)
- `text-text-muted`       — labels, metadata, units
- `text-text-muted/60`    — placeholder, dividers, very low signal

### Borders — never demand attention
- Default:  `border-border` (= rgba ~0.08 alpha)
- Subtle:   `border-border-subtle` (= rgba ~0.05 alpha)
- Strong:   on hover: `border-accent/40` (= 40% accent)
- 0.5px or 1px max; never thicker except for severity edge

### Radius — sharp/technical
- 4px:  controls, badges, chips, metric tiles
- 6px:  cards, rows, primary surfaces
- 8px:  modals, drawers (sparingly)
- Never round (rounded-full) except for status pulses

### Severity channel — accent-orthogonal
The accent is theme-tinted (hot pink in midnight-cloud-8, teal in vaporwave,
etc.) and carries identity + critical-status meaning. Severity stays mapped
to a fixed semantic palette so "high" always reads as escalated regardless
of theme:
- crit:    var(--color-accent)  (theme-tinted hot signal)
- high:    #f0a8c7              (soft pink)
- medium:  #f0a8c7              (peach/pink)
- ok/low:  #97dbbe              (mint)
- info:    var(--color-text-muted) (neutral)

## Patterns

### Button — primary
- Height: 36 (compact), padding 8x16, radius 6
- Background: `var(--color-accent)`, color `var(--color-base)`
- Box-shadow: `0 0 16px color-mix(in srgb, var(--color-accent) 28%, transparent)` (subtle halo, accent-only)
- Hover: `translate-y-[-1px]`, transition 150ms

### Button — secondary
- Height: 32-36, padding 8x12, radius 4
- Background: `var(--color-surface)`, border 1px subtle, color foreground
- Hover: border-accent/40, no fill change

### Card
- Border: 1px solid border (NOT 0.5px — looks wrong on most monitors)
- Padding: 16 (compact) / 24 (spacious)
- Radius: 6
- Background: `var(--color-surface)`
- NO shadow. NO accent glow by default. The `techBorder` + `glow` opt-ins
  (added in commit f96c950) layer a hairline + hover glow when needed.

### Table — Precision pattern
The high-density default for any list >= ~10 rows where each row carries 4+ scannable fields.

```
- Wrap:           <table class="w-full border-collapse text-[13px]">
- Header row:     bg-base, sticky top-0, border-b border-border
- Header cell:    px-3 py-2, font-mono text-[11px] uppercase tracking-[0.08em] text-text-muted text-left
- Body row:       border-b border-border-subtle, hover:bg-surface/60, cursor-pointer
- Body cell:      px-3 py-2, align-top, tabular-nums for numeric columns
- Severity edge:  3px left edge per row (bg color from severity channel)
- Sort affordance: caret next to header label, color shift on active sort
- Selected row:   bg-surface/80 + border-l-accent (3px from default 0)
```

### KpiTile (already shipped — `components/aila/KpiTile.tsx`)
- 4-up grid at top of list pages
- Per-tile: severity-tinted left stripe + 40x40 icon square + label + value + hint
- Value uses display font; hint uses mono

### Badge — chip
Three sizes via `<AilaBadge size="sm|md|lg">`. Semantic severity drives color.

### Status pulse
`<SeverityPulse active={...}>` wraps a badge with a soft accent halo + pulse animation. Use for live/failing items only — never on neutral/completed rows.

### Row card — alternative to table
For pages with <10 rows OR when each row needs >1 logical line, use single-row cards: severity edge + favorite star + chip strip + title + meta + action group.

## Decisions

| Decision | Rationale | Date |
|---|---|---|
| Tables over card grids for list pages with 10+ rows | Operator scans columns; cards force eye to jump between tiles | 2026-05-22 |
| Severity stays orthogonal to accent | Themes change accent; severity must stay readable as "escalated" | 2026-05-22 |
| Borders 1px, not 0.5px | Half-pixel borders look broken on most monitors | 2026-05-22 |
| Sharp radius (4-6px) | Reinforces precision/research-tool feel | 2026-05-22 |
| Display font for page titles only | Sans for everything else keeps display font feeling deliberate | 2026-05-22 |
| `tabular-nums` mandatory on all numeric columns | Operator scans columns of numbers; non-tabular drifts | 2026-05-22 |
| No bounce / spring in transitions | Professional research surface; ease-out 150-200ms only | 2026-05-22 |
| KPI hero strip on every list page | Answers "is anything on fire" before operator scans rows | 2026-05-22 |

## Anti-patterns observed in this codebase

- `<AilaCard ...><h2>...` markup soup — fix when touching (move the h2 onto its own line)
- `text-sm` for row titles in dense tables (too big — use `text-[13px]` base)
- `font-display` on body text (looks chunky/marketing) — reserve for page H1 + section H2
- Inline `<h1>Title</h1>` on every page (handled — PageShell renders it now)
- Card grids for 30+ item list pages (cards force operator to skim across columns of tiles when they want to compare rows of values)

## File layout

- Shared primitives:    `frontend/src/components/aila/`
- Module-local components: `src/aila/modules/<m>/frontend/components/`
- Tokens (CSS):         `frontend/src/styles/themes.css`
- Theme provider:       `frontend/src/app/providers/ThemeProvider.tsx`
