import type { Meta, StoryObj } from "@storybook/react"
import { ShieldWarning, Bug, Warning, ShieldCheck, ShieldSlash } from "@phosphor-icons/react"

import { AilaBadge } from "./AilaBadge"

const meta = {
  title: "AILA/AilaBadge",
  component: AilaBadge,
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    docs: {
      description: {
        component:
          "Severity badge with WCAG-compliant text colors. 2px radius (D-05). CVA variants for severity (D-04, D-04b). Optional CSS pulse animation (D-18). 150ms hover transition on all variants.",
      },
    },
  },
  argTypes: {
    severity: {
      control: "select",
      options: ["critical", "high", "medium", "low", "info", "neutral"],
      description: "Severity level — determines color scheme",
    },
    size: {
      control: "select",
      options: ["sm", "md", "lg"],
      description: "Badge size",
    },
    solid: {
      control: "boolean",
      description: "Solid background with dark badge text (WCAG AA on colored bg)",
    },
    pulse: {
      control: "boolean",
      description: "Apply severity-pulse CSS animation (D-18)",
    },
  },
} satisfies Meta<typeof AilaBadge>

export default meta
type Story = StoryObj<typeof meta>

export const Default: Story = {
  args: {
    severity: "critical",
    size: "md",
    solid: false,
    pulse: false,
    children: "CRITICAL",
  },
}

export const AllSeverities: Story = {
  name: "All Severity Variants",
  render: () => (
    <div className="flex flex-wrap gap-3">
      <AilaBadge severity="critical">CRITICAL</AilaBadge>
      <AilaBadge severity="high">HIGH</AilaBadge>
      <AilaBadge severity="medium">MEDIUM</AilaBadge>
      <AilaBadge severity="low">LOW</AilaBadge>
      <AilaBadge severity="info">INFO</AilaBadge>
      <AilaBadge severity="neutral">NEUTRAL</AilaBadge>
    </div>
  ),
}

export const SolidVariants: Story = {
  name: "Solid Variants (WCAG AA)",
  render: () => (
    <div className="flex flex-wrap gap-3">
      <AilaBadge severity="critical" solid>CRITICAL</AilaBadge>
      <AilaBadge severity="high" solid>HIGH</AilaBadge>
      <AilaBadge severity="medium" solid>MEDIUM</AilaBadge>
      <AilaBadge severity="low" solid>LOW</AilaBadge>
      <AilaBadge severity="info" solid>INFO</AilaBadge>
    </div>
  ),
  parameters: {
    docs: {
      description: {
        story: "Solid badges use text-badge-text (#131313) on colored backgrounds for WCAG AA compliance.",
      },
    },
  },
}

export const AllSizes: Story = {
  name: "All Sizes",
  render: () => (
    <div className="flex flex-wrap items-center gap-3">
      <AilaBadge severity="critical" size="sm">CRITICAL SM</AilaBadge>
      <AilaBadge severity="high" size="md">HIGH MD</AilaBadge>
      <AilaBadge severity="medium" size="lg">MEDIUM LG</AilaBadge>
    </div>
  ),
}

export const PulsingCritical: Story = {
  name: "Pulsing Critical",
  render: () => (
    <div className="flex gap-3 items-center">
      <AilaBadge severity="critical" pulse>CRITICAL</AilaBadge>
      <span className="text-text-muted font-mono text-xs">Pulse active (CSS animation)</span>
    </div>
  ),
  parameters: {
    docs: {
      description: {
        story: "CSS-only severity pulse animation (D-18). opacity 1 → 0.5 → 1 cycle at 2s. Respects prefers-reduced-motion.",
      },
    },
  },
}

export const WithIcons: Story = {
  name: "With Phosphor Icons (D-08)",
  render: () => (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-3">
        {/* fill weight for active/severity state per D-08 */}
        <AilaBadge severity="critical" size="md">
          <ShieldWarning weight="fill" size={12} className="mr-1" />
          CRITICAL
        </AilaBadge>
        <AilaBadge severity="high" size="md">
          <Warning weight="fill" size={12} className="mr-1" />
          HIGH
        </AilaBadge>
        <AilaBadge severity="medium" size="md">
          <Bug weight="fill" size={12} className="mr-1" />
          MEDIUM
        </AilaBadge>
        <AilaBadge severity="low" size="md">
          <ShieldCheck weight="fill" size={12} className="mr-1" />
          LOW
        </AilaBadge>
        <AilaBadge severity="info" size="md">
          <ShieldSlash weight="fill" size={12} className="mr-1" />
          INFO
        </AilaBadge>
      </div>
      <div className="flex flex-wrap gap-3">
        {/* solid variant with icons */}
        <AilaBadge severity="critical" solid size="md">
          <ShieldWarning weight="fill" size={12} className="mr-1" />
          CRITICAL
        </AilaBadge>
        <AilaBadge severity="high" solid size="md">
          <Warning weight="fill" size={12} className="mr-1" />
          HIGH
        </AilaBadge>
        <AilaBadge severity="medium" solid size="md">
          <Bug weight="fill" size={12} className="mr-1" />
          MEDIUM
        </AilaBadge>
      </div>
    </div>
  ),
  parameters: {
    docs: {
      description: {
        story:
          "Phosphor Icons (@phosphor-icons/react) integrated with severity badges. Fill weight used for active severity states (D-08). Icons are 12px to match badge font-size. Tree-shakeable — only imported icons are bundled.",
      },
    },
  },
}

export const SecurityDashboard: Story = {
  name: "Security Dashboard Row",
  render: () => (
    <div className="flex flex-col gap-2">
      {[
        { cve: "CVE-2024-1234", severity: "critical" as const, system: "arch-vm", score: 9.8 },
        { cve: "CVE-2024-5678", severity: "high" as const, system: "ubuntu-prod", score: 7.5 },
        { cve: "CVE-2023-9999", severity: "medium" as const, system: "debian-lab", score: 5.3 },
        { cve: "CVE-2023-0001", severity: "low" as const, system: "alpine-srv", score: 2.1 },
      ].map((row) => (
        <div
          key={row.cve}
          className="flex items-center justify-between gap-4 rounded-[4px] border border-border bg-surface px-4 py-2"
        >
          <code className="font-mono text-text text-sm">{row.cve}</code>
          <AilaBadge severity={row.severity} size="sm">
            {row.severity.toUpperCase()}
          </AilaBadge>
          <span className="font-mono text-text-muted text-xs">{row.system}</span>
          <span className="font-mono text-accent text-sm font-bold">{row.score}</span>
        </div>
      ))}
    </div>
  ),
}
