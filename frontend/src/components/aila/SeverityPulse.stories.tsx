import type { Meta, StoryObj } from "@storybook/react"

import { SeverityPulse } from "./SeverityPulse"
import { AilaBadge } from "./AilaBadge"

const meta = {
  title: "AILA/SeverityPulse",
  component: SeverityPulse,
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    docs: {
      description: {
        component:
          "Wrapper that conditionally applies the severity-pulse CSS animation (D-18). Pure CSS keyframe -- opacity 1 → 0.5 → 1. Respects prefers-reduced-motion. No JS animation code.",
      },
    },
  },
  argTypes: {
    active: {
      control: "boolean",
      description: "When true, applies animate-severity-pulse CSS class",
    },
  },
} satisfies Meta<typeof SeverityPulse>

export default meta
type Story = StoryObj<typeof meta>

export const Active: Story = {
  args: {
    active: true,
    children: (
      <AilaBadge severity="critical" size="md">
        CRITICAL
      </AilaBadge>
    ),
  },
}

export const Inactive: Story = {
  args: {
    active: false,
    children: (
      <AilaBadge severity="critical" size="md">
        CRITICAL
      </AilaBadge>
    ),
  },
}

export const Comparison: Story = {
  name: "Active vs Inactive Comparison",
  render: () => (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-4">
        <span className="font-mono text-text-muted text-xs w-20">active=true</span>
        <SeverityPulse active>
          <AilaBadge severity="critical">CRITICAL</AilaBadge>
        </SeverityPulse>
      </div>
      <div className="flex items-center gap-4">
        <span className="font-mono text-text-muted text-xs w-20">active=false</span>
        <SeverityPulse active={false}>
          <AilaBadge severity="critical">CRITICAL</AilaBadge>
        </SeverityPulse>
      </div>
      <div className="flex items-center gap-4">
        <span className="font-mono text-text-muted text-xs w-20">high pulse</span>
        <SeverityPulse active>
          <AilaBadge severity="high">HIGH</AilaBadge>
        </SeverityPulse>
      </div>
    </div>
  ),
}

export const WithContent: Story = {
  name: "Wrapping Rich Content",
  render: () => (
    <SeverityPulse active className="rounded-[4px] border border-critical/40 bg-critical/10 px-4 py-3">
      <div className="flex items-center gap-3">
        <AilaBadge severity="critical" pulse>CRITICAL</AilaBadge>
        <span className="font-mono text-text text-sm">CVE-2024-1234 detected on arch-vm</span>
      </div>
    </SeverityPulse>
  ),
}
