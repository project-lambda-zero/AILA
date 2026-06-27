import type { Meta, StoryObj } from "@storybook/react"
import { Shield } from "@phosphor-icons/react/dist/csr/Shield"
import { Lock } from "@phosphor-icons/react/dist/csr/Lock"
import { Scan } from "@phosphor-icons/react/dist/csr/Scan"

import { AilaCard } from "./AilaCard"
import { AilaBadge } from "./AilaBadge"

const meta = {
  title: "AILA/AilaCard",
  component: AilaCard,
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    docs: {
      description: {
        component:
          "Surface container with cyberpunk border elevation. No drop shadows (D-06). 4px radius (D-05). Amber border glow on interactive hover. Supports opt-in scroll-triggered reveal animation (D-21) via the `animate` prop.",
      },
    },
  },
  argTypes: {
    variant: {
      control: "select",
      options: ["default", "elevated", "interactive"],
      description: "Visual variant -- controls background and hover behavior",
    },
    padding: {
      control: "select",
      options: ["none", "sm", "md", "lg"],
      description: "Internal padding size",
    },
    animate: {
      control: "boolean",
      description: "Enable scroll-triggered reveal animation (fade-up, D-21)",
    },
    delay: {
      control: { type: "number", step: 0.05, min: 0, max: 1 },
      description: "Stagger delay in seconds for cascading card reveals",
    },
  },
} satisfies Meta<typeof AilaCard>

export default meta
type Story = StoryObj<typeof meta>

export const Default: Story = {
  args: {
    variant: "default",
    padding: "md",
    animate: false,
    children: "Default card -- surface background with static border",
  },
}

export const Elevated: Story = {
  args: {
    variant: "elevated",
    padding: "md",
    animate: false,
    children: "Elevated card -- slightly lighter background",
  },
}

export const Interactive: Story = {
  args: {
    variant: "interactive",
    padding: "md",
    animate: false,
    children: "Interactive card -- hover to see amber border glow",
  },
}

export const AnimatedReveal: Story = {
  name: "Animated Reveal (scroll-triggered)",
  args: {
    variant: "interactive",
    padding: "lg",
    animate: true,
    delay: 0,
    children: "This card fades up on scroll entry. Disabled under prefers-reduced-motion.",
  },
  parameters: {
    docs: {
      description: {
        story:
          "Scroll-triggered fade-up reveal via motion/react useInView (D-21). Set `animate=true` to enable. Use `delay` for staggered grids. Respects prefers-reduced-motion: instant reveal, no y offset.",
      },
    },
  },
}

export const StaggeredGrid: Story = {
  name: "Staggered Card Grid (animated)",
  render: () => (
    <div className="grid grid-cols-2 gap-3">
      {[
        { title: "Total Vulnerabilities", value: "247", severity: "neutral" as const, delay: 0 },
        { title: "Critical", value: "12", severity: "critical" as const, delay: 0.05 },
        { title: "High", value: "38", severity: "high" as const, delay: 0.1 },
        { title: "Medium", value: "91", severity: "medium" as const, delay: 0.15 },
      ].map((item) => (
        <AilaCard key={item.title} variant="elevated" padding="md" animate delay={item.delay} techBorder glow><p className="text-text-muted font-mono text-xs uppercase tracking-wider">{item.title}</p>
        <p className="text-text font-mono text-2xl font-bold mt-1">{item.value}</p>
        <div className="mt-2">
          <AilaBadge severity={item.severity} size="sm">{item.severity.toUpperCase()}</AilaBadge>
        </div></AilaCard>
      ))}
    </div>
  ),
  parameters: {
    docs: {
      description: {
        story: "Staggered reveal using the `delay` prop (0, 0.05, 0.1, 0.15 s). Cards cascade in sequence on scroll entry.",
      },
    },
  },
}

export const AllVariants: Story = {
  name: "All Variants",
  render: () => (
    <div className="flex flex-col gap-4">
      <AilaCard variant="default" padding="md" techBorder glow><p className="text-text font-sans text-sm">default -- static border</p></AilaCard>
      <AilaCard variant="elevated" padding="md" techBorder glow><p className="text-text font-sans text-sm">elevated -- elevated bg</p></AilaCard>
      <AilaCard variant="interactive" padding="md" techBorder glow><p className="text-text font-sans text-sm">interactive -- hover for amber glow</p></AilaCard>
    </div>
  ),
}

export const AllPaddings: Story = {
  name: "All Paddings",
  render: () => (
    <div className="flex flex-col gap-4">
      {(["none", "sm", "md", "lg"] as const).map((padding) => (
        <AilaCard key={padding} variant="default" padding={padding} techBorder glow><p className="text-text font-sans text-sm">padding=&quot;{padding}&quot;</p></AilaCard>
      ))}
    </div>
  ),
}

export const WithContent: Story = {
  name: "With Rich Content",
  render: () => (
    <AilaCard variant="interactive" padding="lg" techBorder glow><div className="flex items-start justify-between gap-4">
      <div className="flex flex-col gap-2">
        <h3 className="text-text font-sans text-base font-semibold">CVE-2024-1234</h3>
        <p className="text-text-muted font-sans text-sm">
          Remote code execution vulnerability in OpenSSL affecting versions prior to 3.2.1
        </p>
      </div>
      <AilaBadge severity="critical" size="md">
        CRITICAL
      </AilaBadge>
    </div>
    <div className="mt-4 flex gap-2">
      <AilaBadge severity="neutral" size="sm">CVSS 9.8</AilaBadge>
      <AilaBadge severity="neutral" size="sm">KEV</AilaBadge>
      <AilaBadge severity="neutral" size="sm">EPSS 0.94</AilaBadge>
    </div></AilaCard>
  ),
}

export const WithSecurityIcons: Story = {
  name: "With Security Icons (Phosphor)",
  render: () => (
    <div className="flex flex-col gap-4">
      {/* regular weight = inactive/monitoring state, fill = active/selected per D-08 */}
      <AilaCard variant="elevated" padding="md" techBorder glow><div className="flex items-center gap-3">
        <Shield size={20} className="text-text-muted" weight="regular" />
        <div>
          <p className="font-mono text-text text-sm font-medium">Security Monitoring</p>
          <p className="font-mono text-text-muted text-xs">Regular weight -- inactive state</p>
        </div>
      </div></AilaCard>
      <AilaCard variant="interactive" padding="md" techBorder glow><div className="flex items-center gap-3">
        <Shield size={20} className="text-accent" weight="fill" />
        <div>
          <p className="font-mono text-text text-sm font-medium">Shield Active</p>
          <p className="font-mono text-text-muted text-xs">Fill weight -- active/selected state (D-08)</p>
        </div>
      </div></AilaCard>
      <AilaCard variant="elevated" padding="md" techBorder glow><div className="flex items-center gap-3">
        <Lock size={20} className="text-mint" weight="fill" />
        <div>
          <p className="font-mono text-text text-sm font-medium">System Locked</p>
          <p className="font-mono text-text-muted text-xs">Mint (#97dbbe) for healthy/secured state (D-04b)</p>
        </div>
      </div></AilaCard>
      <AilaCard variant="elevated" padding="md" techBorder glow><div className="flex items-center gap-3">
        <Scan size={20} className="text-lavender" weight="duotone" />
        <div>
          <p className="font-mono text-text text-sm font-medium">Scan In Progress</p>
          <p className="font-mono text-text-muted text-xs">Lavender (#af87d7) for interactive state (D-04b)</p>
        </div>
      </div></AilaCard>
    </div>
  ),
  parameters: {
    docs: {
      description: {
        story:
          "Phosphor Icons (@phosphor-icons/react) demonstrate 6 weight variants. Convention (D-08): regular weight for inactive/monitoring states, fill for active/selected. Mint for success/healthy, lavender for interactive.",
      },
    },
  },
}

export const CardGrid: Story = {
  name: "Card Grid",
  render: () => (
    <div className="grid grid-cols-2 gap-3">
      {[
        { title: "Total Vulnerabilities", value: "247", severity: "neutral" as const },
        { title: "Critical", value: "12", severity: "critical" as const },
        { title: "High", value: "38", severity: "high" as const },
        { title: "Medium", value: "91", severity: "medium" as const },
      ].map((item) => (
        <AilaCard key={item.title} variant="elevated" padding="md" techBorder glow><p className="text-text-muted font-mono text-xs uppercase tracking-wider">{item.title}</p>
        <p className="text-text font-mono text-2xl font-bold mt-1">{item.value}</p>
        <div className="mt-2">
          <AilaBadge severity={item.severity} size="sm">{item.severity.toUpperCase()}</AilaBadge>
        </div></AilaCard>
      ))}
    </div>
  ),
}
