import type { Meta, StoryObj } from "@storybook/react"

import { AilaChart } from "./AilaChart"

// ─────────────────────────────────────────────────────────
// Mock data
// ─────────────────────────────────────────────────────────

const SEVERITY_DISTRIBUTION = [
  { name: "Critical", count: 12 },
  { name: "High",     count: 38 },
  { name: "Medium",   count: 91 },
  { name: "Low",      count: 106 },
]

const TREND_DATA = [
  { month: "Jan", critical: 8,  high: 24, medium: 67 },
  { month: "Feb", critical: 10, high: 31, medium: 72 },
  { month: "Mar", critical: 7,  high: 28, medium: 58 },
  { month: "Apr", critical: 12, high: 38, medium: 91 },
  { month: "May", critical: 9,  high: 33, medium: 84 },
  { month: "Jun", critical: 6,  high: 22, medium: 61 },
]

const PIE_DATA = [
  { name: "arch-vm",      systems: 45 },
  { name: "ubuntu-prod",  systems: 38 },
  { name: "debian-lab",   systems: 27 },
  { name: "alpine-srv",   systems: 19 },
]

// ─────────────────────────────────────────────────────────
// Meta
// ─────────────────────────────────────────────────────────

const meta = {
  title: "AILA/AilaChart",
  component: AilaChart,
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    docs: {
      description: {
        component:
          "Recharts wrapper with AILA design token colors (D-17). All colors use CSS variables (var(--color-*)) adapting automatically to dark/light theme. XAxis/YAxis use JetBrains Mono (D-03). Tooltip matches AilaCard styling.",
      },
    },
  },
  argTypes: {
    type: {
      control: "select",
      options: ["bar", "line", "area", "pie"],
      description: "Chart type",
    },
    size: {
      control: "select",
      options: ["sm", "md", "lg"],
      description: "Chart height",
    },
  },
} satisfies Meta<typeof AilaChart>

export default meta
type Story = StoryObj<typeof meta>

// ─────────────────────────────────────────────────────────
// Stories
// ─────────────────────────────────────────────────────────

export const BarChart: Story = {
  args: {
    type: "bar",
    data: SEVERITY_DISTRIBUTION,
    dataKey: "count",
    xKey: "name",
    size: "md",
    ariaLabel: "Severity distribution bar chart",
  },
  name: "Bar Chart — Severity Distribution",
}

export const LineChart: Story = {
  args: {
    type: "line",
    data: TREND_DATA,
    dataKey: "critical",
    xKey: "month",
    size: "md",
    ariaLabel: "Critical vulnerabilities trend line chart",
  },
  name: "Line Chart — Critical Trend",
}

export const AreaChart: Story = {
  args: {
    type: "area",
    data: TREND_DATA,
    dataKey: "medium",
    xKey: "month",
    size: "md",
    ariaLabel: "Medium vulnerabilities area chart",
  },
  name: "Area Chart — Medium Trend",
}

export const PieChart: Story = {
  args: {
    type: "pie",
    data: PIE_DATA,
    dataKey: "systems",
    xKey: "name",
    size: "md",
    ariaLabel: "Vulnerability distribution by system pie chart",
  },
  name: "Pie Chart — System Distribution",
}

export const AllSizes: Story = {
  name: "All Sizes",
  args: {
    type: "bar",
    data: SEVERITY_DISTRIBUTION,
    dataKey: "count",
  },
  render: () => (
    <div className="flex flex-col gap-4">
      <div>
        <p className="font-mono text-text-muted text-xs mb-2">size=sm</p>
        <AilaChart type="bar" data={SEVERITY_DISTRIBUTION} dataKey="count" xKey="name" size="sm" />
      </div>
      <div>
        <p className="font-mono text-text-muted text-xs mb-2">size=md</p>
        <AilaChart type="bar" data={SEVERITY_DISTRIBUTION} dataKey="count" xKey="name" size="md" />
      </div>
      <div>
        <p className="font-mono text-text-muted text-xs mb-2">size=lg</p>
        <AilaChart type="bar" data={SEVERITY_DISTRIBUTION} dataKey="count" xKey="name" size="lg" />
      </div>
    </div>
  ),
}

export const DashboardLayout: Story = {
  name: "Dashboard Layout",
  args: {
    type: "bar",
    data: SEVERITY_DISTRIBUTION,
    dataKey: "count",
  },
  render: () => (
    <div className="grid grid-cols-2 gap-4">
      <div className="bg-surface border border-border rounded-[4px] p-4">
        <p className="font-mono text-text-muted text-xs uppercase tracking-wider mb-3">Severity Distribution</p>
        <AilaChart
          type="bar"
          data={SEVERITY_DISTRIBUTION}
          dataKey="count"
          xKey="name"
          size="sm"
          colors={["var(--color-critical)", "var(--color-high)", "var(--color-medium)", "var(--color-low)"]}
        />
      </div>
      <div className="bg-surface border border-border rounded-[4px] p-4">
        <p className="font-mono text-text-muted text-xs uppercase tracking-wider mb-3">System Distribution</p>
        <AilaChart
          type="pie"
          data={PIE_DATA}
          dataKey="systems"
          xKey="name"
          size="sm"
        />
      </div>
      <div className="bg-surface border border-border rounded-[4px] p-4 col-span-2">
        <p className="font-mono text-text-muted text-xs uppercase tracking-wider mb-3">6-Month Critical Trend</p>
        <AilaChart
          type="area"
          data={TREND_DATA}
          dataKey="critical"
          xKey="month"
          size="sm"
        />
      </div>
    </div>
  ),
}
