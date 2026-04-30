import type { Meta, StoryObj } from "@storybook/react"
import type { ColumnDef } from "@tanstack/react-table"
import React from "react"

import { AilaTable } from "./AilaTable"
import { AilaBadge } from "./AilaBadge"

// ─────────────────────────────────────────────────────────
// Mock data — vulnerability-like objects
// ─────────────────────────────────────────────────────────

type Severity = "critical" | "high" | "medium" | "low"

interface VulnRow {
  id: string
  cve: string
  severity: Severity
  system: string
  score: number
  status: string
}

const MOCK_DATA: VulnRow[] = [
  { id: "1",  cve: "CVE-2024-1234", severity: "critical", system: "arch-vm",       score: 9.8, status: "open" },
  { id: "2",  cve: "CVE-2024-5678", severity: "high",     system: "ubuntu-prod",   score: 7.5, status: "open" },
  { id: "3",  cve: "CVE-2023-9999", severity: "medium",   system: "debian-lab",    score: 5.3, status: "triaged" },
  { id: "4",  cve: "CVE-2023-0001", severity: "low",      system: "alpine-srv",    score: 2.1, status: "closed" },
  { id: "5",  cve: "CVE-2024-2222", severity: "critical", system: "arch-vm",       score: 9.1, status: "open" },
  { id: "6",  cve: "CVE-2024-3333", severity: "high",     system: "ubuntu-prod",   score: 8.2, status: "open" },
  { id: "7",  cve: "CVE-2024-4444", severity: "medium",   system: "debian-lab",    score: 6.0, status: "triaged" },
  { id: "8",  cve: "CVE-2024-5555", severity: "low",      system: "alpine-srv",    score: 3.2, status: "closed" },
  { id: "9",  cve: "CVE-2023-6666", severity: "high",     system: "arch-vm",       score: 7.9, status: "open" },
  { id: "10", cve: "CVE-2023-7777", severity: "medium",   system: "ubuntu-prod",   score: 4.5, status: "triaged" },
  { id: "11", cve: "CVE-2022-8888", severity: "critical", system: "debian-lab",    score: 9.5, status: "open" },
  { id: "12", cve: "CVE-2022-9999", severity: "low",      system: "alpine-srv",    score: 1.8, status: "closed" },
  { id: "13", cve: "CVE-2024-0011", severity: "high",     system: "arch-vm",       score: 8.0, status: "open" },
  { id: "14", cve: "CVE-2024-0022", severity: "medium",   system: "ubuntu-prod",   score: 5.7, status: "triaged" },
  { id: "15", cve: "CVE-2024-0033", severity: "low",      system: "debian-lab",    score: 2.9, status: "closed" },
  { id: "16", cve: "CVE-2024-0044", severity: "critical", system: "alpine-srv",    score: 9.9, status: "open" },
  { id: "17", cve: "CVE-2024-0055", severity: "high",     system: "arch-vm",       score: 7.2, status: "open" },
  { id: "18", cve: "CVE-2024-0066", severity: "medium",   system: "ubuntu-prod",   score: 4.8, status: "triaged" },
  { id: "19", cve: "CVE-2024-0077", severity: "low",      system: "debian-lab",    score: 1.5, status: "closed" },
  { id: "20", cve: "CVE-2024-0088", severity: "critical", system: "alpine-srv",    score: 9.3, status: "open" },
]

const columns: ColumnDef<VulnRow>[] = [
  {
    accessorKey: "cve",
    header: "CVE ID",
    cell: ({ row }) => (
      <code className="font-mono text-text text-xs">{row.original.cve}</code>
    ),
  },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ row }) => (
      <AilaBadge severity={row.original.severity} size="sm">
        {row.original.severity.toUpperCase()}
      </AilaBadge>
    ),
  },
  {
    accessorKey: "system",
    header: "System",
    cell: ({ row }) => (
      <span className="font-mono text-text-muted text-xs">{row.original.system}</span>
    ),
  },
  {
    accessorKey: "score",
    header: "CVSS",
    cell: ({ row }) => (
      <span className="font-mono text-accent text-sm font-bold">{row.original.score.toFixed(1)}</span>
    ),
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => (
      <span className="font-mono text-text-muted text-xs uppercase">{row.original.status}</span>
    ),
  },
]

// ─────────────────────────────────────────────────────────
// Meta
// ─────────────────────────────────────────────────────────

// Using a render-only meta to avoid required args inference issues with generic component
const meta: Meta = {
  title: "AILA/AilaTable",
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    docs: {
      description: {
        component:
          "Headless TanStack Table with cyberpunk styling (D-16). Compound component pattern (D-20): AilaTable.Header, AilaTable.Body, AilaTable.Pagination. Sorting, filtering, and pagination built-in. Pagination always enabled to prevent unbounded render (T-139-06).",
      },
    },
  },
}

export default meta
type Story = StoryObj

// ─────────────────────────────────────────────────────────
// Stories
// ─────────────────────────────────────────────────────────

export const Default: Story = {
  render: () => (
    <AilaTable data={MOCK_DATA} columns={columns} enableSorting pageSize={10} />
  ),
  name: "Default (Sortable)",
}

export const WithFiltering: Story = {
  render: () => (
    <AilaTable data={MOCK_DATA} columns={columns} enableFiltering pageSize={10}>
      <AilaTable.Header />
      <AilaTable.Body />
      <AilaTable.Pagination />
    </AilaTable>
  ),
  name: "With Global Filter",
  parameters: {
    docs: {
      description: {
        story: "Type to filter across all columns. Uses TanStack Table getFilteredRowModel().",
      },
    },
  },
}

export const SmallPageSize: Story = {
  render: () => (
    <AilaTable data={MOCK_DATA} columns={columns} pageSize={5}>
      <AilaTable.Header />
      <AilaTable.Body />
      <AilaTable.Pagination pageSizeOptions={[5, 10, 20]} />
    </AilaTable>
  ),
  name: "Small Page Size (5)",
}

export const EmptyState: Story = {
  render: () => (
    <AilaTable<VulnRow> data={[]} columns={columns}>
      <AilaTable.Header />
      <AilaTable.Body emptyState="No vulnerabilities found. System is clean." />
      <AilaTable.Pagination />
    </AilaTable>
  ),
  name: "Empty State",
}

export const CompoundUsage: Story = {
  render: () => (
    <div className="flex flex-col gap-2">
      <h2 className="font-mono text-text text-sm uppercase tracking-wider">Vulnerability Report</h2>
      <AilaTable data={MOCK_DATA} columns={columns} enableFiltering enableSorting pageSize={5}>
        <AilaTable.Header />
        <AilaTable.Body />
        <AilaTable.Pagination pageSizeOptions={[5, 10, 25]} />
      </AilaTable>
    </div>
  ),
  name: "Compound Component Usage",
}
