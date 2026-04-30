import * as React from "react"
import type { Meta, StoryObj } from "@storybook/react"

import { PageTransition } from "./PageTransition"
import { AilaCard } from "./AilaCard"

const meta = {
  title: "AILA/PageTransition",
  component: PageTransition,
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    docs: {
      description: {
        component:
          "Route-level fade + slide animation wrapper (D-21). Uses motion/react (NOT framer-motion). Respects prefers-reduced-motion via useReducedMotion(). AnimatePresence mode=wait ensures exit animation completes before enter begins.",
      },
    },
  },
} satisfies Meta<typeof PageTransition>

export default meta
type Story = StoryObj<typeof meta>

export const Static: Story = {
  args: {
    motionKey: "static-page",
    children: (
      <AilaCard variant="default" padding="lg">
        <p className="font-mono text-text text-sm">
          PageTransition wrapper — this content fades + slides in when motionKey changes.
        </p>
      </AilaCard>
    ),
  },
  name: "Static (No Transition)",
}

function SwappableDemo() {
  const [page, setPage] = React.useState<"a" | "b">("a")

  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-2">
        <button
          onClick={() => setPage("a")}
          className="rounded-[2px] border border-border bg-surface px-3 py-1 font-mono text-xs text-text hover:border-border-hover transition-colors"
        >
          Page A
        </button>
        <button
          onClick={() => setPage("b")}
          className="rounded-[2px] border border-border bg-surface px-3 py-1 font-mono text-xs text-text hover:border-border-hover transition-colors"
        >
          Page B
        </button>
        <span className="font-mono text-text-muted text-xs self-center">
          Current: {page}
        </span>
      </div>

      <div className="relative min-h-32">
        <PageTransition motionKey={page}>
          {page === "a" ? (
            <AilaCard variant="elevated" padding="lg">
              <h2 className="font-mono text-text font-bold text-sm uppercase tracking-wider">Page A</h2>
              <p className="font-mono text-text-muted text-xs mt-2">
                Vulnerability Overview — 247 total findings across 4 systems.
              </p>
            </AilaCard>
          ) : (
            <AilaCard variant="elevated" padding="lg">
              <h2 className="font-mono text-text font-bold text-sm uppercase tracking-wider">Page B</h2>
              <p className="font-mono text-text-muted text-xs mt-2">
                System Detail — arch-vm — 45 active vulnerabilities, 12 critical.
              </p>
            </AilaCard>
          )}
        </PageTransition>
      </div>
    </div>
  )
}

export const Interactive: Story = {
  args: {
    motionKey: "interactive-demo",
    children: null,
  },
  render: () => <SwappableDemo />,
  name: "Interactive (Click to Swap)",
  parameters: {
    docs: {
      description: {
        story:
          "Click Page A / Page B to trigger the fade + 8px slide transition. The exit animation completes before the enter begins (mode=wait).",
      },
    },
  },
}

export const WithReducedMotion: Story = {
  args: {
    motionKey: "reduced-motion-demo",
    children: null,
  },
  render: () => (
    <div className="flex flex-col gap-2">
      <p className="font-mono text-text-muted text-xs">
        When prefers-reduced-motion is set, duration=0 and y offsets are removed.
        The component still renders children — animation is gracefully disabled.
      </p>
      <PageTransition motionKey="reduced-motion-demo">
        <AilaCard variant="default" padding="md">
          <p className="font-mono text-text text-sm">
            Content renders normally — motion removed for accessibility.
          </p>
        </AilaCard>
      </PageTransition>
    </div>
  ),
  name: "Reduced Motion Accessible",
}
