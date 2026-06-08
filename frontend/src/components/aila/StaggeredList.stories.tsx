import type { Meta, StoryObj } from "@storybook/react"

import { AilaCard } from "./AilaCard"
import { StaggeredItem, StaggeredList } from "./StaggeredList"

const meta = {
  title: "AILA/StaggeredList",
  component: StaggeredList,
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    docs: {
      description: {
        component:
          "Orchestrated entrance for a list. The container holds the `staggerChildren` variant; each `<StaggeredItem>` inherits the cascade. One pass per mount — re-renders that keep stable keys do not replay. Respects `prefers-reduced-motion` via the `useReducedMotion` hook (A5 / B10).",
      },
    },
  },
  argTypes: {
    as: {
      control: "select",
      options: ["ul", "ol", "div", "section"],
      description: "Semantic tag for the container element.",
    },
  },
} satisfies Meta<typeof StaggeredList>

export default meta
type Story = StoryObj<typeof meta>

const SAMPLE = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]

export const ListOfCards: Story = {
  args: { as: "ul", className: "flex flex-col gap-2" },
  render: (args) => (
    <StaggeredList {...args}>
      {SAMPLE.map((name) => (
        <StaggeredItem as="li" key={name}>
          <AilaCard padding="md" variant="elevated">
            <span className="font-mono text-sm">{name}</span>
          </AilaCard>
        </StaggeredItem>
      ))}
    </StaggeredList>
  ),
  name: "List of cards",
}

export const GridOfCards: Story = {
  args: { as: "div", className: "grid grid-cols-3 gap-3" },
  render: (args) => (
    <StaggeredList {...args}>
      {SAMPLE.map((name) => (
        <StaggeredItem as="div" key={name}>
          <AilaCard padding="md" cornerAccents>
            <span className="font-mono text-sm">{name}</span>
          </AilaCard>
        </StaggeredItem>
      ))}
    </StaggeredList>
  ),
  name: "Grid of cards",
}

export const ReducedMotion: Story = {
  args: { as: "ul", className: "flex flex-col gap-2" },
  render: (args) => (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-text-muted">
        Toggle the OS reduced-motion preference and reload to see the
        cascade collapse to an instant render with no y-offset.
      </p>
      <StaggeredList {...args}>
        {SAMPLE.map((name) => (
          <StaggeredItem as="li" key={name}>
            <AilaCard padding="md" variant="elevated">
              <span className="font-mono text-sm">{name}</span>
            </AilaCard>
          </StaggeredItem>
        ))}
      </StaggeredList>
    </div>
  ),
  name: "Reduced motion",
}
