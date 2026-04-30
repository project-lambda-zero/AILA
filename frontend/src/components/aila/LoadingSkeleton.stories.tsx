import type { Meta, StoryObj } from "@storybook/react"

import { LoadingSkeleton, LoadingSkeletonGroup } from "./LoadingSkeleton"

const meta = {
  title: "AILA/LoadingSkeleton",
  component: LoadingSkeleton,
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    backgrounds: {
      default: "dark",
    },
    docs: {
      description: {
        component:
          "Amber scan line skeleton placeholder (D-22). Thin amber line sweeps horizontally across dark surface. Pure CSS animation in globals.css (.skeleton-aila). Cyberpunk terminal loading aesthetic.",
      },
    },
  },
  argTypes: {
    size: {
      control: "select",
      options: ["sm", "md", "lg", "xl", "full"],
      description: "Height of the skeleton element",
    },
    width: {
      control: "select",
      options: ["full", "half", "third", "quarter", "auto"],
      description: "Width of the skeleton element",
    },
  },
} satisfies Meta<typeof LoadingSkeleton>

export default meta
type Story = StoryObj<typeof meta>

export const Default: Story = {
  args: {
    size: "md",
    width: "full",
  },
  decorators: [
    (Story) => (
      <div className="bg-base p-4 rounded-[4px]">
        <Story />
      </div>
    ),
  ],
}

export const AllSizes: Story = {
  name: "All Sizes",
  render: () => (
    <div className="bg-base p-4 rounded-[4px] flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <span className="font-mono text-text-muted text-xs">sm</span>
        <LoadingSkeleton size="sm" />
      </div>
      <div className="flex flex-col gap-1">
        <span className="font-mono text-text-muted text-xs">md</span>
        <LoadingSkeleton size="md" />
      </div>
      <div className="flex flex-col gap-1">
        <span className="font-mono text-text-muted text-xs">lg</span>
        <LoadingSkeleton size="lg" />
      </div>
      <div className="flex flex-col gap-1">
        <span className="font-mono text-text-muted text-xs">xl</span>
        <LoadingSkeleton size="xl" />
      </div>
    </div>
  ),
}

export const AllWidths: Story = {
  name: "All Widths",
  render: () => (
    <div className="bg-base p-4 rounded-[4px] flex flex-col gap-3">
      {(["full", "half", "third", "quarter"] as const).map((width) => (
        <div key={width} className="flex flex-col gap-1">
          <span className="font-mono text-text-muted text-xs">width={width}</span>
          <LoadingSkeleton size="sm" width={width} />
        </div>
      ))}
    </div>
  ),
}

export const ParagraphGroup: Story = {
  name: "LoadingSkeletonGroup (Paragraph)",
  render: () => (
    <div className="bg-base p-4 rounded-[4px] flex flex-col gap-6">
      <div>
        <p className="font-mono text-text-muted text-xs mb-2">lines=3 (default)</p>
        <LoadingSkeletonGroup lines={3} />
      </div>
      <div>
        <p className="font-mono text-text-muted text-xs mb-2">lines=5</p>
        <LoadingSkeletonGroup lines={5} />
      </div>
    </div>
  ),
}

export const CardLoading: Story = {
  name: "Card Loading State",
  render: () => (
    <div className="bg-surface border border-border rounded-[4px] p-4 flex flex-col gap-3 w-64">
      <LoadingSkeleton size="sm" width="half" />
      <LoadingSkeleton size="xl" />
      <LoadingSkeletonGroup lines={2} />
    </div>
  ),
}

export const TableLoading: Story = {
  name: "Table Loading State",
  render: () => (
    <div className="bg-surface border border-border rounded-[4px] overflow-hidden">
      <div className="bg-elevated px-4 py-2 border-b border-border">
        <LoadingSkeleton size="sm" width="quarter" />
      </div>
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="flex gap-4 px-4 py-3 border-b border-border last:border-0">
          <LoadingSkeleton size="sm" width="third" />
          <LoadingSkeleton size="sm" width="quarter" />
          <LoadingSkeleton size="sm" width="half" />
          <LoadingSkeleton size="sm" width="quarter" />
        </div>
      ))}
    </div>
  ),
}
