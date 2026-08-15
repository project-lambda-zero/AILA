import { Button as ButtonPrimitive } from "@base-ui/react/button"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  // AILA workbench button: mono UPPERCASE label, wide tracking, sharp
  // --radius-sm (3px), raised key-cap bevel (--bevel-key) that swaps to
  // a pressed inset (--bevel-pressed) + 1px translate on :active.
  "group/button inline-flex shrink-0 items-center justify-center rounded-[3px] border border-transparent bg-clip-padding font-mono text-sm font-medium uppercase tracking-wider whitespace-nowrap shadow-[var(--bevel-key)] transition-all duration-150 ease-out outline-none select-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 active:not-aria-[haspopup]:translate-y-px active:shadow-[var(--bevel-pressed)] disabled:pointer-events-none disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 aria-invalid:border-destructive/50 aria-invalid:ring-destructive/40 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        // Primary CTA -- hot-pink fill on near-black on-accent text.
        // Reserve for the single primary action on a surface.
        default: "bg-primary text-[var(--text-on-accent)] hover:brightness-105",
        // Bordered action -- bright hairline, fills to elevated chrome
        // on hover.
        outline:
          "border-[var(--color-border-bright)] bg-transparent text-foreground hover:bg-elevated hover:text-foreground aria-expanded:bg-elevated aria-expanded:text-foreground",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-[var(--color-hover)] aria-expanded:bg-[var(--color-hover)] aria-expanded:text-secondary-foreground",
        // Ghost -- transparent, cream hairline brightening 0.20 -> 0.40
        // on hover. No key bevel; nothing to raise.
        ghost:
          "border-text/20 bg-transparent text-foreground shadow-none hover:border-text/40 active:shadow-none aria-expanded:border-text/40 aria-expanded:bg-elevated",
        destructive:
          "border-destructive/30 bg-destructive/15 text-destructive shadow-none hover:bg-destructive/25 focus-visible:border-destructive/40 focus-visible:ring-destructive/40 active:shadow-none",
        link: "border-transparent text-primary normal-case tracking-normal shadow-none underline-offset-4 hover:underline active:shadow-none",
      },
      size: {
        default:
          "h-8 gap-1.5 px-2.5 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2",
        xs: "h-6 gap-1 rounded-[min(var(--radius-md),10px)] px-2 text-xs in-data-[slot=button-group]:rounded-lg has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3",
        sm: "h-7 gap-1 rounded-[min(var(--radius-md),12px)] px-2.5 text-[0.8rem] in-data-[slot=button-group]:rounded-lg has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3.5",
        lg: "h-9 gap-1.5 px-2.5 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2",
        icon: "size-8",
        "icon-xs":
          "size-6 rounded-[min(var(--radius-md),10px)] in-data-[slot=button-group]:rounded-lg [&_svg:not([class*='size-'])]:size-3",
        "icon-sm":
          "size-7 rounded-[min(var(--radius-md),12px)] in-data-[slot=button-group]:rounded-lg",
        "icon-lg": "size-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant = "default",
  size = "default",
  ...props
}: ButtonPrimitive.Props & VariantProps<typeof buttonVariants>) {
  return (
    <ButtonPrimitive
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
