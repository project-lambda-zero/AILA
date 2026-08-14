import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  SHORTCUT_GROUPS,
  useKeyboardShortcuts,
} from "@/providers/KeyboardShortcutsProvider";
import { cn } from "@/lib/utils";

/**
 * Cheatsheet overlay listing every registered global shortcut.
 *
 * Rendered once at the app root (inside the AppShell so it inherits the
 * router context that the underlying `<Dialog>` -- base-ui -- portals
 * against). Open/close state lives in the shared
 * {@link useKeyboardShortcuts} context so the "?" key handler in
 * {@link KeyboardShortcutsController} and any future in-app trigger
 * (footer button, header help icon) all drive the same modal.
 *
 * The dialog closes on Escape and backdrop click via base-ui's default
 * behaviour; the underlying `DialogOverlay` already uses
 * `data-open:animate-in` / `data-closed:animate-out` classes that map
 * to reduced-motion-aware keyframes in Tailwind's animate plugin.
 */

function ChordKey({ children }: { children: string }) {
  return (
    <kbd
      className={cn(
        "inline-flex min-w-[1.5rem] items-center justify-center rounded",
        "border border-border bg-muted px-1.5 py-0.5",
        "font-mono text-[0.7rem] leading-none text-foreground",
      )}
    >
      {children}
    </kbd>
  );
}

function renderChord(chord: string) {
  // Space-separated chord tokens ("g d") render as two keys with a
  // "then" separator; "+"-separated tokens ("Cmd/Ctrl + K") render as
  // simultaneous keys joined by "+".
  if (chord.includes(" + ")) {
    const parts = chord.split(" + ");
    return (
      <span className="inline-flex items-center gap-1">
        {parts.map((part, i) => (
          <span key={`${part}-${i}`} className="inline-flex items-center gap-1">
            {i > 0 && <span className="text-muted-foreground">+</span>}
            <ChordKey>{part}</ChordKey>
          </span>
        ))}
      </span>
    );
  }
  if (chord.includes(" ")) {
    const parts = chord.split(" ");
    return (
      <span className="inline-flex items-center gap-1">
        {parts.map((part, i) => (
          <span key={`${part}-${i}`} className="inline-flex items-center gap-1">
            {i > 0 && (
              <span className="text-[0.65rem] text-muted-foreground">then</span>
            )}
            <ChordKey>{part}</ChordKey>
          </span>
        ))}
      </span>
    );
  }
  return <ChordKey>{chord}</ChordKey>;
}

export function ShortcutsCheatsheet() {
  const { isCheatsheetOpen, closeCheatsheet } = useKeyboardShortcuts();

  return (
    <Dialog
      open={isCheatsheetOpen}
      onOpenChange={(open) => {
        if (!open) closeCheatsheet();
      }}
    >
      <DialogContent
        className="sm:max-w-md"
        aria-label="Keyboard shortcuts"
      >
        <DialogHeader>
          <DialogTitle>Keyboard shortcuts</DialogTitle>
          <DialogDescription>
            Press{" "}
            <kbd className="rounded border border-border bg-muted px-1 py-0.5 font-mono text-[0.7rem]">
              ?
            </kbd>{" "}
            anywhere to open this list.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          {SHORTCUT_GROUPS.map((group) => (
            <section key={group.title} className="flex flex-col gap-2">
              <h2 className="text-[0.7rem] font-semibold uppercase tracking-wider text-muted-foreground">
                {group.title}
              </h2>
              <ul className="flex flex-col gap-1.5">
                {group.entries.map((entry) => (
                  <li
                    key={`${group.title}-${entry.chord}`}
                    className="flex items-center justify-between gap-3 text-sm"
                  >
                    <span className="flex flex-col">
                      <span className="text-foreground">{entry.label}</span>
                      {entry.hint && (
                        <span className="font-mono text-[0.7rem] text-muted-foreground">
                          {entry.hint}
                        </span>
                      )}
                    </span>
                    {renderChord(entry.chord)}
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
