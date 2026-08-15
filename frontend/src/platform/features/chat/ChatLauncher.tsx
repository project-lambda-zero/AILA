/**
 * ChatLauncher (issue #211 enhancement 2).
 *
 * Console-styled empty-session launcher: an operator-console header
 * (eyebrow + greeting + subline) above a grid of quick-action lanes.
 * Each lane carries a purposeful phosphor glyph and, when clicked,
 * fills the composer input via `onPick(prompt)`; it never auto-sends.
 * Rendered by ChatPage's ThreadPanel in the empty-thread branch (no
 * persisted messages, not currently streaming) and hides once the
 * conversation starts.
 */
import { Terminal } from "@phosphor-icons/react/dist/csr/Terminal";
import { Crosshair } from "@phosphor-icons/react/dist/csr/Crosshair";
import { Detective } from "@phosphor-icons/react/dist/csr/Detective";
import { Virus } from "@phosphor-icons/react/dist/csr/Virus";
import { Fingerprint } from "@phosphor-icons/react/dist/csr/Fingerprint";
import { Pulse } from "@phosphor-icons/react/dist/csr/Pulse";
import { Compass } from "@phosphor-icons/react/dist/csr/Compass";

export type LauncherChip = {
  label: string;
  hint: string;
  prompt: string;
  Icon: typeof Terminal;
};

export const LAUNCHER_CHIPS: readonly LauncherChip[] = [
  {
    label: "Scan a host",
    hint: "Vulnerability scan",
    prompt:
      "Scan the host <ip-or-hostname> for known vulnerabilities and summarize the risk.",
    Icon: Crosshair,
  },
  {
    label: "VR investigation",
    hint: "Start a hunt",
    prompt:
      "Start a vulnerability-research investigation on <target>; what is the highest-value entry point?",
    Icon: Detective,
  },
  {
    label: "Analyze malware",
    hint: "Classify a sample",
    prompt:
      "Analyze the uploaded sample <name>: classify the family and summarize its capabilities.",
    Icon: Virus,
  },
  {
    label: "Forensics triage",
    hint: "Surface leads",
    prompt:
      "Triage the evidence in <project>: surface the strongest leads first.",
    Icon: Fingerprint,
  },
  {
    label: "Platform health",
    hint: "Workers + queues",
    prompt:
      "Summarize current platform health: workers, queue depth, and any degraded services.",
    Icon: Pulse,
  },
  {
    label: "What can you do?",
    hint: "Explore modules",
    prompt:
      "What can this platform do, and which module should I use for <goal>?",
    Icon: Compass,
  },
];

export interface ChatLauncherProps {
  onPick: (prompt: string) => void;
  greeting?: string;
  subline?: string;
}

export function ChatLauncher({
  onPick,
  greeting = "AILA console",
  subline = "Ask anything, or start from a lane below.",
}: ChatLauncherProps) {
  return (
    <div
      className="relative mx-auto my-auto flex w-full max-w-2xl flex-col gap-7 py-6"
      data-testid="chat-launcher"
      aria-label="Chat quick actions"
      style={{
        // Faint engineering dot-grid -- a subtle console texture behind
        // the launchpad. Cream at ~4% on an 18px lattice; one-off numeric,
        // so inline style per the Tailwind v4 arbitrary-value rule.
        backgroundImage:
          "radial-gradient(rgba(255, 215, 175, 0.045) 1px, transparent 1px)",
        backgroundSize: "18px 18px",
      }}
    >
      {/* Operator header -- eyebrow chip, display greeting, mono subline. */}
      <div className="flex flex-col gap-2.5">
        <div className="flex items-center gap-2 text-text-muted">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-[4px] border border-border bg-elevated text-accent">
            <Terminal size={13} weight="bold" />
          </span>
          <span className="font-mono text-[10px] font-semibold uppercase tracking-widest">
            Operator console
          </span>
        </div>
        <h2 className="text-2xl font-semibold text-text">{greeting}</h2>
        <span className="font-mono text-xs text-text-muted">{subline}</span>
      </div>

      {/* Quick lanes -- differentiated by glyph so it reads as a deliberate
          menu, not a wall of identical cards. */}
      <div className="flex flex-col gap-2.5">
        <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-text-muted">
          Quick lanes
        </span>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {LAUNCHER_CHIPS.map((chip) => {
            const ChipIcon = chip.Icon;
            return (
              <button
                key={chip.label}
                type="button"
                data-testid="chat-launcher-chip"
                data-launcher-label={chip.label}
                onClick={() => onPick(chip.prompt)}
                className="group flex items-center gap-3 rounded-[4px] border border-border bg-surface px-3 py-2.5 text-left transition-colors hover:border-accent focus:outline focus:outline-2 focus:outline-accent"
              >
                <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-[4px] border border-border bg-elevated text-text-muted transition-colors group-hover:border-accent group-hover:bg-accent/10 group-hover:text-accent">
                  <ChipIcon size={17} weight="bold" />
                </span>
                <span className="flex min-w-0 flex-col gap-0.5">
                  <span className="font-mono text-xs font-semibold text-text">
                    {chip.label}
                  </span>
                  <span className="font-mono text-[11px] text-text-muted">
                    {chip.hint}
                  </span>
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default ChatLauncher;
