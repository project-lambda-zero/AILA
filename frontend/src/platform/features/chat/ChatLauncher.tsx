/**
 * ChatLauncher -- the empty-thread launcher, rebuilt from the design mock.
 *
 * Console-styled operator header (eyebrow chip + display greeting + subline)
 * above a grid of quick-action lanes. Each lane fills the composer via
 * `onPick(prompt)` -- never auto-sends. Preserves the `chat-launcher` and
 * `chat-launcher-chip` testids and the exported `LAUNCHER_CHIPS` shape.
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
    prompt: "Triage the evidence in <project>: surface the strongest leads first.",
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
    prompt: "What can this platform do, and which module should I use for <goal>?",
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
  greeting = "aila console",
  subline = "point me at a target -- a repo, a binary, a CVE, an APK -- or pick a lane.",
}: ChatLauncherProps) {
  return (
    <div
      data-testid="chat-launcher"
      aria-label="Chat quick actions"
      className="mx-auto my-auto flex w-full flex-col"
      style={{
        maxWidth: 620,
        padding: "24px 8px",
        gap: 22,
        fontFamily: "var(--font-mono)",
        backgroundImage:
          "radial-gradient(rgba(255, 215, 175, 0.045) 1px, transparent 1px)",
        backgroundSize: "18px 18px",
      }}
    >
      {/* Operator header -- eyebrow chip, display-font greeting, mono subline. */}
      <div className="flex flex-col" style={{ gap: 8 }}>
        <div className="flex items-center" style={{ gap: 9 }}>
          <span
            className="flex items-center justify-center"
            aria-hidden="true"
            style={{
              width: 30,
              height: 30,
              flex: "0 0 auto",
              border: "1px solid var(--accent)",
              background: "color-mix(in srgb, var(--accent) 12%, transparent)",
              borderRadius: 4,
              color: "var(--accent)",
            }}
          >
            <Terminal size={14} weight="bold" />
          </span>
          <span
            style={{
              fontSize: 9,
              letterSpacing: "0.18em",
              textTransform: "uppercase",
              color: "var(--text-muted)",
              fontWeight: 600,
            }}
          >
            operator console
          </span>
        </div>
        <h2
          style={{
            fontFamily: "var(--font-display)",
            fontWeight: 300,
            fontSize: 28,
            letterSpacing: "-0.01em",
            color: "var(--accent)",
            margin: 0,
          }}
        >
          {greeting}
        </h2>
        <span
          style={{
            fontSize: 12,
            color: "var(--text-muted)",
            fontFamily: "var(--font-sans)",
            lineHeight: 1.4,
          }}
        >
          {subline}
        </span>
      </div>

      {/* Quick lanes */}
      <div className="flex flex-col" style={{ gap: 9 }}>
        <span
          style={{
            fontSize: 9,
            letterSpacing: "0.18em",
            textTransform: "uppercase",
            color: "var(--text-faint)",
            fontWeight: 600,
          }}
        >
          quick lanes
        </span>
        <div
          className="grid"
          style={{ gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 6 }}
        >
          {LAUNCHER_CHIPS.map((chip) => {
            const ChipIcon = chip.Icon;
            return (
              <button
                key={chip.label}
                type="button"
                data-testid="chat-launcher-chip"
                data-launcher-label={chip.label}
                onClick={() => onPick(chip.prompt)}
                className="flex items-center text-left"
                style={{
                  gap: 10,
                  padding: "9px 10px",
                  background: "var(--surface-card)",
                  border: "1px solid var(--border-soft)",
                  borderRadius: 3,
                  cursor: "pointer",
                  fontFamily: "var(--font-mono)",
                  color: "var(--text-primary)",
                }}
              >
                <span
                  className="flex items-center justify-center"
                  style={{
                    width: 26,
                    height: 26,
                    flex: "0 0 auto",
                    border: "1px solid var(--border-soft)",
                    background: "var(--surface-sunk)",
                    color: "var(--accent)",
                    borderRadius: 3,
                  }}
                >
                  <ChipIcon size={14} weight="bold" aria-hidden="true" />
                </span>
                <span className="flex min-w-0 flex-col" style={{ gap: 2 }}>
                  <span style={{ fontSize: 11, color: "var(--text-primary)" }}>
                    {chip.label}
                  </span>
                  <span style={{ fontSize: 9.5, color: "var(--text-faint)" }}>
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
