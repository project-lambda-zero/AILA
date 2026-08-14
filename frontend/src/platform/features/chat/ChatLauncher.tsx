/**
 * ChatLauncher (issue #211 enhancement 2).
 *
 * Console-styled empty-session launcher: greeting line + a grid of
 * quick-action chips. Clicking a chip fills the composer input via
 * `onPick(prompt)`; it never auto-sends. Rendered by ChatPage's
 * ThreadPanel in the empty-thread branch (no persisted messages,
 * not currently streaming) and hides once the conversation starts.
 */

type LauncherChip = {
  label: string;
  hint: string;
  prompt: string;
};

const LAUNCHER_CHIPS: readonly LauncherChip[] = [
  {
    label: "Scan a host",
    hint: "Vulnerability scan",
    prompt:
      "Scan the host <ip-or-hostname> for known vulnerabilities and summarize the risk.",
  },
  {
    label: "VR investigation",
    hint: "Start a hunt",
    prompt:
      "Start a vulnerability-research investigation on <target>; what is the highest-value entry point?",
  },
  {
    label: "Analyze malware",
    hint: "Classify a sample",
    prompt:
      "Analyze the uploaded sample <name>: classify the family and summarize its capabilities.",
  },
  {
    label: "Forensics triage",
    hint: "Surface leads",
    prompt:
      "Triage the evidence in <project>: surface the strongest leads first.",
  },
  {
    label: "Platform health",
    hint: "Workers + queues",
    prompt:
      "Summarize current platform health: workers, queue depth, and any degraded services.",
  },
  {
    label: "What can you do?",
    hint: "Explore modules",
    prompt:
      "What can this platform do, and which module should I use for <goal>?",
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
      className="flex flex-col gap-4"
      data-testid="chat-launcher"
      aria-label="Chat quick actions"
    >
      <div className="flex flex-col gap-1">
        <span className="font-mono text-sm font-semibold text-text">
          {greeting}
        </span>
        <span className="font-mono text-xs text-text-muted">{subline}</span>
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {LAUNCHER_CHIPS.map((chip) => (
          <button
            key={chip.label}
            type="button"
            data-testid="chat-launcher-chip"
            data-launcher-label={chip.label}
            onClick={() => onPick(chip.prompt)}
            className="flex flex-col gap-1 rounded-sm border border-border bg-surface px-3 py-2 text-left font-mono transition-colors hover:border-accent hover:text-accent focus:outline focus:outline-2 focus:outline-accent"
          >
            <span className="text-xs font-semibold text-text">
              {chip.label}
            </span>
            <span className="text-[11px] text-text-muted">{chip.hint}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

export default ChatLauncher;
