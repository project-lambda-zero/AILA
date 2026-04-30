import { useEffect, useRef, useState } from "react";

export interface HelpModalProps {
  instruction: string | null;
  guideline: string | null;
  helpText: string | null;
}

type TabKey = "instruction" | "guideline" | "help";

interface Tab {
  key: TabKey;
  label: string;
  content: string;
}

export function HelpModal({ instruction, guideline, helpText }: HelpModalProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<TabKey | null>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  const tabs: Tab[] = [];
  if (instruction) tabs.push({ key: "instruction", label: "Instruction", content: instruction });
  if (guideline) tabs.push({ key: "guideline", label: "Guideline", content: guideline });
  if (helpText) tabs.push({ key: "help", label: "Help", content: helpText });

  // Nothing to show
  if (tabs.length === 0) return null;

  function open() {
    setActiveTab(tabs[0].key);
    setIsOpen(true);
  }

  function close() {
    setIsOpen(false);
  }

  const currentContent = tabs.find((t) => t.key === activeTab)?.content ?? tabs[0].content;

  return (
    <>
      <button
        className="text-xs text-accent cursor-pointer hover:underline"
        type="button"
        aria-label="Show help"
        onClick={open}
      >
        i
      </button>

      {isOpen && (
        <HelpModalDialog
          tabs={tabs}
          activeTab={activeTab ?? tabs[0].key}
          currentContent={currentContent}
          onTabChange={setActiveTab}
          onClose={close}
          closeRef={closeRef}
        />
      )}
    </>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Modal dialog (focus-trapped)
// ──────────────────────────────────────────────────────────────────────────────

interface HelpModalDialogProps {
  tabs: Tab[];
  activeTab: TabKey;
  currentContent: string;
  onTabChange: (tab: TabKey) => void;
  onClose: () => void;
  closeRef: React.RefObject<HTMLButtonElement | null>;
}

function HelpModalDialog({
  tabs,
  activeTab,
  currentContent,
  onTabChange,
  onClose,
  closeRef,
}: HelpModalDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);

  // Focus the close button when modal opens
  useEffect(() => {
    closeRef.current?.focus();
  }, [closeRef]);

  // Close on Escape
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [onClose]);

  // Trap focus inside modal
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    function trapFocus(e: KeyboardEvent) {
      if (e.key !== "Tab") return;
      const focusable = dialog!.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    }
    dialog.addEventListener("keydown", trapFocus);
    return () => dialog.removeEventListener("keydown", trapFocus);
  }, []);

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center"
      role="dialog"
      aria-modal
      aria-label="Question help"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="bg-elevated border border-border rounded-[var(--radius-lg)] p-5 max-w-md w-full max-h-[80vh] overflow-y-auto"
        ref={dialogRef}
      >
        <div className="flex items-center justify-between mb-4">
          <span className="font-mono text-sm font-semibold text-text">Help</span>
          <button
            ref={closeRef}
            className="text-text-muted hover:text-text cursor-pointer"
            type="button"
            aria-label="Close help"
            onClick={onClose}
          >
            ×
          </button>
        </div>

        {tabs.length > 1 && (
          <div className="flex gap-1 mb-4" role="tablist">
            {tabs.map((tab) => (
              <button
                key={tab.key}
                className={[
                  "px-3 py-1.5 rounded-[var(--radius-sm)] font-mono text-xs cursor-pointer transition-colors hover:bg-surface",
                  activeTab === tab.key
                    ? "bg-accent-muted text-accent"
                    : "text-text-muted",
                ]
                  .filter(Boolean)
                  .join(" ")}
                role="tab"
                aria-selected={activeTab === tab.key}
                type="button"
                onClick={() => onTabChange(tab.key)}
              >
                {tab.label}
              </button>
            ))}
          </div>
        )}

        <div className="text-sm text-text-muted leading-relaxed">
          <p>{currentContent}</p>
        </div>
      </div>
    </div>
  );
}
