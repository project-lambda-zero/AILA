import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { CheckCircle } from "@phosphor-icons/react/dist/csr/CheckCircle";
import { ArrowRight } from "@phosphor-icons/react/dist/csr/ArrowRight";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { FilterChip } from "@/components/aila/mock";
import {
  useCreateSystem,
  type SystemMutationInput,
} from "@platform/features/systems/api";
import {
  useSubmitScan,
  type ScanSubmissionRequest,
} from "@platform/features/scans/api";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STORAGE_KEY = "aila-onboarding-done";
const TOTAL_STEPS = 4;

const STEP_LABELS = ["welcome", "target", "run", "done"] as const;

const DEFAULT_SYSTEM_FORM: SystemMutationInput = {
  name: "",
  host: "",
  username: "root",
  port: 22,
  distro: "unknown",
  description: "",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isOnboardingDone(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === "true";
  } catch {
    return false;
  }
}

function markOnboardingDone(): void {
  try {
    localStorage.setItem(STORAGE_KEY, "true");
  } catch {
    // localStorage unavailable -- ignore
  }
}

// ---------------------------------------------------------------------------
// Style tokens
// ---------------------------------------------------------------------------

const INPUT_STYLE: React.CSSProperties = {
  height: 32,
  fontSize: 12,
  padding: "0 10px",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
  fontFamily: "var(--font-mono)",
  width: "100%",
};

const LABEL_STYLE: React.CSSProperties = {
  fontSize: 10,
  color: "var(--text-muted)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  letterSpacing: "0.12em",
};

const PRIMARY_BUTTON_STYLE: React.CSSProperties = {
  height: 30,
  fontSize: 11,
  padding: "0 14px",
  textTransform: "uppercase",
  letterSpacing: "0.12em",
  background: "var(--accent)",
  color: "var(--text-on-accent)",
  border: "1px solid var(--accent)",
  borderRadius: 3,
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
};

const SECONDARY_BUTTON_STYLE: React.CSSProperties = {
  height: 30,
  fontSize: 11,
  padding: "0 14px",
  textTransform: "uppercase",
  letterSpacing: "0.12em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
};

const GHOST_LINK_STYLE: React.CSSProperties = {
  fontSize: 10,
  color: "var(--text-muted)",
  background: "transparent",
  border: "none",
  cursor: "pointer",
  textTransform: "uppercase",
  letterSpacing: "0.12em",
  fontFamily: "var(--font-mono)",
  padding: "0 6px",
};

const ERROR_BOX_STYLE: React.CSSProperties = {
  border:
    "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
  background:
    "color-mix(in srgb, var(--status-warn) 10%, transparent)",
  color: "var(--status-warn)",
  padding: "8px 12px",
  fontSize: 11,
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

// ---------------------------------------------------------------------------
// Step indicator
// ---------------------------------------------------------------------------

function StepChips({ current }: { current: number }) {
  return (
    <div
      className="flex items-center flex-wrap"
      style={{ gap: 6 }}
      aria-label={`Step ${current} of ${TOTAL_STEPS}`}
    >
      {STEP_LABELS.map((label, i) => {
        const stepNum = i + 1;
        const active = stepNum === current;
        const done = stepNum < current;
        return (
          <FilterChip
            key={label}
            active={active || done}
            color={done ? "var(--status-ok)" : "var(--accent)"}
          >
            {stepNum}. {label}
          </FilterChip>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 1: Welcome
// ---------------------------------------------------------------------------

function StepWelcome({
  onNext,
  onSkip,
}: {
  onNext: () => void;
  onSkip: () => void;
}) {
  return (
    <div
      className="flex flex-col items-center text-center"
      style={{ gap: 20, padding: "12px 0" }}
    >
      <div
        className="flex items-center justify-center font-mono"
        style={{
          width: 56,
          height: 56,
          background:
            "color-mix(in srgb, var(--accent) 12%, transparent)",
          border:
            "2px solid color-mix(in srgb, var(--accent) 45%, transparent)",
          borderRadius: 3,
          fontSize: 22,
          fontWeight: 700,
          color: "var(--accent)",
        }}
      >
        A
      </div>
      <div className="flex flex-col" style={{ gap: 8 }}>
        <h2
          className="font-mono"
          style={{
            fontSize: 18,
            color: "var(--text-primary)",
            fontFamily: "var(--font-display)",
            textTransform: "uppercase",
            letterSpacing: "0.14em",
          }}
        >
          welcome to aila
        </h2>
        <p
          className="font-mono"
          style={{
            fontSize: 12,
            color: "var(--text-muted)",
            maxWidth: 380,
            lineHeight: 1.5,
          }}
        >
          AI Lab Assistant -- your modular security platform for vulnerability
          scanning and fleet management. Let&apos;s get you set up in 4 quick
          steps.
        </p>
      </div>
      <div className="flex flex-col" style={{ gap: 8, width: "100%" }}>
        <button
          type="button"
          onClick={onNext}
          style={{ ...PRIMARY_BUTTON_STYLE, width: "100%", justifyContent: "center" }}
        >
          get started
          <ArrowRight size={14} />
        </button>
        <button type="button" onClick={onSkip} style={GHOST_LINK_STYLE}>
          skip setup
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 2: Register System
// ---------------------------------------------------------------------------

function StepRegisterSystem({
  onNext,
  onBack,
  onSkip,
  onSystemRegistered,
}: {
  onNext: () => void;
  onBack: () => void;
  onSkip: () => void;
  onSystemRegistered: (host: string) => void;
}) {
  const [form, setForm] = useState<SystemMutationInput>(DEFAULT_SYSTEM_FORM);
  const createSystem = useCreateSystem();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    createSystem.mutate(form, {
      onSuccess: () => {
        onSystemRegistered(form.host);
        onNext();
      },
    });
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col" style={{ gap: 12 }}>
      <p
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-muted)" }}
      >
        add your first ssh-reachable target to start scanning.
      </p>

      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: 10,
        }}
      >
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label htmlFor="ob-name" style={LABEL_STYLE}>
            system name *
          </label>
          <input
            id="ob-name"
            value={form.name}
            onChange={(e) =>
              setForm((d) => ({ ...d, name: e.target.value }))
            }
            placeholder="arch-vm"
            required
            style={INPUT_STYLE}
          />
        </div>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label htmlFor="ob-host" style={LABEL_STYLE}>
            host / ip *
          </label>
          <input
            id="ob-host"
            value={form.host}
            onChange={(e) =>
              setForm((d) => ({ ...d, host: e.target.value }))
            }
            placeholder="192.168.1.100"
            required
            style={INPUT_STYLE}
          />
        </div>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label htmlFor="ob-user" style={LABEL_STYLE}>
            ssh username
          </label>
          <input
            id="ob-user"
            value={form.username}
            onChange={(e) =>
              setForm((d) => ({ ...d, username: e.target.value }))
            }
            style={INPUT_STYLE}
          />
        </div>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label htmlFor="ob-port" style={LABEL_STYLE}>
            ssh port
          </label>
          <input
            id="ob-port"
            type="number"
            min={1}
            max={65535}
            value={form.port}
            onChange={(e) =>
              setForm((d) => ({
                ...d,
                port: Number(e.target.value) || 22,
              }))
            }
            style={INPUT_STYLE}
          />
        </div>
      </div>

      {createSystem.isError && (
        <div style={ERROR_BOX_STYLE}>
          {(createSystem.error as Error).message}
        </div>
      )}

      <div
        className="flex items-center justify-between"
        style={{ paddingTop: 4 }}
      >
        <button type="button" onClick={onBack} style={SECONDARY_BUTTON_STYLE}>
          back
        </button>
        <div className="flex items-center" style={{ gap: 8 }}>
          <button type="button" onClick={onSkip} style={GHOST_LINK_STYLE}>
            skip
          </button>
          <button
            type="submit"
            disabled={createSystem.isPending}
            style={{
              ...PRIMARY_BUTTON_STYLE,
              opacity: createSystem.isPending ? 0.55 : 1,
              cursor: createSystem.isPending ? "not-allowed" : "pointer",
            }}
          >
            {createSystem.isPending
              ? "registering..."
              : "register & continue"}
          </button>
        </div>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Step 3: Launch Scan
// ---------------------------------------------------------------------------

function StepLaunchScan({
  onNext,
  onBack,
  onSkip,
  prefilledHost,
}: {
  onNext: () => void;
  onBack: () => void;
  onSkip: () => void;
  prefilledHost: string;
}) {
  const [query, setQuery] = useState("give me a full vulnerability scan");
  const [target, setTarget] = useState(prefilledHost);
  const submitScan = useSubmitScan();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const targets = target
      .split(/[,\n]/)
      .map((t) => t.trim())
      .filter(Boolean);

    const payload: ScanSubmissionRequest = {
      query_text: query,
      targets,
    };

    submitScan.mutate(payload, {
      onSuccess: () => {
        onNext();
      },
    });
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col" style={{ gap: 12 }}>
      <p
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-muted)" }}
      >
        run a vulnerability scan to discover cves on your system.
      </p>
      <div className="flex flex-col" style={{ gap: 4 }}>
        <label htmlFor="ob-target" style={LABEL_STYLE}>
          target host
        </label>
        <input
          id="ob-target"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="192.168.1.100"
          style={INPUT_STYLE}
        />
      </div>
      <div className="flex flex-col" style={{ gap: 4 }}>
        <label htmlFor="ob-query" style={LABEL_STYLE}>
          scan query
        </label>
        <input
          id="ob-query"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="give me a full vulnerability scan"
          style={INPUT_STYLE}
        />
      </div>

      {submitScan.isError && (
        <div style={ERROR_BOX_STYLE}>
          {(submitScan.error as Error).message}
        </div>
      )}

      <div
        className="flex items-center justify-between"
        style={{ paddingTop: 4 }}
      >
        <button type="button" onClick={onBack} style={SECONDARY_BUTTON_STYLE}>
          back
        </button>
        <div className="flex items-center" style={{ gap: 8 }}>
          <button type="button" onClick={onSkip} style={GHOST_LINK_STYLE}>
            skip
          </button>
          <button
            type="submit"
            disabled={submitScan.isPending}
            style={{
              ...PRIMARY_BUTTON_STYLE,
              opacity: submitScan.isPending ? 0.55 : 1,
              cursor: submitScan.isPending ? "not-allowed" : "pointer",
            }}
          >
            {submitScan.isPending ? "launching..." : "launch scan"}
          </button>
        </div>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Step 4: Done
// ---------------------------------------------------------------------------

function StepDone({
  onClose,
  onViewFindings,
}: {
  onClose: () => void;
  onViewFindings: () => void;
}) {
  return (
    <div
      className="flex flex-col items-center text-center"
      style={{ gap: 20, padding: "12px 0" }}
    >
      <div
        className="flex items-center justify-center"
        style={{
          width: 56,
          height: 56,
          background:
            "color-mix(in srgb, var(--status-ok) 15%, transparent)",
          border:
            "2px solid color-mix(in srgb, var(--status-ok) 55%, transparent)",
          borderRadius: 3,
        }}
      >
        <CheckCircle size={30} weight="fill" color="var(--status-ok)" />
      </div>
      <div className="flex flex-col" style={{ gap: 8 }}>
        <h2
          className="font-mono"
          style={{
            fontSize: 18,
            color: "var(--text-primary)",
            fontFamily: "var(--font-display)",
            textTransform: "uppercase",
            letterSpacing: "0.14em",
          }}
        >
          setup complete
        </h2>
        <p
          className="font-mono"
          style={{
            fontSize: 12,
            color: "var(--text-muted)",
            maxWidth: 380,
            lineHeight: 1.5,
          }}
        >
          your first scan is running. results will appear in the findings list
          once the scan completes.
        </p>
      </div>
      <div className="flex flex-col" style={{ gap: 8, width: "100%" }}>
        <button
          type="button"
          onClick={onViewFindings}
          style={{ ...PRIMARY_BUTTON_STYLE, width: "100%", justifyContent: "center" }}
        >
          view scan center
          <ArrowRight size={14} />
        </button>
        <button
          type="button"
          onClick={onClose}
          style={{ ...SECONDARY_BUTTON_STYLE, width: "100%" }}
        >
          go to dashboard
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main wizard
// ---------------------------------------------------------------------------

/**
 * OnboardingWizard -- guided first-run setup modal (UX-01).
 *
 * Shown to new users on first visit (localStorage "aila-onboarding-done" absent).
 * Steps: Welcome -> Register System -> Launch Scan -> Done.
 * Stores completion flag in localStorage to avoid reshowing.
 */
export function OnboardingWizard() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [open, setOpen] = useState(!isOnboardingDone());
  const [registeredHost, setRegisteredHost] = useState("");

  function handleSkip() {
    markOnboardingDone();
    setOpen(false);
  }

  function handleNext() {
    setStep((s) => Math.min(s + 1, TOTAL_STEPS));
  }

  function handleBack() {
    setStep((s) => Math.max(s - 1, 1));
  }

  function handleClose() {
    markOnboardingDone();
    setOpen(false);
    navigate("/");
  }

  function handleViewFindings() {
    markOnboardingDone();
    setOpen(false);
    navigate("/scans");
  }

  function handleSystemRegistered(host: string) {
    setRegisteredHost(host);
  }

  // ESC-to-skip parity with the previous shadcn Dialog.
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") handleSkip();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="AILA Setup Wizard"
      className="fixed inset-0 flex items-center justify-center"
      style={{
        zIndex: 60,
        background: "color-mix(in srgb, var(--surface-page) 78%, transparent)",
        backdropFilter: "blur(2px)",
        padding: 16,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) handleSkip();
      }}
    >
      <div style={{ width: "100%", maxWidth: 560 }}>
        <WindowPanel
          title="onboarding"
          status={`STEP ${step} / ${TOTAL_STEPS}`}
          tone="accent"
          actions={
            <button
              type="button"
              onClick={handleSkip}
              aria-label="Close wizard"
              style={{
                background: "transparent",
                border: "none",
                color: "var(--text-muted)",
                fontSize: 13,
                cursor: "pointer",
                padding: "0 4px",
                fontFamily: "var(--font-mono)",
              }}
            >
              {"\u2715"}
            </button>
          }
        >
          <div className="flex flex-col" style={{ gap: 14 }}>
            <StepChips current={step} />

            <div id="onboarding-description">
              {step === 1 && (
                <StepWelcome onNext={handleNext} onSkip={handleSkip} />
              )}
              {step === 2 && (
                <StepRegisterSystem
                  onNext={handleNext}
                  onBack={handleBack}
                  onSkip={handleNext}
                  onSystemRegistered={handleSystemRegistered}
                />
              )}
              {step === 3 && (
                <StepLaunchScan
                  onNext={handleNext}
                  onBack={handleBack}
                  onSkip={handleNext}
                  prefilledHost={registeredHost}
                />
              )}
              {step === 4 && (
                <StepDone
                  onClose={handleClose}
                  onViewFindings={handleViewFindings}
                />
              )}
            </div>
          </div>
        </WindowPanel>
      </div>
    </div>
  );
}
