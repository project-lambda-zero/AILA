import { useState } from "react";
import { useNavigate } from "react-router";
import { CheckCircle } from "@phosphor-icons/react/dist/csr/CheckCircle";
import { Desktop } from "@phosphor-icons/react/dist/csr/Desktop";
import { Crosshair } from "@phosphor-icons/react/dist/csr/Crosshair";
import { ArrowRight } from "@phosphor-icons/react/dist/csr/ArrowRight";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useCreateSystem, type SystemMutationInput } from "@platform/features/systems/api";
import { useSubmitScan, type ScanSubmissionRequest } from "@platform/features/scans/api";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STORAGE_KEY = "aila-onboarding-done";
const TOTAL_STEPS = 4;

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
    // localStorage unavailable — ignore
  }
}

// ---------------------------------------------------------------------------
// Step indicator
// ---------------------------------------------------------------------------

function StepDots({ current, total }: { current: number; total: number }) {
  return (
    <div className="flex items-center gap-1.5" aria-label={`Step ${current} of ${total}`}>
      {Array.from({ length: total }, (_, i) => (
        <div
          key={i}
          className={`h-1.5 rounded-full transition-all duration-200 ${
            i + 1 === current
              ? "w-4 bg-accent"
              : i + 1 < current
                ? "w-1.5 bg-accent/50"
                : "w-1.5 bg-border"
          }`}
        />
      ))}
      <span className="ml-1 font-mono text-xs text-text-muted">
        {current}/{total}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 1: Welcome
// ---------------------------------------------------------------------------

function StepWelcome({ onNext, onSkip }: { onNext: () => void; onSkip: () => void }) {
  return (
    <div className="flex flex-col items-center gap-6 py-4 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full border-2 border-accent/30 bg-accent/10">
        <span className="font-mono text-2xl font-bold text-accent">A</span>
      </div>
      <div className="flex flex-col gap-2">
        <h2 className="font-mono text-xl font-semibold text-text">
          Welcome to AILA
        </h2>
        <p className="font-mono text-sm text-text-muted max-w-sm">
          AI Lab Assistant — your modular security platform for vulnerability
          scanning and fleet management. Let&apos;s get you set up in 4 quick steps.
        </p>
      </div>
      <div className="flex flex-col w-full gap-2">
        <Button onClick={onNext} className="w-full gap-2">
          Get Started
          <ArrowRight size={16} />
        </Button>
        <button
          type="button"
          onClick={onSkip}
          className="font-mono text-xs text-text-muted hover:text-text transition-colors"
        >
          Skip setup
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
    <div className="flex flex-col gap-5">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-full border border-border bg-accent/10">
          <Desktop size={20} className="text-accent" />
        </div>
        <div>
          <h2 className="font-mono text-sm font-semibold text-text">Register a System</h2>
          <p className="font-mono text-xs text-text-muted">
            Add your first SSH-reachable target to start scanning.
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="ob-name">
              System name *
            </label>
            <Input
              id="ob-name"
              value={form.name}
              onChange={(e) => setForm((d) => ({ ...d, name: e.target.value }))}
              placeholder="arch-vm"
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="ob-host">
              Host / IP *
            </label>
            <Input
              id="ob-host"
              value={form.host}
              onChange={(e) => setForm((d) => ({ ...d, host: e.target.value }))}
              placeholder="192.168.1.100"
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="ob-user">
              SSH username
            </label>
            <Input
              id="ob-user"
              value={form.username}
              onChange={(e) => setForm((d) => ({ ...d, username: e.target.value }))}
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="ob-port">
              SSH port
            </label>
            <Input
              id="ob-port"
              type="number"
              min={1}
              max={65535}
              value={form.port}
              onChange={(e) => setForm((d) => ({ ...d, port: Number(e.target.value) || 22 }))}
            />
          </div>
        </div>

        {createSystem.isError && (
          <div className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
            {(createSystem.error as Error).message}
          </div>
        )}

        <div className="flex items-center justify-between pt-1">
          <Button type="button" variant="outline" size="sm" onClick={onBack}>
            Back
          </Button>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={onSkip}
              className="font-mono text-xs text-text-muted hover:text-text transition-colors"
            >
              Skip
            </button>
            <Button type="submit" size="sm" disabled={createSystem.isPending}>
              {createSystem.isPending ? "Registering..." : "Register & Continue"}
            </Button>
          </div>
        </div>
      </form>
    </div>
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
    <div className="flex flex-col gap-5">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-full border border-border bg-accent/10">
          <Crosshair size={20} className="text-accent" />
        </div>
        <div>
          <h2 className="font-mono text-sm font-semibold text-text">Launch Your First Scan</h2>
          <p className="font-mono text-xs text-text-muted">
            Run a vulnerability scan to discover CVEs on your system.
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="ob-target">
            Target host
          </label>
          <Input
            id="ob-target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="192.168.1.100"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="ob-query">
            Scan query
          </label>
          <Input
            id="ob-query"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="give me a full vulnerability scan"
          />
        </div>

        {submitScan.isError && (
          <div className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
            {(submitScan.error as Error).message}
          </div>
        )}

        <div className="flex items-center justify-between pt-1">
          <Button type="button" variant="outline" size="sm" onClick={onBack}>
            Back
          </Button>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={onSkip}
              className="font-mono text-xs text-text-muted hover:text-text transition-colors"
            >
              Skip
            </button>
            <Button type="submit" size="sm" disabled={submitScan.isPending}>
              {submitScan.isPending ? "Launching..." : "Launch Scan"}
            </Button>
          </div>
        </div>
      </form>
    </div>
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
    <div className="flex flex-col items-center gap-6 py-4 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full border-2 border-accent/30 bg-accent/10">
        <CheckCircle size={32} className="text-accent" weight="fill" />
      </div>
      <div className="flex flex-col gap-2">
        <h2 className="font-mono text-xl font-semibold text-text">
          Setup Complete!
        </h2>
        <p className="font-mono text-sm text-text-muted max-w-sm">
          Your first scan is running. Results will appear in the findings list
          once the scan completes.
        </p>
      </div>
      <div className="flex flex-col w-full gap-2">
        <Button onClick={onViewFindings} className="w-full gap-2">
          View Scan Center
          <ArrowRight size={16} />
        </Button>
        <Button variant="outline" onClick={onClose} className="w-full">
          Go to Dashboard
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main wizard
// ---------------------------------------------------------------------------

/**
 * OnboardingWizard — guided first-run setup modal (UX-01).
 *
 * Shown to new users on first visit (localStorage "aila-onboarding-done" absent).
 * Steps: Welcome → Register System → Launch Scan → Done.
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

  if (!open) return null;

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => {
      if (!nextOpen) handleSkip();
    }}>
      <DialogContent
        className="sm:max-w-lg"
        aria-describedby="onboarding-description"
      >
        <DialogHeader className="sr-only">
          <DialogTitle>AILA Setup Wizard</DialogTitle>
        </DialogHeader>

        {/* Progress dots */}
        <div className="flex justify-center pt-2 pb-1">
          <StepDots current={step} total={TOTAL_STEPS} />
        </div>

        <div id="onboarding-description" className="px-2 pb-2">
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
      </DialogContent>
    </Dialog>
  );
}
