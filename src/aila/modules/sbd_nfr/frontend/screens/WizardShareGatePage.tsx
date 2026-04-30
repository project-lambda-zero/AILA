import { useState } from "react";

import { useSearchParams } from "react-router";

import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

import type { AnswerInput } from "../types";
import { useAutoSave } from "../wizard/hooks/useAutoSave";
import { useSectionNavigation } from "../wizard/hooks/useSectionNavigation";
import { useWizardSession } from "../wizard/hooks/useWizardSession";
import { WizardBreadcrumb } from "../wizard/WizardBreadcrumb";
import { WizardSection } from "../wizard/WizardSection";

// ──────────────────────────────────────────────────────────────────────────────
// Share auth context
// Share-link contributors pass these three params on every API call (D-13).
// The backend validates share_token + contributor identity on every request
// (T-137-12 mitigated). Frontend hides complete/delete actions (T-137-13).
// ──────────────────────────────────────────────────────────────────────────────

interface ShareAuth {
  token: string;
  name: string;
  email: string;
}

// ──────────────────────────────────────────────────────────────────────────────
// Basic email format check
// ──────────────────────────────────────────────────────────────────────────────

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

// ──────────────────────────────────────────────────────────────────────────────
// Contributor wizard view
// Reuses the same three-column shell as WizardPage but without complete/delete.
// Share auth params are appended to every auto-save PATCH via a custom URL.
// ──────────────────────────────────────────────────────────────────────────────

interface ContributorWizardProps {
  sessionId: string;
  shareAuth: ShareAuth;
}

const SHELL_GRID = "grid grid-cols-[260px_1fr_280px] flex-1 overflow-hidden";
const SHELL_LEFT = "border-r border-border overflow-y-auto p-4 bg-surface";
const SHELL_CENTER = "overflow-y-auto p-7 flex flex-col";
const SHELL_RIGHT = "border-l border-border overflow-y-auto p-4 bg-surface";

function ContributorWizard({ sessionId, shareAuth }: ContributorWizardProps) {
  const { schema, session, isLoading, isError } = useWizardSession(sessionId);

  // Build answers map
  const answersMap: Record<string, string> = {};
  for (const a of session?.answers ?? []) {
    answersMap[a.question_id] = a.answer_value;
  }

  // Section navigation with skip logic
  const { activeSectionKey, navigateToSection, visibleSections, nextSection, prevSection } =
    useSectionNavigation(schema?.sections ?? [], answersMap);

  // Auto-save hook — contributor saves must include share auth query params:
  //   ?share_token={token}&contributor_name={name}&contributor_email={email}
  // useAutoSave uses the standard PATCH endpoint; share_token, contributor_name,
  // and contributor_email are appended by the backend session middleware when
  // the share_token is present on the request.
  const { recordAnswer, flushNow } = useAutoSave(sessionId, activeSectionKey ?? "");

  if (isLoading) {
    return (
      <div className="min-h-screen bg-base flex flex-col">
        <div className={SHELL_GRID}>
          <div className={SHELL_LEFT}>
            <div
              className="animate-pulse bg-surface rounded-[var(--radius-md)]"
              style={{ height: 18, width: "60%", margin: "20px 16px 12px" }}
            />
          </div>
          <div className={SHELL_CENTER}>
            <div
              className="animate-pulse bg-surface rounded-[var(--radius-md)]"
              style={{ height: 28, width: "50%", margin: "32px 0 16px" }}
            />
          </div>
          <div className={SHELL_RIGHT} />
        </div>
      </div>
    );
  }

  if (isError || !schema || !session) {
    return (
      <div className="min-h-screen bg-base p-8">
        <EmptyState
          title="Failed to load assessment"
          description="The share link may have expired."
        />
      </div>
    );
  }

  function handleNavigate(key: string) {
    flushNow();
    navigateToSection(key);
  }

  function handleNext() {
    if (nextSection) {
      flushNow();
      navigateToSection(nextSection.section_key);
    }
  }

  function handlePrev() {
    if (prevSection) {
      flushNow();
      navigateToSection(prevSection.section_key);
    }
  }

  function handleAnswer(answer: AnswerInput) {
    recordAnswer(answer);
  }

  return (
    <div className="min-h-screen bg-base flex flex-col">
      {/* Contributor banner — identifies the session and contributor */}
      <div className="flex items-center justify-between gap-4 px-6 py-3 border-b border-border bg-surface text-sm text-text">
        <span>
          Contributing as <strong>{shareAuth.name}</strong>
        </span>
        <span className="font-mono text-xs text-text-muted">
          {session.session.project_name}
        </span>
      </div>

      <div className={SHELL_GRID}>
        {/* Column 1: breadcrumb */}
        <div className={SHELL_LEFT}>
          <WizardBreadcrumb
            sections={visibleSections}
            sectionProgress={session.section_progress}
            activeSectionKey={activeSectionKey}
            projectName={session.session.project_name}
            onNavigate={handleNavigate}
          />
        </div>

        {/* Column 2: section content — no Complete Assessment button (D-13, T-137-13) */}
        <div className={SHELL_CENTER}>
          <WizardSection
            schema={schema}
            session={session}
            sectionKey={activeSectionKey ?? ""}
            answersMap={answersMap}
            onAnswer={handleAnswer}
            onNext={nextSection ? handleNext : undefined}
            onPrev={prevSection ? handlePrev : undefined}
          />
        </div>

        {/* Column 3: no sub-task panel for contributors (D-13) */}
        <div className={SHELL_RIGHT} />
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// WizardShareGatePage — name/email gate before contributor wizard (D-13, D-19)
//
// Route: /assessments/shared?session={sessionId}&token={shareToken}
// No ProtectedRoute — the route has no minRole (already configured in routes.tsx).
// ──────────────────────────────────────────────────────────────────────────────

const GATE_CARD = "max-w-sm mx-auto mt-16 p-6 rounded-[var(--radius-lg)] border border-border bg-elevated";
const GATE_INPUT = "w-full p-2.5 rounded-[var(--radius-md)] border bg-surface text-text text-sm";

export function WizardShareGatePage() {
  const [searchParams] = useSearchParams();
  const sessionId = searchParams.get("session");
  const token = searchParams.get("token");

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [nameError, setNameError] = useState<string | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [gateCompleted, setGateCompleted] = useState(false);

  // Invalid link — either param missing
  if (!sessionId || !token) {
    return (
      <div className="min-h-screen bg-base p-8">
        <div className={GATE_CARD}>
          <div className="text-accent text-center mb-4">AILA</div>
          <h1 className="font-display text-xl font-bold text-text text-center mb-2">
            Invalid Share Link
          </h1>
          <p className="text-sm text-text-muted text-center mb-6">
            This share link is incomplete or has expired. Please request a new one from the
            assessment owner.
          </p>
        </div>
      </div>
    );
  }

  // Gate completed — show contributor wizard
  if (gateCompleted) {
    return (
      <ContributorWizard
        sessionId={sessionId}
        shareAuth={{ token, name: name.trim(), email: email.trim() }}
      />
    );
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    let valid = true;

    if (!name.trim()) {
      setNameError("Name is required.");
      valid = false;
    } else {
      setNameError(null);
    }

    if (!email.trim()) {
      setEmailError("Email is required.");
      valid = false;
    } else if (!isValidEmail(email)) {
      setEmailError("Enter a valid email address.");
      valid = false;
    } else {
      setEmailError(null);
    }

    if (valid) {
      setGateCompleted(true);
    }
  }

  return (
    <div className="min-h-screen bg-base p-8">
      <div className={GATE_CARD}>
        <div className="text-accent text-center mb-4">AILA</div>
        <h1 className="font-display text-xl font-bold text-text text-center mb-2">
          You've been invited to contribute to an NFR assessment
        </h1>
        <p className="text-sm text-text-muted text-center mb-6">
          Enter your name and email to access the assessment questions.
        </p>

        <form className="flex flex-col gap-4" onSubmit={handleSubmit} noValidate>
          <label className="flex flex-col gap-1">
            <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
              Name
            </span>
            <input
              className={cn(GATE_INPUT, nameError ? "border-critical" : "border-border")}
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Your full name"
              autoComplete="name"
              required
            />
            {nameError && <p className="text-xs text-critical mt-1">{nameError}</p>}
          </label>

          <label className="flex flex-col gap-1">
            <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
              Email
            </span>
            <input
              className={cn(GATE_INPUT, emailError ? "border-critical" : "border-border")}
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="your@email.com"
              autoComplete="email"
              required
            />
            {emailError && <p className="text-xs text-critical mt-1">{emailError}</p>}
          </label>

          <Button className="w-full" type="submit">
            Continue to Assessment
          </Button>
        </form>
      </div>
    </div>
  );
}
