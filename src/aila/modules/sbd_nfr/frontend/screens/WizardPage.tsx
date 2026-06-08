import { useEffect, useMemo, useState } from "react";
import { AnimatePresence } from "motion/react";
import { useNavigate, useParams } from "react-router";
import { toast } from "sonner";

import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";

import type { AnswerInput, QuestionResponse } from "../types";
import { assessmentStatusDestination, firstWizardPath } from "../sessionFlow";
import { useCompleteSession } from "../queries";
import { useAutoSave } from "../wizard/hooks/useAutoSave";
import { useSectionNavigation } from "../wizard/hooks/useSectionNavigation";
import { useWizardSession } from "../wizard/hooks/useWizardSession";
import { WizardAssistPanel } from "../wizard/WizardAssistPanel";
import { WizardLayout } from "../wizard/WizardLayout";
import { WizardProgressSidebar } from "../wizard/WizardProgressSidebar";
import { WizardResolutionOverlay } from "../wizard/WizardResolutionOverlay";
import { WizardSection } from "../wizard/WizardSection";
import { WizardSubtaskPanel } from "../wizard/WizardSubtaskPanel";

function WizardSkeleton() {
  return (
    <div
      className="flex flex-col bg-base overflow-hidden"
      style={{ minHeight: "calc(100vh - 64px)", borderRadius: "var(--radius-lg)" }}
    >
      <div
        className="grid flex-1 overflow-hidden"
        style={{ gridTemplateColumns: "260px 1fr 280px" }}
      >
        <aside className="border-r border-border overflow-y-auto p-4 bg-surface">
          <div
            className="animate-pulse bg-surface rounded-md"
            style={{ height: 18, width: "60%", marginBottom: 16, borderRadius: 4 }}
          />
          {[1, 2, 3, 4, 5].map((i) => (
            <div
              key={i}
              className="animate-pulse bg-surface rounded-md"
              style={{ height: 36, marginBottom: 8, borderRadius: 6 }}
            />
          ))}
        </aside>
        <main className="overflow-y-auto p-7 flex flex-col">
          <div
            className="animate-pulse bg-surface rounded-md"
            style={{ height: 28, width: "50%", marginBottom: 16, borderRadius: 4 }}
          />
          <div
            className="animate-pulse bg-surface rounded-md"
            style={{ height: 16, width: "80%", marginBottom: 32, borderRadius: 4 }}
          />
          {[1, 2, 3].map((i) => (
            <div key={i} style={{ marginBottom: 24 }}>
              <div
                className="animate-pulse bg-surface rounded-md"
                style={{ height: 16, width: "40%", marginBottom: 10, borderRadius: 4 }}
              />
              <div
                className="animate-pulse bg-surface rounded-md"
                style={{ height: 48, width: "100%", borderRadius: 6 }}
              />
            </div>
          ))}
        </main>
        <aside className="border-l border-border overflow-y-auto p-4 bg-surface">
          <div
            className="animate-pulse bg-surface rounded-md"
            style={{ height: 18, width: "60%", marginBottom: 16, borderRadius: 4 }}
          />
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="animate-pulse bg-surface rounded-md"
              style={{ height: 56, marginBottom: 8, borderRadius: 8 }}
            />
          ))}
        </aside>
      </div>
    </div>
  );
}

function WizardError() {
  return (
    <div
      className="flex items-center justify-center p-7 bg-base"
      style={{ minHeight: "calc(100vh - 64px)", borderRadius: "var(--radius-lg)" }}
    >
      <EmptyState
        title="Failed to load assessment"
        description="The session may not exist or could not be reached."
        action={{ label: "Return to Assessments", href: "/assessments" }}
      />
    </div>
  );
}

const TERMINAL_SESSION_STATUSES = new Set(["resolved", "in_review", "approved", "report_generated"]);

export function WizardPage() {
  const { sessionId } = useParams<{ sessionId: string; sectionKey: string }>();
  const navigate = useNavigate();

  const { schema, session, isLoading, isError, schemaDrifted } = useWizardSession(sessionId ?? "");

  const answersMap = useMemo<Record<string, string>>(() => {
    const map: Record<string, string> = {};
    for (const answer of session?.answers ?? []) {
      map[answer.question_id] = answer.answer_value;
    }
    return map;
  }, [session?.answers]);

  const { activeSectionKey, navigateToSection, visibleSections, nextSection, prevSection } =
    useSectionNavigation(schema?.sections ?? [], answersMap);

  const overallPct = useMemo(() => {
    const progress = session?.section_progress ?? [];
    const totalVisible = progress.reduce((sum, item) => sum + item.visible_count, 0);
    const totalAnswered = progress.reduce((sum, item) => sum + item.answered_count, 0);
    if (totalVisible === 0) return 0;
    return Math.round((totalAnswered / totalVisible) * 100);
  }, [session?.section_progress]);

  const { recordAnswer, flushNow } = useAutoSave(sessionId ?? "", activeSectionKey ?? "");
  const completeSession = useCompleteSession();
  const [showOverlay, setShowOverlay] = useState(false);
  const [assistQuestion, setAssistQuestion] = useState<QuestionResponse | null>(null);

  useEffect(() => {
    if (!sessionId || !session) {
      return;
    }
    if (!TERMINAL_SESSION_STATUSES.has(session.session.status)) {
      return;
    }
    const destination = assessmentStatusDestination(
      sessionId,
      session.session.status,
      visibleSections[0]?.section_key,
    );
    if (destination) {
      void navigate(destination, { replace: true });
    }
  }, [navigate, session, sessionId, visibleSections]);

  useEffect(() => {
    if (!sessionId || !activeSectionKey) {
      return;
    }
    const expectedPath = firstWizardPath(sessionId, activeSectionKey);
    if (!expectedPath) {
      return;
    }
    if (!window.location.pathname.endsWith(`/wizard/${encodeURIComponent(activeSectionKey)}`)) {
      void navigate(expectedPath, { replace: true });
    }
  }, [activeSectionKey, navigate, sessionId]);

  if (isLoading) return <WizardSkeleton />;
  if (isError || !schema || !session) return <WizardError />;
  if (!activeSectionKey) {
    return (
      <div
        className="flex items-center justify-center p-7 bg-base"
        style={{ minHeight: "calc(100vh - 64px)", borderRadius: "var(--radius-lg)" }}
      >
        <EmptyState
          title="No visible sections"
          description="This assessment has no visible sections in the current schema."
          action={{ label: "Return to Assessments", href: "/assessments" }}
        />
      </div>
    );
  }

  function handleNavigate(sectionKey: string) {
    flushNow();
    navigateToSection(sectionKey);
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

  async function handleCompleteAssessment() {
    try {
      await flushNow();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to save your latest answers.";
      toast.error(message);
      return;
    }
    completeSession.mutate(sessionId!, {
      onSuccess: () => {
        setShowOverlay(true);
      },
    });
  }

  function handleOverlayCompleted() {
    void navigate(`/assessments/${sessionId}/results`);
  }

  function handleOverlayFailed() {
    setShowOverlay(false);
  }

  const sessionStatus = session.session.status;
  const canComplete = sessionStatus === "in_progress" || sessionStatus === "completed";
  const isResolving = sessionStatus === "resolving";

  return (
    <>
      <WizardLayout
        overallPct={overallPct}
        sidebar={
          <WizardProgressSidebar
            sections={visibleSections}
            sectionProgress={session.section_progress}
            activeSectionKey={activeSectionKey}
            projectName={session.session.project_name}
            onNavigate={handleNavigate}
          />
        }
        content={
          <>
            {schemaDrifted && (
              <div className="rounded-md border border-accent bg-accent-muted p-3 text-sm text-accent mb-4" role="alert">
                Schema updated since you started. Your answers are preserved — continue with the original questions.
              </div>
            )}
            <AnimatePresence mode="wait">
              <WizardSection
                key={activeSectionKey}
                schema={schema}
                session={session}
                sectionKey={activeSectionKey}
                answersMap={answersMap}
                onAnswer={handleAnswer}
                onNext={nextSection ? handleNext : undefined}
                onPrev={prevSection ? handlePrev : undefined}
                onAssist={setAssistQuestion}
              />
            </AnimatePresence>
            {canComplete && (
              <div className="sticky bottom-0 pt-5 mt-auto border-t border-border bg-base">
                <Button
                  type="button"
                  onClick={handleCompleteAssessment}
                  disabled={completeSession.isPending}
                  aria-busy={completeSession.isPending}
                >
                  {completeSession.isPending ? "Submitting..." : "Complete Assessment"}
                </Button>
                {completeSession.isError && (
                  <p className="text-sm text-critical mt-2">
                    {completeSession.error instanceof Error
                      ? completeSession.error.message
                      : "Failed to complete assessment."}
                  </p>
                )}
              </div>
            )}
          </>
        }
        panel={
          <WizardSubtaskPanel
            sessionId={sessionId!}
            sessionStatus={sessionStatus}
            answersMap={answersMap}
          />
        }
      />

      {(showOverlay || isResolving) && (
        <WizardResolutionOverlay
          sessionId={sessionId!}
          onCompleted={handleOverlayCompleted}
          onFailed={handleOverlayFailed}
        />
      )}

      {assistQuestion && (
        <WizardAssistPanel
          questionId={assistQuestion.id}
          questionLabel={assistQuestion.label}
          currentAnswer={answersMap[assistQuestion.id] ?? null}
          onClose={() => setAssistQuestion(null)}
        />
      )}
    </>
  );
}
