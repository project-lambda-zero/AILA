import { Link } from "react-router";

import { AilaBadge } from "@/components/aila";
import { buttonVariants } from "@/components/ui/button";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { assessmentStatusDestination } from "../sessionFlow";
import { useWizardSchema, useWizardSessionList } from "../queries";

function WorkspaceSkeleton() {
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      {Array.from({ length: 6 }).map((_, index) => (
        <div key={index} className="animate-pulse bg-surface rounded-[var(--radius-md)]" style={{ height: 136, borderRadius: 10 }} />
      ))}
    </div>
  );
}

function statusSeverity(status: string): "neutral" | "info" | "high" | "critical" {
  if (["resolved", "approved", "report_generated"].includes(status)) return "info";
  if (status === "in_review") return "high";
  if (status === "resolution_failed") return "critical";
  return "neutral";
}

export function SbdNfrWorkspacePage() {
  const role = useAuthStore((state) => state.role);
  const schemaQuery = useWizardSchema();
  const sessionsQuery = useWizardSessionList();

  const sessions = sessionsQuery.data ?? [];
  const schemaVersion = schemaQuery.data?.schema_version;
  const firstSectionKey = schemaQuery.data?.sections[0]?.section_key;
  const activeSessions = sessions.filter((session) => ["draft", "in_progress", "completed", "resolving"].includes(session.status));
  const reviewSessions = sessions.filter((session) => ["resolved", "in_review", "approved"].includes(session.status));

  return (
    <div className="flex flex-col gap-6">
      <section className="rounded-2xl border border-amber-500/20 bg-[#141414] p-6 text-amber-50 shadow-[0_0_0_1px_rgba(245,158,11,0.05)]">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-3">
            <p className="font-mono text-xs uppercase tracking-[0.3em] text-amber-500/70">Secure by Design NFR</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link className={buttonVariants({ variant: "default" })} to="/assessments">
              Open Assessments
            </Link>
            {role === "admin" && (
              <Link className={buttonVariants({ variant: "outline" })} to="/admin/schema-editor">
                Open Schema Editor
              </Link>
            )}
          </div>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <article className="rounded-xl border border-amber-500/10 bg-[#171717] p-4">
          <p className="font-mono text-xs uppercase tracking-[0.28em] text-amber-500/60">Schema Version</p>
          <div className="mt-3 flex items-center gap-3">
            <strong className="text-2xl text-amber-100">{schemaVersion ?? "—"}</strong>
            {schemaVersion !== undefined && <AilaBadge severity="medium">v{schemaVersion}</AilaBadge>}
          </div>
        </article>
        <article className="rounded-xl border border-amber-500/10 bg-[#171717] p-4">
          <p className="font-mono text-xs uppercase tracking-[0.28em] text-amber-500/60">Sessions</p>
          <strong className="mt-3 block text-2xl text-amber-100">{sessions.length}</strong>
        </article>
        <article className="rounded-xl border border-amber-500/10 bg-[#171717] p-4">
          <p className="font-mono text-xs uppercase tracking-[0.28em] text-amber-500/60">Active Work</p>
          <strong className="mt-3 block text-2xl text-amber-100">{activeSessions.length}</strong>
        </article>
        <article className="rounded-xl border border-amber-500/10 bg-[#171717] p-4">
          <p className="font-mono text-xs uppercase tracking-[0.28em] text-amber-500/60">Review Queue</p>
          <strong className="mt-3 block text-2xl text-amber-100">{reviewSessions.length}</strong>
        </article>
      </section>

      {schemaQuery.isLoading || sessionsQuery.isLoading ? (
        <WorkspaceSkeleton />
      ) : (
        <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
          <section className="rounded-2xl border border-amber-500/10 bg-[#171717] p-5">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-amber-100">Recent assessments</h2>
                <p className="text-sm text-amber-100/60">Jump straight into the live wizard, review, results, or report view.</p>
              </div>
              <Link className={buttonVariants({ variant: "outline" })} to="/assessments">
                View all
              </Link>
            </div>
            {sessions.length === 0 ? (
              <div className="rounded-xl border border-dashed border-amber-500/20 bg-[#141414] p-5 text-sm text-amber-100/60">
                No assessment sessions yet. Start one from the assessments page.
              </div>
            ) : (
              <div className="space-y-3">
                {sessions.slice(0, 6).map((session) => {
                  const destination = assessmentStatusDestination(session.id, session.status, firstSectionKey);
                  return (
                    <div key={session.id} className="rounded-xl border border-amber-500/10 bg-[#141414] p-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div>
                          <p className="font-medium text-amber-100">{session.project_name}</p>
                          <p className="text-xs text-amber-100/50">{session.requestor_name} · {session.updated_at ? new Date(session.updated_at).toLocaleString() : "—"}</p>
                        </div>
                        <AilaBadge severity={statusSeverity(session.status)}>{session.status.replace(/_/g, " ")}</AilaBadge>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {destination && (
                          <Link className={buttonVariants({ variant: "outline" })} to={destination}>
                            Open
                          </Link>
                        )}
                        <Link className={buttonVariants({ variant: "outline" })} to="/assessments/compare">
                          Compare
                        </Link>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          <section className="rounded-2xl border border-amber-500/10 bg-[#171717] p-5">
            <h2 className="text-lg font-semibold text-amber-100">Admin editor</h2>
            <p className="mt-1 text-sm text-amber-100/60">
              Maintain sections, subgroups, questions, mappings, and conditional logic from the schema editor.
            </p>
            <div className="mt-4 rounded-xl border border-dashed border-amber-500/20 bg-[#141414] p-4 text-sm text-amber-100/70">
              <ul className="space-y-2">
                <li>• Drag to reorder sections and subgroups</li>
                <li>• Edit question labels, answer type, help text, and dependency rules</li>
                <li>• Preview the live wizard against the current schema draft</li>
              </ul>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {role === "admin" ? (
                <Link className={buttonVariants({ variant: "default" })} to="/admin/schema-editor">
                  Launch Editor
                </Link>
              ) : (
                <div className="rounded-lg border border-amber-500/15 bg-[#141414] px-3 py-2 text-xs text-amber-100/60">
                  Schema editing is admin-only.
                </div>
              )}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
