import { AilaCard } from "@/components/aila/AilaCard";

/**
 * DocsPage — operator-facing usage guide (D-03, D-33).
 *
 * Fresh content authored for the operator console. NOT a README dump; NOT a
 * verbatim port of the removed onboarding wizard. Five H2 section headings are
 * locked by the plan test harness and must remain stable.
 */
export function DocsPage() {
  return (
    <div className="mx-auto max-w-3xl p-4 sm:p-6">
      <header className="mb-4">
        <h1 className="font-mono text-xl font-semibold text-foreground">
          Operator Docs
        </h1>
        <p className="mt-1 font-mono text-sm text-text-muted">
          A short guide to what each sidebar item does and how to get work
          done. Follow the five sections below in order if this is your first
          time in the console.
        </p>
      </header>

      <div className="flex flex-col gap-4">
        <AilaCard variant="default" padding="md">
          <h2 className="font-mono text-base font-semibold text-foreground">
            What this tool does
          </h2>
          <p className="mt-2 font-mono text-sm text-text-muted">
            This is an operator console for running vulnerability and posture
            scans against registered systems. Each scan produces a report with
            findings, severity counts, and remediation notes that you can
            review from the Reports section. Tasks are executed by background
            workers; the sidebar's Tasks page shows their live state. The
            Dashboard surfaces recent activity across all modules.
          </p>
        </AilaCard>

        <AilaCard variant="default" padding="md">
          <h2 className="font-mono text-base font-semibold text-foreground">
            How to register a system
          </h2>
          <p className="mt-2 font-mono text-sm text-text-muted">
            Open the <strong>Systems</strong> tab from the sidebar and use the
            "Add system" action. You will need an SSH host, port, username,
            and either a password or a private key. After saving, the system
            appears in the list and can be targeted by scans. Health of the
            SSH connection is reflected on the System Detail page — if a
            scan fails with a connection error, re-check credentials there
            before opening a ticket.
          </p>
        </AilaCard>

        <AilaCard variant="default" padding="md">
          <h2 className="font-mono text-base font-semibold text-foreground">
            How to run a scan
          </h2>
          <p className="mt-2 font-mono text-sm text-text-muted">
            Go to the <strong>Console</strong> tab (formerly Scans). Type a
            plain-English query such as "give me a full vulnerability scan of
            arch-vm" and, optionally, a comma-separated list of targets. Press
            Submit. The run appears in the recent-runs list, and selecting it
            opens a live progress stream. You can cancel in-flight runs from
            the detail panel; completed runs surface an "Open Report" button.
          </p>
        </AilaCard>

        <AilaCard variant="default" padding="md">
          <h2 className="font-mono text-base font-semibold text-foreground">
            How to read results
          </h2>
          <p className="mt-2 font-mono text-sm text-text-muted">
            Reports are listed under <strong>Vulnerability Reports</strong>.
            Clicking a row opens the detail view with four sections: Summary
            (high-level run info), Findings (table with severity badges),
            Remediation (prose notes), and Metadata (raw key/value context).
            Severity badges follow the platform palette — critical/high/medium
            are colored per theme, low and info are desaturated. Exports for
            JSON, CSV, and PDF are available on the detail sidebar.
          </p>
        </AilaCard>

        <AilaCard variant="default" padding="md">
          <h2 className="font-mono text-base font-semibold text-foreground">
            Where to set the API key
          </h2>
          <p className="mt-2 font-mono text-sm text-text-muted">
            LLM-backed features need an API key. Admins configure this under
            <strong> Admin → API Keys</strong>. If you see a toast with hint
            "Go to Admin → API Keys and add the provider key for this
            operation", that is the backend telling you a scan or explanation
            requires credentials. Non-admins cannot set keys; ask your admin.
            Key rotation is also done from the same page.
          </p>
        </AilaCard>
      </div>
    </div>
  );
}
