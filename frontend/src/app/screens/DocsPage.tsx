import type { ReactNode } from "react";

import { BookOpen } from "@phosphor-icons/react/dist/csr/BookOpen";

import { SectionHeader } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

/**
 * DocsPage -- operator-facing usage guide (D-03, D-33).
 *
 * Fresh content authored for the operator console. NOT a README dump; NOT a
 * verbatim port of the removed onboarding wizard. Five H2 section headings
 * are locked by the plan test harness and must remain stable.
 */

const SECTIONS: { heading: string; body: ReactNode }[] = [
  {
    heading: "What this tool does",
    body: (
      <>
        This is an operator console for running vulnerability and posture
        scans against registered systems. Each scan produces a report with
        findings, severity counts, and remediation notes that you can review
        from the Reports section. Tasks are executed by background workers;
        the sidebar&apos;s Tasks page shows their live state. The Dashboard
        surfaces recent activity across all modules.
      </>
    ),
  },
  {
    heading: "How to register a system",
    body: (
      <>
        Open the <strong>Systems</strong> tab from the sidebar and use the
        &ldquo;Add system&rdquo; action. You will need an SSH host, port,
        username, and either a password or a private key. After saving, the
        system appears in the list and can be targeted by scans. Health of the
        SSH connection is reflected on the System Detail page {"\u2014"} if a
        scan fails with a connection error, re-check credentials there before
        opening a ticket.
      </>
    ),
  },
  {
    heading: "How to run a scan",
    body: (
      <>
        Go to the <strong>Console</strong> tab (formerly Scans). Type a
        plain-English query such as &ldquo;give me a full vulnerability scan
        of arch-vm&rdquo; and, optionally, a comma-separated list of targets.
        Press Submit. The run appears in the recent-runs list, and selecting
        it opens a live progress stream. You can cancel in-flight runs from
        the detail panel; completed runs surface an &ldquo;Open Report&rdquo;
        button.
      </>
    ),
  },
  {
    heading: "How to read results",
    body: (
      <>
        Reports are listed under <strong>Vulnerability Reports</strong>.
        Clicking a row opens the detail view with four sections: Summary
        (high-level run info), Findings (table with severity badges),
        Remediation (prose notes), and Metadata (raw key/value context).
        Severity badges follow the platform palette {"\u2014"}
        critical/high/medium are coloured per theme, low and info are
        desaturated. Exports for JSON, CSV, and PDF are available on the
        detail sidebar.
      </>
    ),
  },
  {
    heading: "Where to set the API key",
    body: (
      <>
        LLM-backed features need an API key. Admins configure this under
        {" "}
        <strong>Admin {"\u2192"} API Keys</strong>. If you see a toast with
        hint &ldquo;Go to Admin {"\u2192"} API Keys and add the provider key
        for this operation&rdquo;, that is the backend telling you a scan or
        explanation requires credentials. Non-admins cannot set keys; ask your
        admin. Key rotation is also done from the same page.
      </>
    ),
  },
];

export function DocsPage() {
  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={
          <BookOpen
            size={18}
            weight="duotone"
            style={{ color: "var(--text-on-accent)" }}
            aria-hidden="true"
          />
        }
        title="documentation"
      />

      <p
        className="font-mono"
        style={{
          color: "var(--text-muted)",
          fontSize: 11.5,
          lineHeight: 1.6,
          maxWidth: 720,
        }}
      >
        A short guide to what each sidebar item does and how to get work done.
        Follow the five sections below in order if this is your first time in
        the console.
      </p>

      <WindowPanel title="sections" tone="muted">
        <div className="flex flex-col" style={{ gap: 18 }}>
          {SECTIONS.map((section, idx) => (
            <section
              key={section.heading}
              className="flex flex-col"
              style={{
                gap: 8,
                paddingBottom: idx < SECTIONS.length - 1 ? 16 : 0,
                borderBottom:
                  idx < SECTIONS.length - 1
                    ? "1px solid var(--border-faint)"
                    : "none",
              }}
            >
              <div className="flex items-baseline" style={{ gap: 10 }}>
                <span
                  className="font-mono"
                  style={{
                    color: "var(--accent)",
                    fontSize: 10,
                    letterSpacing: "0.14em",
                    minWidth: 28,
                  }}
                >
                  {String(idx + 1).padStart(2, "0")}
                </span>
                <h2
                  className="font-mono uppercase"
                  style={{
                    fontFamily: "var(--font-display)",
                    color: "var(--text-primary)",
                    fontSize: 14,
                    letterSpacing: "0.08em",
                    margin: 0,
                  }}
                >
                  {section.heading}
                </h2>
              </div>
              <p
                className="font-mono"
                style={{
                  color: "var(--text-muted)",
                  fontSize: 12,
                  lineHeight: 1.65,
                  paddingLeft: 38,
                  margin: 0,
                }}
              >
                {section.body}
              </p>
            </section>
          ))}
        </div>
      </WindowPanel>
    </div>
  );
}
