# VR Module Frontend UX Discussion — 10 Vulnerability Researcher Personas

## Personas

### P1: "Ari" — Offensive Security Lead, Bug Bounty Top-50
**Background:** 8 years exploit dev. Runs bugs through Synack Red Team. Uses IDA, pwntools, GDB daily. Has 200+ CVEs. Writes PoCs in C and Python. Doesn't trust tools that hide state. Wants raw data accessible at every layer.

### P2: "Jun" — Product Security Engineer, FAANG
**Background:** 5 years internal security. Triages 40 vulns/week from Dependabot, fuzzing, and internal researchers. Cares about CVSS accuracy, SLA timelines, and whether advisories are "PM-readable." Uses Jira, Bugcrowd, and internal dashboards. Spends 70% of time writing advisories, 30% reproducing.

### P3: "Reva" — Academic Vulnerability Researcher
**Background:** PhD student, systems security lab. Publishes at USENIX/CCS. Evaluates tools on reproducibility and evidence chain integrity. Needs to cite specific analysis steps in papers. Cares deeply about methodology transparency. Uses Ghidra because it's free (would use IDA if she had it).

### P4: "Marcus" — Red Team Operator, Defense Contractor
**Background:** 12 years offense. Writes kernel exploits. Cares about OPSEC, information compartmentalization, and whether tool output can be shared without leaking TTP. Wants to export results without metadata that reveals the analysis toolchain. Minimal UI, maximum keyboard control.

### P5: "Dina" — Malware Analyst Turned Vuln Researcher
**Background:** 6 years reversing malware, now hunting N-days in the same codebases. Uses YARA, IDA, and x64dbg. Thinks in terms of behavioral indicators and execution traces. Wants to see the binary's behavior, not just its code. Workflow: find the vuln via diffing, write a trigger, prove the crash.

### P6: "Tomás" — Security Consultant, Boutique Firm
**Background:** Runs pentests and vuln assessments for 15 clients simultaneously. Needs to produce client-deliverable reports. Cares about advisory formatting, professional appearance, and disclosure tracking timelines. Uses multiple tools but needs one dashboard view. Time-boxed: 2h per vuln max.

### P7: "Kenji" — Fuzzing Infrastructure Engineer
**Background:** Maintains a 200-core fuzzing cluster. OSS-Fuzz contributor. Sees thousands of crash reports/day. Cares about dedup quality, false positive rate, and triage speed. The UI must handle scale — 50+ findings per project is normal for him. Doesn't manually analyze most crashes; wants the tool to tell him which ones are worth looking at.

### P8: "Sasha" — Junior Security Analyst, First Vuln Research Job
**Background:** 1 year in security, CS degree. Can read C and Python. Understands stack overflows conceptually but has never written an exploit. Needs guidance: what does this CVSS score mean? What should I do next? The tool's workflow is educational for her. She'll learn from watching the agent reason.

### P9: "Emeka" — Vulnerability Disclosure Coordinator
**Background:** Manages coordinated disclosure at a large vendor. Receives 200+ reports/year. Doesn't write exploits — evaluates them. Needs to track disclosure state, embargo dates, vendor response, and CVE assignment. Cares about the advisory being complete and actionable. Wants email-ready export.

### P10: "Lena" — Security Team Lead, Startup
**Background:** 4-person security team, 3 products. Needs executive-level visibility: how many vulns are open, what's the worst CVSS, are we tracking disclosure timelines. Doesn't do hands-on research but reviews findings and approves advisories before they go out. Wants a dashboard, not a terminal.

---

## Discussion Topic 1: Project List Page — What Matters at a Glance?

**Lena:** The project list is the first thing I see. I need: project name, CVE ID, status (is it running, done, failed?), CVSS score of the worst finding, and how old it is. Traffic-light status indicators. Red = failed or stalled, green = completed with findings, yellow = still running.

**Jun:** Agree on traffic lights but add the finding count. If a project completed with zero findings, that's different from completing with five. Also need the target class — "native" vs "python" vs "jvm" changes how I interpret the results.

**Tomás:** I'm managing 15 clients. I need to filter by status and sort by creation date. Also, which system was this run against? If I can't tell which client's binary this is for, the list is useless. The project name should be prominent — that's my client identifier.

**Kenji:** Pagination is non-negotiable. I might have 200 projects. Infinite scroll is fine if it's lazy-loaded, but I need a way to search/filter by CVE ID. I search by CVE more than by project name.

**Marcus:** Minimal. Name, CVE, status, date. No thumbnails, no icons, no cards with shadows. A dense table. Every pixel of whitespace is a pixel I'm scrolling past. Think htop, not Notion.

**Ari:** Table view with sortable columns. Name, CVE, status, target class, finding count, CVSS (highest), created date, last updated. Click a row to drill in. No cards — they waste vertical space. One action button per row: "View" or "Delete".

**Sasha:** I only have 3 projects so the list view doesn't matter much to me. But I need to understand what each status means. Can we have tooltips? "Analyzing" means what — is it decompiling? Researching? Can I see which workflow state it's in?

**Reva:** Status granularity is important. "Analyzing" is too vague. Show the current workflow state: `setup`, `research (turn 12/30)`, `poc_development`, `advisory`. That's the information I need to decide whether to wait or go do something else.

**Dina:** +1 on showing the current state within the workflow. And the budget: how many turns used out of how many? If the agent is at 28/30 and still in research, I know it's going to auto-submit a partial result. I want to see that before it happens, not after.

**Emeka:** I don't care about workflow internals. I care about disclosure status. Add a column: "Disclosure: undisclosed / reported / patched." That's my workflow, not yours.

### Consensus: Project List Page
- **Table layout, not cards.** Dense, sortable columns.
- **Columns:** Name, CVE ID, Status (with current workflow state, not just "analyzing"), Target Class, Finding Count, Highest CVSS, Disclosure Status, Created, Updated.
- **Status shows workflow state in parentheses:** "Analyzing (research 12/30)" — current state + budget progress when running.
- **Filters:** Status dropdown, target class, free-text search (matches name and CVE).
- **Sort:** All columns sortable, default by updated_at desc.
- **Pagination:** Offset-based, 20 per page, with total count shown.
- **Actions:** "New Project" button (top-right), per-row "View" link, delete via confirmation dialog.
- **Disclosure column** for Emeka's use case — color-coded badge.

---

## Discussion Topic 2: Project Detail Page — Layout and Information Hierarchy

**Ari:** Top of page: project header with CVE, status, target info. Then two panels: left = findings list, right = selected finding detail. Classic master-detail. No tabs hiding information — I want to see the finding list AND the detail simultaneously.

**Jun:** Disagree on the master-detail split. Most projects have 1-2 findings. The master list takes up space for nothing. Give me tabs: Overview, Findings, Agent Log, Advisory. Overview = summary + mitigations. Findings = the detail. Agent Log = what the agent did. Advisory = the formatted output.

**Reva:** I want the agent reasoning trace above everything else. That's the methodology. Show me each turn: what action it took, what it found, what it concluded. Think of it as a lab notebook. If I can't see the chain of evidence, I can't cite it.

**Marcus:** Tabs are fine but the agent log is the only thing I care about. I need to verify the agent actually analyzed the right function, not some unrelated code. Show me the decompiled output it worked with. If the agent looked at `sub_14000A230` but the vuln is in `sub_14000B110`, I need to catch that immediately.

**Dina:** I agree with tabs. But the "Overview" tab needs to be useful, not a lorem ipsum placeholder. Show: CVE ID, target binary name, target class, mitigations (checksec output — ASLR/NX/canary as badges), workflow state, budget (turns used, time elapsed), and the obligation ledger (which obligations are met, which are outstanding).

**Sasha:** The obligation ledger is the thing I find most valuable. It tells me what the agent has proven vs what it hasn't. Show it as a checklist: green check = met, red X = unmet, gray dash = waived. With the evidence reference for each met obligation.

**Lena:** I skip to the advisory. If there's a completed advisory, show me a preview right on the overview page. Title, CVSS score + severity badge, CWE, one-paragraph summary. That's my decision point: do I approve this for disclosure or not?

**Kenji:** When I have 50 findings from a fuzzing run (v0.3+), the findings list needs to be filterable by crash type and sortable by exploitability verdict. For v0.1 with 1-2 findings, a simple list is fine. But design for scale now.

**Tomás:** The advisory export is my deliverable. I need a "Copy to clipboard" button for the advisory text (Markdown), and an "Export PDF" button. The advisory must look professional without manual editing. If I have to reformat it, the tool failed.

**Emeka:** The disclosure tracking section needs to be editable inline. I click "UNDISCLOSED" → dropdown → "REPORTED" → fills in vendor_contact → saves. Don't make me navigate to a separate page to update disclosure status.

### Consensus: Project Detail Page
- **Header bar:** Project name, CVE ID (linked to NVD if exists), status badge with workflow state, target class badge, created/updated timestamps.
- **Mitigations ribbon:** Inline badges for NX, ASLR, Canary, CFI, CET — derived from checksec. Green = enabled, red = missing.
- **Tab layout with 4 tabs:**
  1. **Overview** — Obligation checklist (met/unmet/waived with evidence refs), budget gauge (turns + time), advisory preview card (if completed), disclosure status inline-editable.
  2. **Findings** — List with crash type, exploitability verdict, CVSS, signature hash prefix. Click to expand detail: root cause text, vulnerable function, PoC code (syntax-highlighted), ASAN report (monospaced).
  3. **Agent Log** — Chronological turn-by-turn trace. Each turn shows: action name, params, reasoning text, result summary (collapsed), tool time. Expand to see full result JSON. Adjudication warnings highlighted in amber.
  4. **Advisory** — Full formatted advisory. Copy-to-clipboard (Markdown). Export button (PDF in v0.2). Editable sections (title, remediation) for consultant use case.
- **No master-detail split in v0.1.** Tabs are cleaner for 1-2 findings. When findings scale (v0.3), the Findings tab becomes a filterable table.

---

## Discussion Topic 3: The Agent Log — How Much to Show?

**Reva:** Everything. Every turn, every LLM prompt (or at least a summary), every tool result. I need to reconstruct the full reasoning chain. Collapsed by default is fine, but expandable to full detail.

**Marcus:** I need the raw decompiled output the agent saw. If it decompiled function X, show me the pseudocode. Not a summary — the actual code. I'll read it faster than the agent's paraphrase.

**Ari:** Agree with Marcus. Show the tool results inline, in collapsible panels. Turn 3: decompile(sub_14000A230) → [expand to see 200 lines of pseudocode]. Turn 5: diff_versions → [expand to see the unified diff]. The reasoning text is secondary — I care about what data the agent had.

**Jun:** I'm the opposite. I care about the reasoning, not the raw data. What did the agent conclude? Did it identify the right function? Did it classify the bug correctly? The raw decompiled code is noise for my workflow. I trust the tool or I don't.

**Sasha:** Can we have two views? A "Summary" mode (Jun's view) and a "Detail" mode (Ari's view)? In summary mode, each turn is one line: "Turn 3: decompiled ParseHeader — identified 4-byte stack buffer." In detail mode, expand to see the full pseudocode.

**Dina:** The adjudication results are critical. When the agent tried to submit and got blocked — "submission_blocked: CRITICAL obligation 'patch_identified' unmet" — that needs to be visually prominent. Red banner, not buried in JSON.

**Kenji:** For 30 turns, the log gets long. Add a filter: "show only tool actions" (skip reasoning-only turns), "show only errors," "show only submissions."

**Tomás:** I never look at the agent log. If the advisory is good, I don't care how it got there. But I need to know if it failed — and why. Show me the last turn's status prominently. "Agent submitted after 18 turns. All critical obligations met." Or "Agent exhausted budget. Root cause: partial."

**Emeka:** I agree with Tomás. The log is for power users. The overview tab should have a one-sentence summary: "Research completed in 18 turns (4 minutes). All 5 CRITICAL/REQUIRED obligations met. 2 RECOMMENDED waived at 80% budget."

**Lena:** I need a progress indicator while it's running. A live-updating log is too much. Give me a progress bar: "Research: turn 12/30" with a spinner. When it transitions to `poc_development`, update the bar. I'll check back in 10 minutes.

### Consensus: Agent Log
- **Turn-by-turn timeline**, vertical, newest at bottom (chronological reading order).
- **Each turn card shows:** Turn number, action badge (color-coded: blue=decompile, green=diff, orange=reasoning, red=submit_blocked, purple=submit_success), reasoning text (first sentence visible, expand for full), tool time.
- **Expandable tool results:** Click to reveal full result (pseudocode, diff, xrefs). Syntax-highlighted for code. Monospaced.
- **Adjudication warnings:** Amber/red banners inline when submission was blocked. Shows which obligation was unmet.
- **Summary line at top of log tab:** "Completed in 18/30 turns (4m 12s). 5/5 critical met. 3/3 required met. 2/3 recommended waived."
- **Filter bar:** All | Tool Actions | Reasoning | Errors | Submissions.
- **While running:** Live-updating with newest turn appearing. Progress indicator in tab title: "Agent Log (12/30)".

---

## Discussion Topic 4: Finding Detail — What Does a Vulnerability Look Like?

**Ari:** The finding is the product. Show me: crash type (with CWE badge), root cause (full paragraph), vulnerable function (link to decompile if we store it), PoC code (syntax-highlighted, copy button), ASAN report (raw, monospaced, searchable), exploitability verdict, CVSS vector breakdown.

**Dina:** The crash signature is important for dedup. Show the hash prefix and the normalized frames. When I'm triaging 20 crashes from a fuzzer (v0.3), I need to see at a glance which ones are duplicates.

**Jun:** CVSS breakdown must be interactive. Show the vector string AND the metric-by-metric table: AV:N (Network), AC:L (Low), PR:N (None), UI:N (None), S:U (Unchanged), C:H (High), I:H (High), A:H (High). With the score computation visible. I adjust CVSS for every vuln I review — "actually this requires local access, not network" — and I need to see how that changes the score.

**Reva:** Evidence references. Every claim in the finding should link back to the agent turn that produced the evidence. "Root cause: heap buffer overflow in ParseHeader due to unchecked length field (Turn 5, Turn 8)." Click to jump to that turn in the log.

**Marcus:** PoC code needs a "Download" button. I'm not copying 200 lines from a browser. Download as `poc.py` or `poc.c` with the right extension based on `poc_language`.

**Sasha:** Exploitability verdict needs explanation. "Likely exploitable" means what? Show the rationale: "Controllable write into adjacent memory. Write size: 128 bytes. Heap grooming feasible." Don't just say the verdict — explain it.

**Kenji:** For bulk triage: each finding in the list should show crash_type, verdict, CVSS as inline badges. I decide in 2 seconds whether to drill in. The detail panel is for the 5% I actually investigate.

**Tomás:** The advisory section of the finding is what I export. It should look like a vendor advisory: Title, Summary, Technical Details, Impact, Affected Versions, Remediation, References. Each section editable. I'll tweak the wording before sending it to a client.

**Emeka:** Disclosure history. When I change the status from "undisclosed" to "reported," that transition should be logged with a timestamp. "May 8 2026: status changed to REPORTED by emeka@vendor.com." I need an audit trail, not just the current state.

**Lena:** CVSS severity as a large colored badge. CRITICAL = dark red, HIGH = red, MEDIUM = orange, LOW = yellow, NONE = gray. That's what I see first. The number is secondary to the color.

### Consensus: Finding Detail
- **Header:** Crash type badge (color-coded by family), CVSS severity badge (large, colored), exploitability verdict badge.
- **Sections (collapsible):**
  1. **Root Cause** — Full paragraph. Evidence refs linked to agent log turns.
  2. **Vulnerable Function** — Function name/address. Decompiled code if stored (syntax-highlighted).
  3. **CVSS Breakdown** — Vector string + metric table (8 metrics, each showing value and description). Score computation visible. Read-only in v0.1 (interactive adjustment is v0.2 enhancement).
  4. **CWE** — Badge with CWE-ID, name, description.
  5. **PoC** — Syntax-highlighted code. Copy button. Download button (filename = `poc_{cve_id}.{ext}`).
  6. **ASAN Report** — Monospaced, scrollable, collapsible. Raw output preserved.
  7. **Crash Signature** — Hash prefix, normalized top-5 frames, dedup note.
  8. **Exploitability** — Verdict + rationale text.
  9. **Disclosure** — Current status badge, inline editable dropdown, vendor contact field, embargo date picker, assigned CVE field, transition history log.
  10. **Advisory Preview** — Rendered advisory text (Markdown). Copy + Download buttons.

---

## Discussion Topic 5: Creating a New Project — The Input Form

**Ari:** CVE ID, binary path, patched binary path (optional), system ID (for SSH), go. Four fields and a submit button. Don't over-design this.

**Jun:** Add a "target class" selector. The system needs to know if it's native, JVM, Python, etc. Default to "native" but let me pick.

**Sasha:** I don't know what "system ID" means. Can the form explain that this is the research workstation I'm running the analysis on? And list the available systems so I can pick from a dropdown instead of typing a number?

**Dina:** The binary path is the most error-prone field. Is this a local path on the workstation? On the AILA server? Can I upload a file? In v0.1 with SSH, the path is on the remote system. Make that explicit: "Path on the research workstation."

**Tomás:** I want a "context notes" field — free text where I write "Client reported this crashes their production server. Priority: urgent. Test against version 2.3.1 specifically." The agent should see this context.

**Reva:** The form should show a readiness check result before I submit. "System 'workstation-1': gcc OK, gdb OK, python3 OK, IDA MCP reachable OK." If the system isn't ready, don't let me submit and waste time.

**Marcus:** No readiness check in the form — that's a separate step. I know my system is ready. Don't add round-trips to the happy path. Make it a button: "Check readiness" (optional), then "Create Project" (always available).

**Kenji:** If I'm creating 20 projects from a fuzzing run (v0.3), the form needs to be fast. Pre-fill target class, system ID, and patched binary from the last project. Or better: batch creation via CSV upload.

**Emeka:** I don't create projects. I receive findings. This form doesn't affect me.

**Lena:** The form should be a modal, not a separate page. I click "New Project" from the list page, fill in the modal, submit, see the new project appear in the list. No page navigation.

### Consensus: New Project Form
- **Modal or slide-over panel** from the project list page (not a separate route, but a route exists for direct linking).
- **Fields:**
  1. **Name** — Text input, required. Placeholder: "CVE-2024-12345 — libpng analysis"
  2. **CVE ID** — Text input, optional. Validated format: CVE-YYYY-NNNNN. Auto-linked to NVD on blur.
  3. **Target binary path** — Text input with label "Path on the research workstation." Required.
  4. **Target class** — Dropdown, default "native." Shows all 9 TargetClass values.
  5. **Patched binary path** — Text input, optional. Label: "Path to patched version (for differential analysis)."
  6. **Research workstation** — Dropdown of registered systems (fetched from `/systems`). Required. Shows system name + host.
  7. **Context notes** — Textarea, optional. Placeholder: "Add notes the agent should consider during analysis..."
- **Optional readiness check:** Button "Check readiness" runs the check and shows results inline. Does NOT block submission.
- **Submit button:** "Start Research" — creates project and dispatches workflow. Shows toast with task ID.
- **Pre-fill from URL params:** `?cve=CVE-2024-12345&system=3` pre-fills fields for programmatic use.

---

## Discussion Topic 6: Live Progress — What Happens While It's Running?

**Lena:** Progress bar or stepper. Show the 5 workflow states as steps: Setup → Research → PoC Dev → Advisory → Done. Highlight the current step. That's all I need.

**Dina:** Inside the Research step, show the turn counter: "Turn 12/30." And the obligation status — how many met vs unmet. I want to know if the agent is making progress or spinning.

**Ari:** SSE live log. Stream each turn result as it happens. I'm watching this like a terminal. Don't poll every 5 seconds and give me stale data — stream it.

**Sasha:** The stepper + turn counter is enough for me. But add estimated time remaining. If the agent averages 15 seconds per turn and has 18 turns left, say "~4.5 minutes remaining."

**Jun:** I start a project and come back later. When I return, I need to immediately see: it's done, it found something, here's the CVSS. Don't make me click through to figure out the result. The project list page status column should say "Completed — CVSS 9.8 CRITICAL" not just "Completed."

**Marcus:** No estimated time. It's wrong more often than right and creates false expectations. Show: state, turn X/Y, elapsed time. That's it.

**Kenji:** Toast notification when a project completes. I have 20 running. I need to know which one finished without polling every tab.

**Reva:** The live log should show the agent's reasoning text as each turn completes. Not the full result — just the 1-3 sentence reasoning. I'm reading along as it thinks. This is the most educational part of the tool.

**Tomás:** I start projects and check back in 30 minutes. Live progress doesn't matter to me. But the email notification when it completes would be killer (v0.2).

**Emeka:** No live progress needed for my workflow. I wait for the final advisory.

### Consensus: Live Progress
- **Workflow stepper** on the project detail overview tab: 5 states as horizontal steps with active state highlighted. Completed steps show green checkmarks.
- **Inside Research step:** Turn counter "12/30" with a mini progress bar. Obligation tally: "3/5 critical met."
- **Agent log tab live-updates** via SSE or polling (2-second poll). New turns appear at the bottom with smooth scroll-into-view.
- **Reasoning text visible** as each turn completes — one sentence summary in the log.
- **Toast notification** when project completes (browser notification if tab is backgrounded, in-app toast if foreground). Shows project name + outcome.
- **No estimated time.** Show elapsed time only.
- **Project list page status column** includes CVSS when completed: "Completed (9.8 CRITICAL)".

---

## Discussion Topic 7: Advisory Export and Disclosure Workflow

**Tomás:** This is my entire use case. The advisory must export as Markdown (clipboard) and eventually PDF. The format must be client-ready: no "Generated by AILA" watermark, no internal IDs visible, no evidence hashes. Clean, professional, with my firm's name if I add it.

**Emeka:** The disclosure workflow is a state machine. I need: a timeline showing status transitions, editable fields (vendor_contact, embargo_until, assigned_cve_id, patch_version), and a button to advance the status. "Mark as Reported" → fills in reported_at automatically.

**Jun:** The advisory should match the format used by major vendors (Google Project Zero, Microsoft MSRC, Ubuntu Security Notices). Title, affected software, severity, description, impact, workarounds, fix. Don't invent a new format — match the industry.

**Reva:** References section is critical. The advisory should cite the agent's evidence: "Root cause identified via binary diff of commit abc123 (reference: agent turn 5)." And external references: NVD link, vendor advisory link, patch commit URL.

**Ari:** I don't care about the advisory. I care about the PoC. If the advisory has a wrong CVSS or a weak summary, I'll fix it in 30 seconds. What I can't fix is a broken PoC. Make the PoC the hero of the finding, not the advisory text.

**Marcus:** Export the advisory without any AILA branding, internal project IDs, or system hostnames. If I send this to a vendor and they see "project_id: abc123" or "system: workstation-1.internal," that's an OPSEC leak. Strip all internal metadata from exports.

**Dina:** +1 on Marcus. The export should be a standalone document. No back-references to the platform. Just the vulnerability description, PoC, and remediation guidance.

**Sasha:** The CVSS severity label should use standard colors from the NVD color scheme. CRITICAL=dark red, HIGH=red, MEDIUM=orange, LOW=yellow. Consistent with what I learned in training.

**Kenji:** Batch export. If I have 50 findings, I want "Export all as CSV" with one row per finding: CVE, crash_type, CVSS, function, verdict. For triage reporting, not individual advisories.

**Lena:** I approve advisories before disclosure. Add an "Approve" action on the advisory. Approved advisories can proceed to disclosure; unapproved ones are drafts. Simple boolean, visible in the list.

### Consensus: Advisory & Disclosure
- **Advisory rendered as Markdown** on the Advisory tab, with a "Copy Markdown" button.
- **Export strips internal metadata:** No project_id, no system_id, no agent turn references, no AILA branding. Clean standalone document.
- **Disclosure timeline:** Chronological log of status transitions with timestamps and actor. Inline-editable fields: vendor_contact, embargo_until, assigned_cve_id, patch_version.
- **Status advancement buttons:** "Mark as Reported" (auto-fills reported_at), "Mark as Acknowledged," etc. Each transition is a PATCH to the API.
- **CVSS colors:** NVD standard. CRITICAL=#7b241c, HIGH=#c0392b, MEDIUM=#e67e22, LOW=#f1c40f, NONE=#95a5a6.
- **PoC download button** prominent on the finding detail, not buried in the advisory.
- **v0.2 enhancements:** PDF export, batch CSV export, advisory approval workflow.

---

## Discussion Topic 8: Obligations and Evidence — How to Surface the "Trust Layer"

**Reva:** This is the differentiator. No other tool shows you what it proved vs what it assumed. The obligation ledger should be front-and-center on the overview tab. Not hidden in a settings page.

**Dina:** Show it as a checklist card. Each obligation is a row: icon (check/X/dash), name, severity badge (CRITICAL/REQUIRED/RECOMMENDED), evidence reference (clickable link to agent log turn), and met/unmet/waived status.

**Ari:** The adjudication result is the one thing I check. "Submission accepted: no hedge phrases, all criticals met, 2 recommended waived at 80% budget." Or "Submission downgraded: hedge phrase 'might be' detected in root cause." Show this as a banner at the top of the finding.

**Sasha:** Can you explain what each obligation means? Tooltip: "patch_identified: The agent must locate the specific code change that fixed the vulnerability. Evidence: a binary diff result naming the patched function."

**Jun:** I want to see which obligations were auto-waived vs manually waived vs met. Three distinct states, three distinct visuals. Auto-waived (gray, italic text), met (green check), unmet (red X). If an obligation is unmet in a completed project, that's a data quality issue I need to flag.

**Marcus:** Obligations are internal quality control. Don't show them to the end user unless they ask. Put them in a collapsible "Evidence Quality" section, collapsed by default.

**Tomás:** I agree with Marcus for my use case. My clients don't care about obligation ledgers. But for internal review, I expand it and check: did the agent actually prove its claims?

**Kenji:** For scale: when I have 50 findings, show an aggregate: "45 findings with all criticals met, 3 with partial evidence, 2 with unmet criticals." Click to see which findings are under-evidenced.

**Emeka:** I need to trust the CVSS score. If the CVSS was computed from a template (crash_type → default vector) vs computed from actual analysis, label it. "CVSS source: template-derived" vs "CVSS source: agent-verified."

**Lena:** Summary metric on the overview: "Evidence quality: 5/5 critical obligations met." Green if complete, yellow if partial. One glance.

### Consensus: Obligations & Evidence
- **Obligation checklist card** on the Overview tab. Visible by default (not collapsed — Reva wins over Marcus here because this is the tool's differentiator).
- **Three states:** Met (green check + evidence ref link), Unmet (red X), Waived (gray dash + waive reason).
- **Severity badges** inline: CRITICAL (red), REQUIRED (orange), RECOMMENDED (blue).
- **Tooltips** on each obligation name explaining what it means and what constitutes evidence.
- **Adjudication banner** on the finding detail: green = accepted, amber = downgraded (with reason), red = blocked (with unmet obligations listed).
- **Summary metric** in project header: "Evidence: 5/5 critical met" — green badge.
- **CVSS source label:** "template-derived" or "agent-computed" next to the CVSS vector.

---

## Discussion Topic 9: Keyboard Navigation and Accessibility

**Marcus:** Full keyboard navigation. `j/k` to move between items in any list. `Enter` to drill in. `Escape` to go back. `?` for keyboard shortcut help. I don't use a mouse.

**Ari:** Tab-through form fields is enough for me. But code blocks (decompiled output, PoC) need to be selectable and copyable without weird browser selection issues. No "smart" copy that reformats my text.

**Sasha:** Screen reader support. Proper ARIA labels on badges and status indicators. "Status: analyzing, research turn 12 of 30" should be read aloud, not "green circle icon."

**Reva:** Color-blind mode. If you're using red/green for met/unmet, add shapes or text labels alongside. Some of us are red-green color blind.

**Dina:** Code blocks should use monospace font with the user's system preference. Not a random web font. And dark mode support — I'm in IDA all day, my eyes are adapted to dark themes.

**Tomás:** Mobile responsive? I check project status on my phone sometimes. The project list and status should render on a small screen. The agent log and code blocks can be desktop-only.

**Lena:** Focus indicators on all interactive elements. If I'm tabbing through the form, I need to see where I am. The default browser outline is fine — don't hide it for aesthetics.

### Consensus: Accessibility & UX
- **Keyboard:** Tab navigation for all interactive elements. `j/k` for list navigation (nice-to-have, v0.2).
- **Screen readers:** ARIA labels on all badges, status indicators, and interactive elements.
- **Color-blind safe:** Shapes + text labels alongside color indicators. Met = check icon + green, Unmet = X icon + red, Waived = dash icon + gray.
- **Dark mode:** Respect system preference via AILA's existing theme system. Code blocks use `font-mono` (system monospace stack).
- **Mobile:** Project list and overview tab responsive. Agent log and code blocks desktop-optimized (horizontal scroll on mobile).
- **Copy behavior:** Plain text copy on all code blocks. No formatting artifacts.

---

## Discussion Topic 10: What NOT to Build in v0.1

**Ari:** No chat interface. The agent is not a chatbot. It's an autonomous researcher. I watch it work, I don't talk to it mid-run.

**Jun:** No real-time CVSS editor. Show the computed score. If I need to adjust, I'll do it in my own tooling or in v0.2.

**Marcus:** No social features. No comments, no @mentions, no activity feeds. This is a single-operator tool.

**Kenji:** No dashboard with charts. No "vulnerabilities found this month" graph. That's v0.4 analytics.

**Tomás:** No PDF export. Markdown copy is enough for v0.1. PDF formatting is a rabbit hole.

**Reva:** No comparison view between findings. "Compare finding A vs finding B" is useful but complex. Save it.

**Dina:** No binary upload from the browser. The binary is on the research workstation, accessed via SSH. The browser never touches it.

**Sasha:** No onboarding wizard. A good form with good labels and tooltips is enough. Don't build a 5-step setup flow.

**Emeka:** No email notifications. I'll check the UI. Email is v0.2.

**Lena:** No multi-project dashboard rollup. Each project is independent in v0.1. Portfolio view is v0.3.

### Consensus: NOT in v0.1
- No chat/conversational interface with the agent
- No interactive CVSS editor (read-only display)
- No PDF export (Markdown copy only)
- No binary upload from browser (paths are SSH-side)
- No onboarding wizard
- No email/webhook notifications
- No dashboard charts/analytics
- No comparison view between findings
- No social features (comments, mentions)
- No portfolio/multi-project rollup dashboard
- No batch project creation

---

## Final Design Summary

### Page Structure
1. **`/vr`** — Project list (table, sortable, filterable, paginated)
2. **`/vr/projects/new`** — New project form (also accessible as modal from list)
3. **`/vr/projects/:id`** — Project detail with 4 tabs:
   - **Overview** — Header + mitigations + obligation checklist + budget gauge + advisory preview + disclosure status
   - **Findings** — Finding list (crash type + verdict + CVSS badges) → click to expand detail
   - **Agent Log** — Turn-by-turn timeline with expandable tool results
   - **Advisory** — Rendered advisory text + copy/download

### Component Inventory (v0.1)
- `ProjectsPage` — table with filters
- `NewProjectForm` — modal/page with 7 fields
- `ProjectDetailPage` — header + tab container
- `OverviewTab` — mitigations ribbon, obligation checklist, budget gauge, advisory preview card, disclosure inline editor
- `FindingsTab` — finding list with expandable detail panels
- `AgentLogTab` — turn timeline with collapsible result panels
- `AdvisoryTab` — markdown renderer + copy button
- **Shared widgets:** CVSS badge, severity badge, crash type badge, status badge, obligation row, workflow stepper

### Design Principles (from the personas)
1. **Dense, not decorative.** Table over cards. Information over whitespace. These users read terminals.
2. **Evidence is the product.** Obligations, evidence refs, adjudication banners — these aren't metadata, they're the value proposition.
3. **Export must be clean.** No internal IDs, no platform branding, no evidence hashes in exported advisories.
4. **Status is granular.** "Analyzing" is not enough. Show workflow state + turn progress.
5. **Code is king.** PoC and decompiled output are syntax-highlighted, copyable, downloadable. Not secondary content.
6. **Progressive disclosure.** Sasha sees tooltips and a simple checklist. Ari expands to see raw JSON and full decompiled output. Both use the same page.
7. **Accessibility by default.** Screen readers, color-blind safe, keyboard navigable. Not an afterthought.
