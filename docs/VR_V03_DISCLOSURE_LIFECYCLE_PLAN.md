# VR Module v0.3 — Disclosure Lifecycle Plan (multi-track, not VRP-only)

## What this plan covers

When the VR reasoning engine emits a `DirectFinding` outcome, the work isn't done — it has to reach an audience. That audience is rarely just Chrome VRP. Real vulnerability researchers route the same finding down multiple disclosure tracks in parallel:

- **Bug bounty programs** (Chrome VRP, Mozilla, Apple Security, MSRC, GitHub Bug Bounty, HackerOne programs, Bugcrowd, Intigriti)
- **Vulnerability brokers** (Trend Micro ZDI, Crowdfense)
- **Coordination centers** (CERT/CC, CISA, ICS-CERT, JPCERT, ENISA)
- **Vendor-direct** (PSIRTs, `security@` mailboxes for vendors without programs)
- **CVE Numbering Authorities** (MITRE direct, GitHub Security Advisory CNA, Red Hat CNA, etc.)
- **Public writeup** (blog post, conference talk, GitHub advisory, mastodon thread)
- **Academic publication** (USENIX Security, IEEE S&P, CCS, NDSS papers; Black Hat / DEF CON talks)

Each track has its own state machine, evidence requirements, embargo rules, and output artifacts. v0.3 ships the system that orchestrates these tracks for a single finding, tracks cross-track embargoes, and produces submission-ready artifacts.

**Critical**: the "public writeup / blog post" track is a first-class output, not an afterthought. Per operator feedback: public writeups serve as portfolio/audition material for hiring, conference invitations, and reputation-building. The system supports them with embargo-aware publishing, sanitized PoCs (working PoC stays private, public PoC is de-fanged), and attribution chains.

## Position in the VR roadmap

This plan is a companion to `VR_V03_REASONING_PLAN.md` and `VR_V03_FUZZING_PLAN.md`. Where:
- v0.3 reasoning produces `DirectFinding` outcomes
- v0.3 fuzzing produces `vr_fuzz_finding` records that get promoted to `vr_findings`
- **v0.3 disclosure** (this plan) consumes both and routes them to disclosure tracks

Out of scope for v0.3 disclosure:
- Negotiating bounty amounts (operator does this manually)
- Drafting legal/contractual language (operator does this manually)
- Sending vendor emails (operator does this from their own mailbox; system drafts the email but doesn't send)
- Public talks (system drafts the talk abstract; operator gives it)

---

## Gray Area Resolutions (v0.3 disclosure scope)

### GA-31: Disclosure tracks as plugins, not enum

**Decision:** Each disclosure track is a Python class implementing `DisclosureTrack` protocol. New tracks (a new bounty program, new CERT) are added by writing a small class + YAML config. Not a hardcoded enum.

```python
class DisclosureTrack(Protocol):
    track_id: str                      # "chrome_vrp" | "mozilla" | "zdi" | "blog_post" | etc.
    track_kind: TrackKind              # bounty|broker|coordination|vendor_direct|cna|public|academic
    display_name: str
    
    submission_template_path: Path     # Markdown/Jinja2 template
    severity_schema: SeveritySchema    # CVSS | custom
    required_artifacts: list[ArtifactKind]
    embargo_policy: EmbargoPolicy
    bounty_estimator: BountyEstimator | None
    
    def validate_finding(self, finding: VRFinding) -> ValidationResult: ...
    def render_submission(self, finding: VRFinding, artifacts: list[Artifact]) -> SubmissionDraft: ...
    def parse_response(self, vendor_response: str) -> ResponseUpdate: ...
```

Built-in tracks for v0.3 (~10 implementations):

| Track ID | Kind | Notes |
|---|---|---|
| `chrome_vrp` | bounty | Chrome VRP submission form via Issue Tracker; severity self-rating |
| `mozilla_bb` | bounty | Bugzilla submission with confidentiality flag |
| `apple_security` | bounty | Apple Security Bounty portal |
| `msrc` | bounty | MSRC Researcher Portal; CVE pre-assignment |
| `github_bb` | bounty | GitHub Bug Bounty (HackerOne) |
| `zdi` | broker | ZDI researcher submission; exclusivity required |
| `cert_cc` | coordination | CERT/CC VINCE; multi-vendor coordination |
| `cisa_kev` | coordination | CISA KEV report (post-exploitation observation only) |
| `vendor_direct` | vendor_direct | Generic vendor `security@` email; uses Markdown template |
| `cna_github_gsa` | cna | GitHub Security Advisory draft (own-repo or via CNA) |
| `blog_post` | public | Public writeup as Markdown; embargo-aware publishing |
| `conference_cfp` | academic | Conference paper/talk abstract |

YAML config per track (`data/disclosure_tracks/<track_id>.yaml`):

```yaml
track_id: chrome_vrp
display_name: Chrome Vulnerability Reward Program
kind: bounty
program_url: https://bughunters.google.com/report
required_artifacts:
  - working_poc
  - crash_report
  - severity_assessment
  - reproducer_instructions
embargo:
  default_days: 90
  vendor_extension_allowed: true
  public_disclosure_after_patch: true
severity_schema: chrome_vrp_custom    # not CVSS
bounty_table_path: data/bounty_tables/chrome_vrp.json
template_path: data/disclosure_templates/chrome_vrp.md.j2
```

### GA-32: One finding → many disclosure tracks (parallel)

**Decision:** `vr_findings` has a 1:N relationship with `vr_disclosures`. Each `vr_disclosures` row is one track's lifecycle for that finding. Tracks run in parallel with cross-track coordination via embargo records.

Examples of routing decisions:
- **High-impact V8 sandbox escape**: `chrome_vrp` + (after patch ships) `blog_post` + (after blog) `conference_cfp`
- **Multi-vendor TLS implementation bug**: `cert_cc` (coordinates) + N×`vendor_direct` (each vendor) + (after coordinated disclosure) `blog_post`
- **GitHub Action vulnerability in third-party library**: `cna_github_gsa` (CVE assignment) + `vendor_direct` (project maintainer) + (after fix) `blog_post`
- **Bug in shipping commercial product without bounty**: `zdi` (broker pays) OR `vendor_direct` (free disclosure)

Operator selects tracks at finding creation. System suggests defaults based on `target_kind` (chrome → suggest `chrome_vrp` + `blog_post`; linux_kernel → suggest `vendor_direct` to linux-distros + `cna` + `blog_post`).

### GA-33: Cross-track embargo coordination

**Decision:** Embargoes are tracked at the **finding** level, not the disclosure level. A finding has one canonical `earliest_public_disclosure_at` derived from the most restrictive track's embargo. Public tracks (`blog_post`, `conference_cfp`) cannot be set to `published` state until `now() >= earliest_public_disclosure_at`.

Embargo precedence (longest wins):
- Bounty programs typically 90 days
- Broker programs typically 6-12 months
- CERT/CC coordinated typically 45-90 days
- Academic papers typically 12 months (publication cycle)

Computed per-finding:
```python
@property
def earliest_public_disclosure_at(self) -> datetime:
    return max(
        disclosure.embargo_until
        for disclosure in self.disclosures
        if disclosure.embargo_until is not None
    )
```

Public tracks check this on every state transition attempt. Override requires operator confirmation + audit-log entry.

### GA-34: Working PoC vs sanitized PoC vs no-PoC

**Decision:** Three artifact tiers per finding. Tracks declare which tier they accept.

| Tier | Audience | Content | Storage |
|---|---|---|---|
| `working_poc` | Bounty/broker submission only | Full exploitation chain, works on shipping versions | Encrypted at rest, access-logged, never published |
| `sanitized_poc` | Public writeup | Demonstrates bug, will NOT yield code execution; primitives removed or instrumented | Plain storage; suitable for blog post |
| `no_poc` | Coordination / CNA / vendor-direct | Description only, optionally with disassembly/source pointers | Plain storage |

Tracks declare requirement:
- `chrome_vrp`: requires `working_poc`
- `cert_cc`: accepts `no_poc` for initial submission; vendor may request `working_poc` privately
- `blog_post`: requires `sanitized_poc` minimum; never publishes `working_poc`
- `conference_cfp`: requires `sanitized_poc` for the talk artifact; `working_poc` reserved for vendor pre-disclosure

System validates at submission render time: missing required artifact → submission blocked with operator-facing error.

### GA-35: Public writeup as a first-class artifact

**Decision:** `blog_post` track produces a structured `PublicWriteup` artifact (Markdown + frontmatter). Operator publishes to their own platform (Hugo blog, Medium, Mastodon, etc.) — system does not host or publish, but renders and validates.

`PublicWriteup` Pydantic schema:

```python
class PublicWriteup(BaseModel):
    finding_id: str
    title: str                              # "How I found CVE-2026-XXXXX in V8 Map Inference"
    publication_date: date | None           # set when operator publishes
    venue: str | None                       # "personal blog" | "phrack" | "googleprojectzero.blogspot.com"
    markdown: str                           # full body
    frontmatter: dict[str, Any]             # Hugo/Jekyll/etc. headers
    sanitized_poc_path: str | None          # link to sanitized PoC artifact
    embargo_check_passed: bool              # gate: True only if past earliest_public_disclosure_at
    related_disclosures: list[str]          # IDs of bounty submissions, CVE, advisories to cross-link
    attribution: list[Attribution]          # researcher names + handles
    technical_sections: list[TechnicalSection]   # ordered: background, finding, exploitation, mitigation
    timeline_section: TimelineSection       # required: discovery → vendor contact → patch → disclosure
    artifacts_section: list[ArtifactRef]    # CFG diagrams, decompiled excerpts, taint traces (from D-44)
    
    def render(self, theme: WriteupTheme = "minimal") -> str:
        """Render to final Markdown with embedded artifacts."""
```

The reasoning engine drafts `technical_sections` automatically from the investigation's evidence graph (D-44 typed payloads → Markdown). Operator edits and approves before publish.

**Audition angle**: the writeup carries attribution and links back to bounty awards / CVEs. Building portfolio: every finding produces a writeup ready to deploy when embargo lifts. The operator's blog accumulates these as credibility artifacts.

### GA-36: Vendor communications log

**Decision:** Every back-and-forth with a vendor is recorded in `vr_disclosure_communications`. Operator pastes email contents OR forwards via a webhook OR connects an IMAP folder. System parses, classifies, updates state.

```python
class DisclosureCommunication(BaseModel):
    id: str
    disclosure_id: str
    direction: Literal["outbound", "inbound"]
    medium: Literal["email", "form_submission", "phone_call", "in_person", "platform_message"]
    occurred_at: datetime
    summary: str                            # operator-supplied or LLM-extracted
    raw_content: str | None                 # full text if available
    raw_content_uri: str | None             # if too large for DB
    extracted_actions: list[str]            # LLM-extracted: "vendor requests more details by Y/M/D"
    triggers_state_transition: str | None   # "acknowledged" | "triaged" | etc.
    reminder_set_for: datetime | None       # follow-up reminder if no vendor response
```

ARQ task `disclosure_communication_classifier` runs after each new communication: LLM extracts state-relevant info, updates `vr_disclosures.status` if a transition is implied, sets reminder if applicable.

Built-in reminder rules:
- No vendor response within 14 days → operator nudge
- Embargo ending in 14 days → operator alert
- Patch released but disclosure not updated → operator alert
- Bounty awarded but no payment recorded after 30 days → operator alert

### GA-37: Bounty estimation and tracking

**Decision:** Per-program bounty tables in `data/bounty_tables/`. Estimator runs at finding creation; updates as severity/impact firms up. Tracks estimated vs actual.

Example `data/bounty_tables/chrome_vrp.json`:

```json
{
  "program": "chrome_vrp",
  "as_of_date": "2026-01-01",
  "source": "https://bughunters.google.com/about/rules/chrome-friends",
  "tiers": {
    "sandbox_escape": {
      "base_range_usd": [25000, 75000],
      "patch_bonus_multiplier_max": 1.5,
      "high_quality_report_multiplier_max": 1.5
    },
    "renderer_rce_with_persistence": {
      "base_range_usd": [10000, 30000]
    },
    "uxss": {
      "base_range_usd": [3000, 8000]
    }
  },
  "bonuses": {
    "early_root_cause_analysis": 1.5,
    "high_quality_writeup": 1.5,
    "fuzzer_or_test_case_contribution": 500
  }
}
```

Estimator computes range; operator can override with notes. Actuals recorded when payment notification arrives.

Aggregate views:
- Per-finding: estimated, actual, delta, notes
- Per-program: total estimated YTD, total actual YTD, response time stats, payment lag
- Per-researcher: pipeline value, realized revenue
- Tax-relevant export: CSV of payment dates + amounts + program (operator handles tax filing)

### GA-38: Coordinated multi-vendor disclosure

**Decision:** `cert_cc` track owns multi-vendor coordination. Per-vendor sub-disclosures hang off the CERT coordination record. State of the parent CERT/CC track is the rollup of vendor states.

```python
class CoordinatedDisclosure(BaseModel):
    """Parent record when a finding affects multiple vendors."""
    
    id: str
    finding_id: str
    coordinator_track_id: str               # usually "cert_cc"
    coordination_case_id: str               # CERT/CC VU# or JPCERT JVN#
    vendors: list[VendorCoordination]
    proposed_embargo_until: datetime
    actual_embargo_until: datetime | None
    
class VendorCoordination(BaseModel):
    vendor_name: str
    vendor_psirt_contact: str
    sub_disclosure_id: str                  # vr_disclosures row
    notified_at: datetime | None
    acknowledged_at: datetime | None
    patch_committed_at: datetime | None
    patch_released_at: datetime | None
    advisory_url: str | None
```

Engine produces a multi-vendor finding when `CrashTriageReport` or `DirectFinding` evidence chains identify shared root cause across distinct codebases (e.g., a vulnerable library used by 5 products).

### GA-39: CVE assignment workflow

**Decision:** Two CVE acquisition paths: vendor-provided (track records what vendor assigned) and CNA-direct (operator requests via system). Default depends on track:

| Track | CVE source |
|---|---|
| `chrome_vrp` | Vendor (Google) assigns; system records assigned CVE |
| `mozilla_bb` | Vendor (Mozilla) assigns |
| `msrc` | Vendor (Microsoft) assigns |
| `apple_security` | Vendor (Apple) assigns |
| `zdi` | ZDI requests on researcher's behalf |
| `cert_cc` | CERT/CC requests |
| `vendor_direct` (project without CNA) | System assists: request via MITRE web form OR via GitHub Security Advisory CNA path |
| `cna_github_gsa` | Direct: draft Advisory in target repo's Security tab; CVE auto-assigned by GitHub |

For the CNA paths, system renders a CVE request form (`data/disclosure_templates/cve_request_mitre.md.j2` and `cve_request_ghsa.md.j2`) prefilled from finding evidence. Operator submits; CVE arrival recorded.

### GA-40: Academic publication path

**Decision:** `conference_cfp` track produces talk abstracts and paper outlines. Embargo is the deciding factor — academic timelines are slow (12 months venue submission to publication), so the academic track usually starts before disclosure resolution.

`AcademicSubmission` artifact:
- Talk abstract (250 words, conference template)
- Paper outline (sections: abstract, introduction, background, finding, technique, evaluation, related work, conclusion)
- Evaluation requirements (system tracks what experiments need to run for the paper to hold up)
- Submission venue + deadline tracking
- Co-author attribution chain

System does NOT auto-write the paper. Drafts the talk abstract, suggests venues based on topic/findings, tracks deadlines, reminds operator. Paper writing remains a human task.

---

## File Layout

Building on existing v0.3 reasoning + fuzzing structure:

```
src/aila/modules/vr/
├── ... (existing files unchanged) ...
├── disclosure/                            # NEW v0.3 subpackage
│   ├── __init__.py
│   ├── contracts/
│   │   ├── __init__.py
│   │   ├── track.py                       # DisclosureTrack protocol + TrackKind
│   │   ├── disclosure.py                  # VRDisclosure (one per track per finding)
│   │   ├── artifact.py                    # PocArtifact, WriteupArtifact, EvidenceArtifact
│   │   ├── communication.py               # DisclosureCommunication
│   │   ├── bounty.py                      # BountyEstimate, BountyPayment
│   │   ├── coordination.py                # CoordinatedDisclosure, VendorCoordination
│   │   ├── writeup.py                     # PublicWriteup, AcademicSubmission
│   │   └── embargo.py                     # EmbargoPolicy, embargo math
│   ├── tracks/                            # Per-track implementations
│   │   ├── __init__.py                    # track registry
│   │   ├── base.py                        # BaseDisclosureTrack helpers
│   │   ├── chrome_vrp.py
│   │   ├── mozilla_bb.py
│   │   ├── apple_security.py
│   │   ├── msrc.py
│   │   ├── github_bb.py
│   │   ├── zdi.py
│   │   ├── cert_cc.py
│   │   ├── cisa_kev.py
│   │   ├── vendor_direct.py
│   │   ├── cna_github_gsa.py
│   │   ├── blog_post.py
│   │   └── conference_cfp.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── disclosure_orchestrator.py     # finding → tracks routing
│   │   ├── embargo_calculator.py          # cross-track embargo math (GA-33)
│   │   ├── artifact_renderer.py           # PoC sanitization, writeup rendering
│   │   ├── communication_classifier.py    # GA-36 inbound parsing
│   │   ├── bounty_estimator.py            # GA-37 calculator
│   │   ├── cve_requester.py               # GA-39 MITRE/GHSA path
│   │   ├── reminder_scheduler.py          # ARQ-backed nudges
│   │   └── poc_sanitizer.py               # working → sanitized PoC transform
│   ├── workers/
│   │   ├── __init__.py
│   │   ├── communication_classifier_worker.py
│   │   ├── reminder_worker.py
│   │   ├── embargo_watch_worker.py        # nightly: alerts on embargoes ending soon
│   │   ├── bounty_payment_watch_worker.py
│   │   └── writeup_renderer_worker.py
│   ├── workflow/
│   │   ├── __init__.py
│   │   ├── definitions.py                 # VR_DISCLOSURE_V1 (per track)
│   │   ├── services.py
│   │   └── states/
│   │       ├── disclosure_draft.py        # render submission, gather artifacts
│   │       ├── disclosure_submit.py       # operator submits OR auto-submit (some tracks)
│   │       ├── disclosure_track.py        # state machine progression
│   │       └── disclosure_close.py        # terminal: published / bounty / closed
│   ├── data/
│   │   ├── disclosure_tracks/             # GA-31 YAML configs (one per track)
│   │   │   ├── chrome_vrp.yaml
│   │   │   ├── mozilla_bb.yaml
│   │   │   └── ... (12 tracks)
│   │   ├── disclosure_templates/          # Jinja2 submission templates
│   │   │   ├── chrome_vrp.md.j2
│   │   │   ├── mozilla_bb.md.j2
│   │   │   ├── vendor_direct.md.j2
│   │   │   ├── blog_post.md.j2            # Markdown with frontmatter
│   │   │   ├── conference_abstract.md.j2
│   │   │   ├── cve_request_mitre.md.j2
│   │   │   └── cve_request_ghsa.md.j2
│   │   ├── bounty_tables/                 # GA-37 per-program bounty data
│   │   │   ├── chrome_vrp.json
│   │   │   ├── mozilla_bb.json
│   │   │   ├── msrc.json
│   │   │   ├── apple_security.json
│   │   │   └── ... (per program)
│   │   ├── writeup_themes/                # GA-35 Markdown/Hugo themes
│   │   │   ├── minimal.j2
│   │   │   ├── google_p0_style.j2
│   │   │   └── phrack_style.j2
│   │   └── reminder_rules.json            # GA-36 nudge schedule
│   └── api_router.py
├── db_models/
│   ├── disclosure.py                      # VRDisclosureRecord + child records
│   └── coordination.py                    # CoordinatedDisclosureRecord
└── alembic/versions/
    └── 031_vr_disclosure_tables.py
```

---

## DB Schema (additions)

### vr_disclosures
```sql
CREATE TABLE vr_disclosures (
    id                          TEXT PRIMARY KEY,
    finding_id                  TEXT NOT NULL REFERENCES vr_findings(id),
    team_id                     TEXT,
    track_id                    TEXT NOT NULL,    -- 'chrome_vrp' | 'blog_post' | etc.
    track_kind                  TEXT NOT NULL,    -- 'bounty' | 'broker' | 'coordination' | 'vendor_direct' | 'cna' | 'public' | 'academic'
    status                      TEXT NOT NULL DEFAULT 'draft',
                                                  -- draft|ready|submitted|acknowledged|triaged|confirmed
                                                  -- |fix_pending|patched|published|bounty_awarded|closed
                                                  -- |rejected|duplicate|withdrawn
    submission_url              TEXT,             -- bug tracker URL once submitted
    submission_id_external      TEXT,             -- vendor-side ID (Bugzilla #, MSRC #, etc.)
    assigned_cve_id             TEXT,
    severity_self_rating        TEXT,             -- format depends on schema
    severity_vendor_rating      TEXT,
    embargo_until               TIMESTAMPTZ,
    reminders_paused_until      TIMESTAMPTZ,
    submission_artifact_uri     TEXT,             -- rendered Markdown/HTML in object storage
    submission_artifact_sha256  TEXT,
    bounty_estimate_low_usd     INTEGER,
    bounty_estimate_high_usd    INTEGER,
    bounty_actual_usd           INTEGER,
    bounty_paid_at              TIMESTAMPTZ,
    notes                       TEXT,
    submitted_at                TIMESTAMPTZ,
    acknowledged_at             TIMESTAMPTZ,
    confirmed_at                TIMESTAMPTZ,
    patched_at                  TIMESTAMPTZ,
    published_at                TIMESTAMPTZ,
    closed_at                   TIMESTAMPTZ,
    closure_reason              TEXT,
    created_at                  TIMESTAMPTZ NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_disclosure_finding ON vr_disclosures (finding_id);
CREATE INDEX idx_disclosure_team_status ON vr_disclosures (team_id, status);
CREATE INDEX idx_disclosure_embargo_watch ON vr_disclosures (embargo_until) WHERE status NOT IN ('published', 'closed', 'withdrawn');
```

### vr_disclosure_artifacts
```sql
CREATE TABLE vr_disclosure_artifacts (
    id                  TEXT PRIMARY KEY,
    disclosure_id       TEXT NOT NULL REFERENCES vr_disclosures(id),
    finding_id          TEXT NOT NULL REFERENCES vr_findings(id),  -- denormalized for FK fanout
    artifact_kind       TEXT NOT NULL,    -- 'working_poc' | 'sanitized_poc' | 'writeup' | 'crash_report'
                                          -- | 'severity_assessment' | 'reproducer_instructions'
                                          -- | 'academic_outline' | 'talk_abstract' | 'cve_request'
    storage_tier        TEXT NOT NULL,    -- 'encrypted' (working_poc) | 'plain'
    storage_uri         TEXT NOT NULL,    -- s3://aila-vr/disclosures/<id>/<artifact_id>.<ext>
    storage_sha256      TEXT NOT NULL,
    size_bytes          BIGINT NOT NULL,
    rendered_from_template TEXT,          -- which Jinja2 template produced this
    sanitized_from_artifact_id TEXT REFERENCES vr_disclosure_artifacts(id),  -- if this is a sanitized version
    operator_approved   BOOLEAN NOT NULL DEFAULT false,
    operator_approved_at TIMESTAMPTZ,
    operator_approved_by TEXT,
    notes               TEXT,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_artifact_disclosure ON vr_disclosure_artifacts (disclosure_id);
CREATE INDEX idx_artifact_finding ON vr_disclosure_artifacts (finding_id);
```

### vr_disclosure_communications
```sql
CREATE TABLE vr_disclosure_communications (
    id                  TEXT PRIMARY KEY,
    disclosure_id       TEXT NOT NULL REFERENCES vr_disclosures(id),
    direction           TEXT NOT NULL,    -- outbound | inbound
    medium              TEXT NOT NULL,    -- email | form_submission | phone_call | in_person | platform_message
    occurred_at         TIMESTAMPTZ NOT NULL,
    counterparty        TEXT,             -- email address, person name, platform handle
    summary             TEXT NOT NULL,
    raw_content         TEXT,
    raw_content_uri     TEXT,             -- if too large for DB
    extracted_actions_json TEXT DEFAULT '[]',
    triggers_transition TEXT,             -- which state transition this implied
    classification_confidence TEXT,       -- exact|strong|medium|caveated|unknown
    reminder_set_for    TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_comm_disclosure_time ON vr_disclosure_communications (disclosure_id, occurred_at DESC);
CREATE INDEX idx_comm_reminder_watch ON vr_disclosure_communications (reminder_set_for) WHERE reminder_set_for IS NOT NULL;
```

### vr_coordinated_disclosures
```sql
CREATE TABLE vr_coordinated_disclosures (
    id                          TEXT PRIMARY KEY,
    finding_id                  TEXT NOT NULL REFERENCES vr_findings(id),
    coordinator_disclosure_id   TEXT NOT NULL REFERENCES vr_disclosures(id),
    coordination_case_id        TEXT,             -- VU# / JVN#
    proposed_embargo_until      TIMESTAMPTZ,
    actual_embargo_until        TIMESTAMPTZ,
    status                      TEXT NOT NULL DEFAULT 'opened',
                                                  -- opened|vendors_notified|patches_pending|coordinated_release|closed
    closed_at                   TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL
);

CREATE TABLE vr_vendor_coordinations (
    id                              TEXT PRIMARY KEY,
    coordinated_disclosure_id       TEXT NOT NULL REFERENCES vr_coordinated_disclosures(id),
    vendor_name                     TEXT NOT NULL,
    vendor_psirt_contact            TEXT,
    sub_disclosure_id               TEXT REFERENCES vr_disclosures(id),  -- per-vendor disclosure if separate
    notified_at                     TIMESTAMPTZ,
    acknowledged_at                 TIMESTAMPTZ,
    patch_committed_at              TIMESTAMPTZ,
    patch_released_at               TIMESTAMPTZ,
    advisory_url                    TEXT,
    notes                           TEXT
);
CREATE INDEX idx_vendor_coord ON vr_vendor_coordinations (coordinated_disclosure_id);
```

Alembic migration: `src/aila/alembic/versions/031_vr_disclosure_tables.py`

---

## Workflow: VR_DISCLOSURE_V1

One workflow definition; per-track behavior driven by the `DisclosureTrack` implementation.

```
disclosure_draft -> disclosure_submit -> disclosure_track -> disclosure_close -> __succeeded__
                                              |
                                              v
                              (long-running; loops back to itself
                               on each state transition trigger)
```

### State: disclosure_draft (timeout: 600s)
1. Load track config from YAML
2. Validate finding has required evidence
3. Auto-sanitize PoC if track needs `sanitized_poc` and only `working_poc` exists
4. Render submission template via Jinja2 with finding + artifacts as context
5. Upload rendered artifact to object storage
6. Compute SHA256
7. Set status to `ready`
8. Notify operator: "Disclosure for <track> ready for review"

**Output:** Rendered submission artifact + checklist of artifacts attached

### State: disclosure_submit (timeout: depends on track)
For tracks supporting auto-submission (`cna_github_gsa` via API, future others): system submits, parses response, records external ID.

For manual tracks (most bounty/vendor-direct): operator marks as submitted, provides external URL/ID, system transitions to `submitted` and starts reminder schedule.

**Output:** `submission_url`, `submission_id_external`, `submitted_at` populated

### State: disclosure_track (long-running)
This is the bulk of the lifecycle. State transitions driven by:
- Inbound `DisclosureCommunication` records (parsed by classifier worker)
- Operator manual updates (status change via UI)
- Automated reminders (no response after N days → operator nudge)
- Embargo events (embargo ending → operator alert)
- Cross-track events (sibling disclosure transitions can trigger this one)

Transitions emitted by classifier worker auto-update status. Operator can override.

**Output:** Eventually one of: `published` (public tracks) / `bounty_awarded` (bounty/broker) / `closed` (everything else)

### State: disclosure_close (timeout: 60s)
1. Final status persisted
2. Bounty payment recorded (if applicable)
3. Cross-disclosure notifications: if this was the last open track for a finding, mark finding as `fully_disclosed`
4. Public writeup (if `blog_post`) auto-renders final version with all timeline data

**Output:** Final closed disclosure

---

## API Endpoints (additions)

```
POST   /api/vr/findings/<id>/disclosures              create disclosures for finding (one or many tracks)
GET    /api/vr/findings/<id>/disclosures              list disclosures for a finding
GET    /api/vr/disclosures                            list all (filterable: track_id, status, embargo)
GET    /api/vr/disclosures/<id>                       full disclosure details
PATCH  /api/vr/disclosures/<id>                       update status, embargo, notes (operator override)
POST   /api/vr/disclosures/<id>/submit                mark submitted (provides URL/ID)
POST   /api/vr/disclosures/<id>/withdraw              operator-initiated close

GET    /api/vr/disclosures/<id>/artifacts             list artifacts (with download links)
POST   /api/vr/disclosures/<id>/artifacts             upload custom artifact OR trigger re-render
GET    /api/vr/disclosures/<id>/artifacts/<aid>/download  signed download (encrypted artifacts gated)

POST   /api/vr/disclosures/<id>/communications        log inbound/outbound communication
GET    /api/vr/disclosures/<id>/communications        timeline of all communications

POST   /api/vr/disclosures/<id>/render_submission     re-render submission template
POST   /api/vr/disclosures/<id>/sanitize_poc          generate sanitized PoC from working PoC
POST   /api/vr/disclosures/<id>/render_writeup        regenerate public writeup (blog_post only)

GET    /api/vr/disclosures/tracks                     list available tracks + config
GET    /api/vr/disclosures/tracks/<track_id>/template view raw Jinja2 template
GET    /api/vr/disclosures/tracks/<track_id>/bounty_table  see bounty estimation table

POST   /api/vr/findings/<id>/coordination             create coordinated disclosure
GET    /api/vr/findings/<id>/coordination             coordinated disclosure status
PATCH  /api/vr/findings/<id>/coordination/<vendor_id> update vendor status

GET    /api/vr/dashboard/disclosures                  ops dashboard: open disclosures, deadlines, embargoes
GET    /api/vr/dashboard/bounties                     bounty pipeline + realized YTD
GET    /api/vr/dashboard/reminders                    upcoming reminders + alerts
```

---

## Build Order (Milestones)

### Milestone M3.D-1: Foundation
**Goal:** Data layer + track plugin protocol.

| # | File | LOC | Depends on |
|---|---|---|---|
| 1.1 | `disclosure/contracts/track.py` | 120 | — |
| 1.2 | `disclosure/contracts/disclosure.py` | 120 | — |
| 1.3 | `disclosure/contracts/artifact.py` | 100 | — |
| 1.4 | `disclosure/contracts/communication.py` | 80 | — |
| 1.5 | `disclosure/contracts/bounty.py` | 80 | — |
| 1.6 | `disclosure/contracts/coordination.py` | 100 | — |
| 1.7 | `disclosure/contracts/writeup.py` | 200 | — |
| 1.8 | `disclosure/contracts/embargo.py` | 80 | — |
| 1.9 | `db_models/disclosure.py` | 250 | 1.x |
| 1.10 | `db_models/coordination.py` | 100 | 1.6 |
| 1.11 | `alembic/versions/031_vr_disclosure_tables.py` | 200 | 1.9, 1.10 |
| 1.12 | `disclosure/tracks/base.py` | 150 | 1.1 |

**Exit:** Migrations apply. Track registry loadable. Pydantic models round-trip.

### Milestone M3.D-2: Embargo + artifact rendering
**Goal:** Cross-track embargo math + artifact rendering pipeline.

| # | File | LOC | Depends on |
|---|---|---|---|
| 2.1 | `disclosure/services/embargo_calculator.py` | 150 | 1.8 |
| 2.2 | `disclosure/services/artifact_renderer.py` | 250 | 1.3, Jinja2 |
| 2.3 | `disclosure/services/poc_sanitizer.py` | 200 | 1.3 |
| 2.4 | `disclosure/data/disclosure_templates/blog_post.md.j2` | 150 | — |
| 2.5 | `disclosure/data/disclosure_templates/vendor_direct.md.j2` | 80 | — |
| 2.6 | `disclosure/data/writeup_themes/minimal.j2` | 100 | — |

**Exit:** Render a finding through blog_post template → get publishable Markdown. Render through vendor_direct → get email-ready text. Embargo calculator correctly picks longest among 3 tracks.

### Milestone M3.D-3: First 5 tracks (bounty programs)
**Goal:** Most common bounty programs working end-to-end.

| # | File | LOC | Depends on |
|---|---|---|---|
| 3.1 | `disclosure/tracks/chrome_vrp.py` | 180 | 1.12 |
| 3.2 | `disclosure/tracks/mozilla_bb.py` | 140 | 1.12 |
| 3.3 | `disclosure/tracks/apple_security.py` | 130 | 1.12 |
| 3.4 | `disclosure/tracks/msrc.py` | 150 | 1.12 |
| 3.5 | `disclosure/tracks/github_bb.py` | 130 | 1.12 |
| 3.6 | `data/disclosure_tracks/*.yaml` (5 YAML configs) | 250 | — |
| 3.7 | `data/disclosure_templates/chrome_vrp.md.j2` | 100 | — |
| 3.8 | `data/disclosure_templates/mozilla_bb.md.j2` | 90 | — |
| 3.9 | `data/disclosure_templates/apple_security.md.j2` | 90 | — |
| 3.10 | `data/disclosure_templates/msrc.md.j2` | 100 | — |
| 3.11 | `data/disclosure_templates/github_bb.md.j2` | 80 | — |
| 3.12 | `data/bounty_tables/*.json` (5 program tables) | 200 | — |
| 3.13 | `disclosure/services/bounty_estimator.py` | 200 | 1.5 |

**Exit:** Operator routes a finding to chrome_vrp → submission Markdown rendered → bounty estimate $25K-$75K shown. Same for other 4 programs.

### Milestone M3.D-4: Public writeup + academic + CNA tracks
**Goal:** Public-facing outputs (blog post, talk, CVE assignment).

| # | File | LOC | Depends on |
|---|---|---|---|
| 4.1 | `disclosure/tracks/blog_post.py` | 200 | 1.12, 2.2 |
| 4.2 | `disclosure/tracks/conference_cfp.py` | 180 | 1.12 |
| 4.3 | `disclosure/tracks/cna_github_gsa.py` | 200 | 1.12 |
| 4.4 | `data/disclosure_templates/conference_abstract.md.j2` | 60 | — |
| 4.5 | `data/disclosure_templates/cve_request_mitre.md.j2` | 80 | — |
| 4.6 | `data/disclosure_templates/cve_request_ghsa.md.j2` | 80 | — |
| 4.7 | `disclosure/services/cve_requester.py` | 200 | 4.3 |
| 4.8 | `data/writeup_themes/google_p0_style.j2` | 150 | — |
| 4.9 | `data/writeup_themes/phrack_style.j2` | 150 | — |

**Exit:** Operator generates a blog_post writeup for a fix-completed finding → embargo passes → Markdown ready for publish. CVE request for GHSA renders. Conference abstract drafts for finding.

### Milestone M3.D-5: Coordination + remaining tracks
**Goal:** CERT/CC coordination + vendor-direct + remaining specialty tracks.

| # | File | LOC | Depends on |
|---|---|---|---|
| 5.1 | `disclosure/tracks/cert_cc.py` | 250 | 1.12 |
| 5.2 | `disclosure/tracks/cisa_kev.py` | 100 | 1.12 |
| 5.3 | `disclosure/tracks/vendor_direct.py` | 200 | 1.12 |
| 5.4 | `disclosure/tracks/zdi.py` | 150 | 1.12 |
| 5.5 | `disclosure/services/disclosure_orchestrator.py` | 250 | tracks |
| 5.6 | Coordinated disclosure API endpoints | 200 | 5.5 |

**Exit:** Multi-vendor finding can be routed to CERT/CC + N×vendor_direct. Coordinated embargo respected. ZDI broker submission renders.

### Milestone M3.D-6: Communications + reminders
**Goal:** Inbound classification + outbound reminders.

| # | File | LOC | Depends on |
|---|---|---|---|
| 6.1 | `disclosure/services/communication_classifier.py` | 250 | 1.4 |
| 6.2 | `disclosure/workers/communication_classifier_worker.py` | 100 | 6.1 |
| 6.3 | `disclosure/services/reminder_scheduler.py` | 200 | 1.4 |
| 6.4 | `disclosure/workers/reminder_worker.py` | 120 | 6.3 |
| 6.5 | `disclosure/workers/embargo_watch_worker.py` | 100 | 2.1 |
| 6.6 | `disclosure/workers/bounty_payment_watch_worker.py` | 80 | 1.5 |
| 6.7 | `data/reminder_rules.json` | 60 | — |

**Exit:** Operator pastes vendor email → classifier extracts state transition → status updates automatically. Reminders fire on schedule. Embargo alerts surface 14 days before deadline.

### Milestone M3.D-7: Workflow + API
**Goal:** Disclosure as a first-class workflow.

| # | File | LOC | Depends on |
|---|---|---|---|
| 7.1 | `disclosure/workflow/services.py` | 80 | — |
| 7.2 | `disclosure/workflow/states/disclosure_draft.py` | 150 | 2.2 |
| 7.3 | `disclosure/workflow/states/disclosure_submit.py` | 100 | 5.5 |
| 7.4 | `disclosure/workflow/states/disclosure_track.py` | 200 | 6.x |
| 7.5 | `disclosure/workflow/states/disclosure_close.py` | 100 | — |
| 7.6 | `disclosure/workflow/definitions.py` (VR_DISCLOSURE_V1) | 80 | 7.2-7.5 |
| 7.7 | `disclosure/api_router.py` (full REST surface) | 500 | services |
| 7.8 | `runtime.py` updates | 30 | 7.6 |

**Exit:** Disclosure runs as workflow with audit trail. API endpoints all functional. Dashboard endpoints return summary data.

### Milestone M3.D-8: Frontend
**Goal:** Operator UI for disclosure lifecycle.

| # | File | LOC | Depends on |
|---|---|---|---|
| 8.1 | `frontend/queries.ts` disclosure queries | 100 | API |
| 8.2 | `frontend/mutations.ts` disclosure mutations | 80 | API |
| 8.3 | `frontend/screens/DisclosuresList.tsx` | 250 | 8.1 |
| 8.4 | `frontend/screens/DisclosureDetail.tsx` | 400 | 8.1 |
| 8.5 | `frontend/screens/WriteupEditor.tsx` (Monaco-based Markdown editor) | 350 | 8.1 |
| 8.6 | `frontend/screens/CoordinationDashboard.tsx` | 250 | 8.1 |
| 8.7 | `frontend/components/DisclosureTimeline.tsx` | 200 | — |
| 8.8 | `frontend/components/BountyPipelinePanel.tsx` | 200 | 8.1 |
| 8.9 | `frontend/components/EmbargoCountdown.tsx` | 80 | — |
| 8.10 | `frontend/components/CommunicationLog.tsx` | 200 | 8.4 |
| 8.11 | `frontend/components/ArtifactBrowser.tsx` | 150 | 8.4 |
| 8.12 | `frontend/spec.ts` route additions | 30 | 8.3-8.6 |

**Exit:** Operator browses disclosures, opens one, sees timeline + communications + artifacts, edits writeup, accepts/sends submission, tracks bounty pipeline.

### Milestone M3.D-9: Tests + benchmark
**Goal:** Verify lifecycle correctness.

| # | File | LOC | Depends on |
|---|---|---|---|
| 9.1 | `tests/vr/disclosure/test_contracts.py` | 150 | 1.x |
| 9.2 | `tests/vr/disclosure/test_embargo_calculator.py` | 150 | 2.1 |
| 9.3 | `tests/vr/disclosure/test_artifact_renderer.py` | 200 | 2.2 |
| 9.4 | `tests/vr/disclosure/test_poc_sanitizer.py` | 150 | 2.3 |
| 9.5 | `tests/vr/disclosure/test_communication_classifier.py` | 200 | 6.1 |
| 9.6 | `tests/vr/disclosure/test_bounty_estimator.py` | 100 | 3.13 |
| 9.7 | `tests/vr/disclosure/test_cve_requester.py` | 150 | 4.7 |
| 9.8 | `tests/vr/disclosure/scenarios/*.json` (5 scenarios) | 300 | — |
| 9.9 | `tests/vr/disclosure/test_lifecycle_benchmark.py` | 300 | M3.D-1 to M3.D-7 |

**Exit benchmarks:**
- **Scenario D-A**: Single-track Chrome VRP — finding → render → submit → vendor acknowledges → patch → bounty awarded → close. Full lifecycle in test (with mocked vendor responses).
- **Scenario D-B**: Triple-track — same finding to chrome_vrp + cna_github_gsa + blog_post. Embargo correctly held until patch + 7 days.
- **Scenario D-C**: Multi-vendor coordination — finding affects 3 vendors via CERT/CC. Per-vendor sub-disclosures track independently; parent coordination closes when all 3 patched.
- **Scenario D-D**: Withdraw scenario — disclosure submitted but operator withdraws after discovering duplicate; state transitions correctly, audit trail clean.
- **Scenario D-E**: Embargo override — operator force-publishes blog_post before embargo (with audit log entry); system records override + warns sibling tracks.

---

## Total Estimate

| Milestone | Files | LOC | Cumulative |
|---|---|---|---|
| M3.D-1 Foundation | 12 | ~1580 | 1580 |
| M3.D-2 Embargo + rendering | 6 | ~930 | 2510 |
| M3.D-3 5 bounty tracks | 13 | ~1840 | 4350 |
| M3.D-4 Public/academic/CNA | 9 | ~1300 | 5650 |
| M3.D-5 Coordination + remaining | 6 | ~1150 | 6800 |
| M3.D-6 Communications + reminders | 7 | ~910 | 7710 |
| M3.D-7 Workflow + API | 8 | ~1240 | 8950 |
| M3.D-8 Frontend | 12 | ~2290 | 11240 |
| M3.D-9 Tests + benchmark | 9 | ~1700 | 12940 |
| **Total** | **82 files** | **~13000 LOC** | |

Cross-cutting v0.3 totals now:
- v0.3 reasoning: ~14000 LOC
- v0.3 fuzzing: ~9000 LOC
- v0.3 disclosure: ~13000 LOC
- MCP fleet platform: ~1900 LOC
- MCP fleet frontend: ~700 LOC
- **Total v0.3: ~38600 LOC across ~270 files**

---

## Risks & Open Questions

### R-D1: Vendor portal API instability
Few vendors expose stable submission APIs. v0.3 auto-submission is limited to `cna_github_gsa` (REST API stable). All other tracks render submission text, operator pastes into vendor form/email. This is correct — we're not in the business of reverse-engineering vendor portals.

### R-D2: Inbound communication parsing accuracy
Classifying "we acknowledge receipt" vs "we are triaging" vs "we have rejected" from free-text vendor email is hard. Mitigation: classifier produces draft state transition; operator confirms in UI before transition applies. Confidence < strong triggers operator confirmation by default.

### R-D3: Working PoC encryption / access control
`working_poc` artifacts contain weaponized exploits. Storage at rest must be encrypted; access requires operator authentication + audit log entry. v0.3 uses application-layer envelope encryption with key in `platform_secrets`. Key rotation deferred to v0.4.

### R-D4: Sanitization correctness
Auto-sanitizing a working PoC to a public PoC is risk-prone — incomplete sanitization could leak working primitives. Mitigation: sanitization output requires explicit operator approval before use in any public artifact. Sanitization itself does conservative things (replace shellcode with NOP-equivalent, replace concrete addresses with `<REDACTED>`, etc.). Aggressive simplification stays human.

### R-D5: Bounty table staleness
Bounty programs update tiers regularly. Tables in `data/bounty_tables/` ship with `as_of_date`. UI shows the date; if stale > 6 months, banner prompts operator to refresh. v0.4 considers a periodic refresh via web scraping with operator review.

### R-D6: Cross-platform writeup theme drift
Operator's personal blog uses Hugo; conference site uses a custom template; mastodon truncates. v0.3 ships 3 themes (minimal / google_p0_style / phrack_style). Operator can supply custom Jinja2 theme via API. Per-publish theme override.

### R-D7: Coordinated disclosure scaling
CERT/CC coordinations with 20+ vendors get unwieldy. v0.3 supports up to 50 vendors per coordination. Beyond that, performance untested; recommend splitting into multiple coordinations.

---

## Out of Scope (deferred)

- **Automated email send/receive** — v0.3 operator pastes; v0.4 considers IMAP integration
- **Automated bounty negotiation** — operator handles
- **Tax tooling integration** — v0.3 exports CSV; operator runs tax software
- **Conference paper writing** — v0.3 drafts outline + abstract; paper writing is human
- **Talk slide generation** — defer to v0.5
- **Vendor PSIRT contact database** — v0.3 operator-maintained; v0.4 considers shared database
- **Multi-organization coordination** — v0.3 single-organization; multi-org shared coordination in v0.5
- **Researcher attribution chain** — v0.3 single primary researcher per finding; co-authorship tracking in v0.4
