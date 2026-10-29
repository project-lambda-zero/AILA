/**
 * Typed inline forms for forensics project-scoped mutations. Every field
 * maps 1:1 to a Pydantic model field (ConfigDict extra=forbid), so the
 * submit payload contains ONLY the declared keys with correctly typed
 * values. No JSON blobs anywhere; enums render as radios/selects, chip
 * lists render as ChipInput, numbers as NumberInput, etc.
 */
import type { JSX } from "react";
import { useState } from "react";

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "../../../api/client";
import {
  parseAnswerCandidate,
  parseDirective,
  parseInvestigationSummary,
  parseOne,
  parseRows,
  parseSolidEvidence,
  parseSuppression,
  useForensicsQuery,
} from "../../../api/forensics";
import type { Directive, ForensicsFinding, InvestigationSummary, SolidEvidence, Suppression } from "../../../api/forensics";
import {
  ChipInput,
  Field,
  FormBox,
  NumberInput,
  Radio,
  Select,
  TextArea,
  TextInput,
} from "./formControls";

/* --- Investigate: POST /forensics/projects/{pid}/investigate ---------- */

export function InvestigateForm({
  projectId,
  onClose,
  onCreated,
}: {
  projectId: string;
  onClose: () => void;
  onCreated: (investigationId: string) => void;
}): JSX.Element {
  const qc = useQueryClient();
  const [question, setQuestion] = useState("");
  const [maxAttempts, setMaxAttempts] = useState(10);
  const [err, setErr] = useState<string | null>(null);
  const m = useMutation({
    mutationFn: async (): Promise<InvestigationSummary> =>
      parseOne(
        await apiFetch<unknown>(`/forensics/projects/${projectId}/investigate`, {
          method: "POST",
          body: JSON.stringify({ question, max_attempts: maxAttempts }),
        }),
        parseInvestigationSummary,
      ),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "investigations"] });
      onCreated(res.id);
      onClose();
    },
    onError: (e: unknown) => setErr(e instanceof Error ? e.message : "request failed"),
  });
  return (
    <FormBox
      title="ask a question"
      onCancel={onClose}
      onSubmit={() => {
        if (question.trim().length === 0) {
          setErr("question is required");
          return;
        }
        setErr(null);
        m.mutate();
      }}
      submitLabel="start investigation"
      submitting={m.isPending}
      error={err}
    >
      <Field label="question" hint={"1\u20134000 chars. Frames the free-flow agent's investigation."}>
        <TextArea value={question} onChange={setQuestion} rows={5} placeholder="What executed on host X between 12:00 and 13:00 UTC?" />
      </Field>
      <Field label="max attempts" hint={"Turn budget for the agent. 1\u201350; default 10."}>
        <NumberInput value={maxAttempts} onChange={setMaxAttempts} min={1} max={50} />
      </Field>
    </FormBox>
  );
}

/* --- Directive create: POST /projects/{pid}/directives ---------------- */

export function DirectiveCreateForm({
  projectId,
  onClose,
}: {
  projectId: string;
  onClose: () => void;
}): JSX.Element {
  const qc = useQueryClient();
  const [text, setText] = useState("");
  const [investigationId, setInvestigationId] = useState<string>("");
  const [strategyFamily, setStrategyFamily] = useState("");
  const [requiredArtifact, setRequiredArtifact] = useState("");
  const [err, setErr] = useState<string | null>(null);

  // Populate the scope select from the project's investigations so the
  // analyst can pin a directive to one run instead of the whole project.
  const invQ = useForensicsQuery(projectId, ["investigations"], `/forensics/projects/${projectId}/investigations`, (raw) =>
    parseRows(raw, parseInvestigationSummary),
  );
  const invOpts = invQ.data ?? [];

  const m = useMutation({
    mutationFn: async (): Promise<Directive> => {
      const body: Record<string, unknown> = { text };
      if (investigationId) body.investigation_id = investigationId;
      if (strategyFamily.trim()) body.strategy_family = strategyFamily.trim();
      if (requiredArtifact.trim()) body.required_artifact = requiredArtifact.trim();
      return parseOne(
        await apiFetch<unknown>(`/forensics/projects/${projectId}/directives`, {
          method: "POST",
          body: JSON.stringify(body),
        }),
        parseDirective,
      );
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "directives"] });
      onClose();
    },
    onError: (e: unknown) => setErr(e instanceof Error ? e.message : "request failed"),
  });
  return (
    <FormBox
      title="new directive"
      onCancel={onClose}
      onSubmit={() => {
        const t = text.trim();
        if (t.length === 0) {
          setErr("directive text is required");
          return;
        }
        if (t.length > 4000) {
          setErr("directive text max 4000 chars");
          return;
        }
        setErr(null);
        m.mutate();
      }}
      submitLabel="create"
      submitting={m.isPending}
      error={err}
    >
      <Field label="directive" hint={"1\u20134000 chars. Standing rule the reasoning engine must honour."}>
        <TextArea value={text} onChange={setText} rows={5} placeholder="Always verify the persistence mechanism before submitting a verdict." />
      </Field>
      <Field label="scope" hint="Leave empty for project-wide. Otherwise pin to one investigation.">
        <Select
          value={investigationId}
          onChange={(v) => setInvestigationId(v)}
          options={[
            { value: "", label: "project-wide (all investigations)" },
            ...invOpts.map((i) => ({
              value: i.id,
              label: `${i.id.slice(0, 8)} \u00b7 ${i.question.slice(0, 60)}`,
            })),
          ]}
        />
      </Field>
      <Field label="strategy family" hint="Optional explicit strategy-family pin.">
        <TextInput value={strategyFamily} onChange={setStrategyFamily} placeholder="e.g. persistence_analysis" />
      </Field>
      <Field label="required artifact" hint="Optional artifact id/path the answer must cite before submission.">
        <TextInput value={requiredArtifact} onChange={setRequiredArtifact} placeholder="artifact:persistence_finding:..." />
      </Field>
    </FormBox>
  );
}

/* --- Suppress finding: POST /projects/{pid}/findings/suppress -------- */

const REASON_PRESETS = [
  "known-good",
  "legitimate-software",
  "test-artifact",
  "duplicate",
  "false-positive",
];

export function SuppressFindingForm({
  projectId,
  row,
  onClose,
}: {
  projectId: string;
  row: ForensicsFinding;
  onClose: () => void;
}): JSX.Element {
  const qc = useQueryClient();
  const [artifactType, setArtifactType] = useState<string>(row.artifact_type);
  const [executable, setExecutable] = useState<string>(row.executable ?? "");
  const [path, setPath] = useState<string>(row.path ?? "");
  const [name, setName] = useState<string>(row.name ?? "");
  const [findingUser, setFindingUser] = useState<string>(row.user ?? "");
  const [reasons, setReasons] = useState<string[]>([]);
  const [notes, setNotes] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const fingerprint = row.fingerprint;

  const m = useMutation({
    mutationFn: async (): Promise<Suppression> => {
      const body: Record<string, unknown> = { fingerprint };
      if (artifactType.trim()) body.artifact_type = artifactType.trim();
      if (executable.trim()) body.executable = executable.trim();
      if (path.trim()) body.path = path.trim();
      if (name.trim()) body.name = name.trim();
      if (findingUser.trim()) body.finding_user = findingUser.trim();
      if (reasons.length) body.reasons = reasons;
      if (notes.trim()) body.notes = notes.trim();
      return parseOne(
        await apiFetch<unknown>(`/forensics/projects/${projectId}/findings/suppress`, {
          method: "POST",
          body: JSON.stringify(body),
        }),
        parseSuppression,
      );
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "findings"] });
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "suppressions"] });
      onClose();
    },
    onError: (e: unknown) => setErr(e instanceof Error ? e.message : "request failed"),
  });

  return (
    <FormBox
      title="suppress finding as false-positive"
      onCancel={onClose}
      onSubmit={() => {
        if (!fingerprint) {
          setErr("row has no fingerprint");
          return;
        }
        if (notes.length > 4000) {
          setErr("notes max 4000 chars");
          return;
        }
        setErr(null);
        m.mutate();
      }}
      submitLabel="suppress"
      submitting={m.isPending}
      error={err}
    >
      <Field label="fingerprint" hint="Identity hash of the finding (from row).">
        <TextInput value={fingerprint} onChange={() => {}} placeholder={"\u2014"} />
      </Field>
      <Field label="artifact type"><TextInput value={artifactType} onChange={setArtifactType} /></Field>
      <Field label="executable"><TextInput value={executable} onChange={setExecutable} /></Field>
      <Field label="path"><TextInput value={path} onChange={setPath} /></Field>
      <Field label="name"><TextInput value={name} onChange={setName} /></Field>
      <Field label="finding user"><TextInput value={findingUser} onChange={setFindingUser} /></Field>
      <Field label="reasons" hint="Free-form tags. Press Enter or , to add. Presets suggested below.">
        <ChipInput values={reasons} onChange={setReasons} placeholder={"reason\u2026"} />
        <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 4 }}>
          {REASON_PRESETS.map((r) => (
            <button
              key={r}
              type="button"
              onClick={() => reasons.includes(r) || setReasons([...reasons, r])}
              style={{
                background: "transparent",
                border: "1px dashed var(--border-soft)",
                color: "var(--text-muted)",
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                padding: "1px 6px",
                borderRadius: 2,
                cursor: "pointer",
              }}
            >
              + {r}
            </button>
          ))}
        </div>
      </Field>
      <Field label="notes" hint={"\u2264 4000 chars."}>
        <TextArea value={notes} onChange={setNotes} rows={3} />
      </Field>
    </FormBox>
  );
}

/* --- Tag investigation: POST /investigations/{iid}/tag --------------- */

export function TagInvestigationForm({
  projectId,
  investigationId,
  onClose,
}: {
  projectId: string;
  investigationId: string;
  onClose: () => void;
}): JSX.Element {
  const qc = useQueryClient();
  const [verdict, setVerdict] = useState<"true" | "false">("true");
  const [answerId, setAnswerId] = useState<string>("");
  const [notes, setNotes] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const ansQ = useForensicsQuery(projectId, ["answers"], `/forensics/projects/${projectId}/answers`, (raw) =>
    parseRows(raw, parseAnswerCandidate),
  );
  const answers = (ansQ.data ?? []).filter((a) => !a.investigation_id || a.investigation_id === investigationId);

  const m = useMutation({
    mutationFn: async (): Promise<SolidEvidence> => {
      const body: Record<string, unknown> = { verdict };
      if (answerId) body.answer_id = answerId;
      if (notes.trim()) body.notes = notes.trim();
      return parseOne(
        await apiFetch<unknown>(`/forensics/projects/${projectId}/investigations/${investigationId}/tag`, {
          method: "POST",
          body: JSON.stringify(body),
        }),
        parseSolidEvidence,
      );
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "solid-evidence"] });
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "investigations"] });
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "investigation", investigationId] });
      onClose();
    },
    onError: (e: unknown) => setErr(e instanceof Error ? e.message : "request failed"),
  });

  return (
    <FormBox
      title="tag investigation as solid evidence"
      onCancel={onClose}
      onSubmit={() => {
        if (notes.length > 4000) {
          setErr("notes max 4000 chars");
          return;
        }
        setErr(null);
        m.mutate();
      }}
      submitLabel="tag"
      submitting={m.isPending}
      error={err}
    >
      <Field label="verdict" hint="true = confirmed positive; false = analyst-verified negative.">
        <Radio
          value={verdict}
          onChange={(v) => setVerdict(v)}
          options={[
            { value: "true", label: "true (positive)" },
            { value: "false", label: "false (negative)" },
          ]}
        />
      </Field>
      <Field label="bind to answer" hint="Optional. When set, the tag binds to a specific answer candidate.">
        <Select
          value={answerId}
          onChange={(v) => setAnswerId(v)}
          options={[
            { value: "", label: "use investigation final_answer" },
            ...answers.map((a) => ({
              value: a.id,
              label: `${(a.question_text || "\u2014").slice(0, 40)} \u2192 ${a.answer_text.slice(0, 40)}`,
            })),
          ]}
        />
      </Field>
      <Field label="notes" hint={"\u2264 4000 chars."}>
        <TextArea value={notes} onChange={setNotes} rows={4} />
      </Field>
    </FormBox>
  );
}

/* --- Rerun investigation: POST /investigations/{iid}/rerun ----------- */

export function RerunForm({
  projectId,
  investigationId,
  onClose,
}: {
  projectId: string;
  investigationId: string;
  onClose: () => void;
}): JSX.Element {
  const qc = useQueryClient();
  const [override, setOverride] = useState("");
  const [maxAttempts, setMaxAttempts] = useState<number>(10);
  const [useOverride, setUseOverride] = useState(false);
  const [useMax, setUseMax] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const m = useMutation({
    mutationFn: async (): Promise<InvestigationSummary> => {
      const body: Record<string, unknown> = {};
      if (useMax) body.max_attempts = maxAttempts;
      if (useOverride && override.trim()) body.question_override = override.trim();
      return parseOne(
        await apiFetch<unknown>(`/forensics/projects/${projectId}/investigations/${investigationId}/rerun`, {
          method: "POST",
          body: JSON.stringify(body),
        }),
        parseInvestigationSummary,
      );
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "investigations"] });
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "investigation", investigationId] });
      onClose();
    },
    onError: (e: unknown) => setErr(e instanceof Error ? e.message : "request failed"),
  });
  return (
    <FormBox
      title="rerun investigation"
      onCancel={onClose}
      onSubmit={() => {
        setErr(null);
        m.mutate();
      }}
      submitLabel="rerun"
      submitting={m.isPending}
      error={err}
    >
      <Field label="question override" hint="Optional. Leave off to reuse the original question.">
        <label style={{ display: "inline-flex", gap: 8, alignItems: "center", fontFamily: "var(--font-mono)", fontSize: 11 }}>
          <input type="checkbox" checked={useOverride} onChange={(e) => setUseOverride(e.target.checked)} />
          override question
        </label>
        {useOverride ? <TextArea value={override} onChange={setOverride} rows={4} /> : null}
      </Field>
      <Field label="max attempts" hint="Optional. Overrides the original attempt budget.">
        <label style={{ display: "inline-flex", gap: 8, alignItems: "center", fontFamily: "var(--font-mono)", fontSize: 11 }}>
          <input type="checkbox" checked={useMax} onChange={(e) => setUseMax(e.target.checked)} />
          override max attempts
        </label>
        {useMax ? <NumberInput value={maxAttempts} onChange={setMaxAttempts} min={1} max={50} /> : null}
      </Field>
    </FormBox>
  );
}
