/** Prompt alias console over /admin/prompts/aliases (god-tier admin): inspect
 * the alias pointers for a prompt key, repoint an alias at a registered
 * version (deploy / rollback), and diff the bodies of any two registered
 * versions line by line. */
import { useState } from "react";
import type { JSX } from "react";

import { usePromptAliases, usePromptBody, usePromptKeys, usePromptVersions, useSetPromptAlias } from "../../../api/admin";
import type { PromptVersion } from "../../../api/admin";
import type { ModulePageProps } from "../../contract";
import { css } from "../../css";
import { toast } from "../../toast";
import { ActButton, actionRow, fieldStyle } from "../xray/actions";
import { AdminWindow, FAINT, Field, KvGrid, MONO, QueryState, Section, SubmitButton, Table, fmtTime } from "./kit";

/** One row of a unified line diff between two prompt bodies. */
interface DiffLine {
  kind: "same" | "add" | "del";
  text: string;
}

/** Merge two bodies into a unified diff. A simple LCS over lines keeps the
 * implementation dependency-free; prompt bodies are small (a few hundred
 * lines at most), so the quadratic cost is irrelevant here. */
function diffBodies(a: string, b: string): DiffLine[] {
  const al = a.split("\n");
  const bl = b.split("\n");
  const n = al.length;
  const m = bl.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      lcs[i][j] = al[i] === bl[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (al[i] === bl[j]) {
      out.push({ kind: "same", text: al[i] });
      i += 1;
      j += 1;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ kind: "del", text: al[i] });
      i += 1;
    } else {
      out.push({ kind: "add", text: bl[j] });
      j += 1;
    }
  }
  while (i < n) out.push({ kind: "del", text: al[i++] });
  while (j < m) out.push({ kind: "add", text: bl[j++] });
  return out;
}

const DIFF_COLORS = {
  same: "color:var(--text-muted);",
  add: "color:var(--status-ok);background:color-mix(in srgb,var(--status-ok) 8%,transparent);",
  del: "color:var(--status-warn);background:color-mix(in srgb,var(--status-warn) 8%,transparent);",
} as const satisfies Record<DiffLine["kind"], string>;

function DiffView({ a, b }: { a: string; b: string }): JSX.Element {
  const rows = diffBodies(a, b);
  const changed = rows.filter((r) => r.kind !== "same").length;
  return (
    <div style={css("display:flex;flex-direction:column;gap:4px;min-width:0;")}>
      <span style={css(FAINT + MONO + "font-size:11px;")}>
        {rows.length} lines · {changed} changed
      </span>
      <pre style={css(MONO + "font-size:11px;margin:0;padding:8px;background:var(--surface-sunk);border:1px solid var(--border-soft);overflow:auto;max-height:420px;")}>
        {rows.map((r, idx) => (
          <div key={idx} style={css(`${DIFF_COLORS[r.kind]}white-space:pre-wrap;word-break:break-word;`)}>
            {r.kind === "add" ? "+ " : r.kind === "del" ? "- " : "  "}
            {r.text}
          </div>
        ))}
      </pre>
    </div>
  );
}

export default function PromptAliasesPage(props: ModulePageProps): JSX.Element {
  const keysQ = usePromptKeys();
  const [keyDraft, setKeyDraft] = useState("");
  const [key, setKey] = useState("");

  const aliasesQ = usePromptAliases(key);
  const versionsQ = usePromptVersions(key);

  const [aliasName, setAliasName] = useState("");
  const [aliasVersion, setAliasVersion] = useState("");
  const [aliasReason, setAliasReason] = useState("");
  const setAlias = useSetPromptAlias();

  const [diffA, setDiffA] = useState("");
  const [diffB, setDiffB] = useState("");
  const bodyA = usePromptBody(key, diffA);
  const bodyB = usePromptBody(key, diffB);

  const versionOptions = (versionsQ.data ?? []).map((v) => v.version);
  const canSet = key !== "" && aliasName.trim() !== "" && aliasVersion.trim() !== "";

  const versionColumns = [
    { label: "version", cell: (v: PromptVersion) => v.version },
    { label: "author", cell: (v: PromptVersion) => v.author },
    { label: "hash", cell: (v: PromptVersion) => v.content_hash.slice(0, 12) },
    { label: "notes", cell: (v: PromptVersion) => v.notes || "—" },
    { label: "registered", cell: (v: PromptVersion) => fmtTime(v.created_at) },
  ] as const;

  return (
    <AdminWindow page={props}>
      <form
        style={actionRow}
        onSubmit={(e) => {
          e.preventDefault();
          setKey(keyDraft.trim());
          setDiffA("");
          setDiffB("");
        }}
      >
        <input
          list="alias-keys"
          value={keyDraft}
          onChange={(e) => setKeyDraft(e.target.value)}
          placeholder="prompt key"
          style={{ ...fieldStyle, width: 340 }}
        />
        <datalist id="alias-keys">
          {(keysQ.data ?? []).map((k) => (
            <option key={k.key} value={k.key} />
          ))}
        </datalist>
        <SubmitButton label="load" disabled={keyDraft.trim() === ""} />
      </form>

      {key === "" ? (
        <div style={css(FAINT + "font-size:11px;")}>Load a prompt key to inspect its aliases and versions.</div>
      ) : (
        <>
          <Section title={`aliases · ${key}`}>
            <QueryState loading={aliasesQ.isLoading} error={aliasesQ.error} empty={(aliasesQ.data ?? []).length === 0} emptyText="no aliases registered for this key" />
            {(aliasesQ.data ?? []).length > 0 ? (
              <KvGrid rows={(aliasesQ.data ?? []).map((a) => [a.alias, `v${a.version} · updated ${fmtTime(a.updated_at)}`] as const)} />
            ) : null}
          </Section>

          <Section title="set alias">
            <div style={css("display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;")}>
              <Field label="alias (e.g. production)">
                <input value={aliasName} onChange={(e) => setAliasName(e.target.value)} maxLength={32} style={fieldStyle} />
              </Field>
              <Field label="version">
                <input list="alias-versions" value={aliasVersion} onChange={(e) => setAliasVersion(e.target.value)} maxLength={32} style={fieldStyle} />
                <datalist id="alias-versions">
                  {versionOptions.map((v) => (
                    <option key={v} value={v} />
                  ))}
                </datalist>
              </Field>
              <Field label="reason">
                <input value={aliasReason} onChange={(e) => setAliasReason(e.target.value)} maxLength={4096} style={fieldStyle} />
              </Field>
            </div>
            <div style={actionRow}>
              <span style={css("flex:1;")} />
              <ActButton
                label="set alias"
                tone="accent"
                pending={setAlias.isPending}
                disabled={!canSet}
                onClick={() =>
                  setAlias.mutate(
                    { key, alias: aliasName.trim(), version: aliasVersion.trim(), reason: aliasReason },
                    {
                      onSuccess: (a) => toast.success(`alias ${a.alias} → v${a.version}`),
                      onError: (e) => toast.fail("set alias", e),
                    },
                  )
                }
              />
            </div>
          </Section>

          <Section title="versions">
            <QueryState loading={versionsQ.isLoading} error={versionsQ.error} empty={(versionsQ.data ?? []).length === 0} emptyText="no versions registered for this key" />
            {(versionsQ.data ?? []).length > 0 ? (
              <Table rows={versionsQ.data ?? []} columns={versionColumns} rowKey={(v) => v.version} />
            ) : null}
          </Section>

          <Section title="version diff">
            <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:8px;")}>
              <Field label="from version">
                <input list="alias-versions" value={diffA} onChange={(e) => setDiffA(e.target.value)} placeholder="e.g. v1" style={fieldStyle} />
              </Field>
              <Field label="to version">
                <input list="alias-versions" value={diffB} onChange={(e) => setDiffB(e.target.value)} placeholder="e.g. v2" style={fieldStyle} />
              </Field>
            </div>
            {diffA !== "" && diffB !== "" ? (
              <>
                <QueryState loading={bodyA.isLoading || bodyB.isLoading} error={bodyA.error ?? bodyB.error} empty={false} emptyText="" />
                {bodyA.data && bodyB.data ? <DiffView a={bodyA.data.body} b={bodyB.data.body} /> : null}
              </>
            ) : (
              <div style={css(FAINT + "font-size:11px;")}>Pick two registered versions to diff their bodies.</div>
            )}
          </Section>
        </>
      )}
    </AdminWindow>
  );
}
