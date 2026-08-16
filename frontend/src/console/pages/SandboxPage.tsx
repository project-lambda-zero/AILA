/**
 * SandboxPage -- bespoke admin window over the platform sandbox /
 * isolation subsystem (`aila.platform.services.sandbox`, backends
 * `nsjail` + `firecracker`).
 *
 * Four panels, honest loading / error / empty states throughout:
 *   BACKEND & HEALTH   GET  /platform/sandbox/status
 *   CONFIG EDITOR      GET  /config/platform  +  PUT /config/platform/{key}
 *                      (client-filtered to sandbox_* keys)
 *   EXEC CONSOLE       POST /platform/sandbox/exec  (mutation)
 *   RECENT EXECUTIONS  no endpoint -- honest not-implemented placeholder
 *
 * Config is not raw JSON: each of the 15 sandbox_* keys renders as a
 * labelled row with a type-aware editor. The exec form is a typed form
 * (never a JSON blob) and the SandboxResult renders as prose + chips +
 * mono blocks + StructuredValue for output_files. Follows the DataPage
 * window-chrome convention: absolute-fill body + a footer strip that
 * carries the min / fullscreen / close controls the shell wired through
 * ModulePageProps.
 */

import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent, CSSProperties, FormEvent, JSX } from "react";

import { ApiError } from "../../api/client";
import {
  useSandboxConfig,
  useSandboxExec,
  useSandboxStatus,
  useUpdateSandboxConfig,
} from "../../api/sandbox";
import type {
  SandboxConfigRow,
  SandboxResult,
  SandboxSpec,
  SandboxStatus,
} from "../../api/sandbox";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import StructuredValue from "./StructuredValue";

/* ------------------------------ constants -------------------------------- */

const H_WARN = "#ffb85f";

/** Canonical order for the 15 sandbox_* keys, so the editor always reads
 *  top-to-bottom in the operator's mental order (backend + host first,
 *  then defaults, then per-backend binaries). Anything the backend hands
 *  back that isn't in this list is appended at the bottom in stable
 *  key order so a new key added upstream is visible immediately. */
const SANDBOX_KEY_ORDER: string[] = [
  "sandbox_backend",
  "sandbox_ssh_host",
  "sandbox_ssh_user",
  "sandbox_ssh_port",
  "sandbox_default_timeout_s",
  "sandbox_max_timeout_s",
  "sandbox_allow_network",
  "sandbox_vcpu",
  "sandbox_mem_mb",
  "sandbox_output_max_bytes",
  "sandbox_nsjail_bin",
  "sandbox_firecracker_bin",
  "sandbox_jailer_bin",
  "sandbox_rootfs_path",
  "sandbox_kernel_path",
];

const SANDBOX_BACKEND_CHOICES: string[] = ["none", "nsjail", "firecracker"];

/* ------------------------------- styles ---------------------------------- */

const panelBox: CSSProperties = css(
  "min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));",
);
const panelTitle: CSSProperties = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:9.5px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
const dot: CSSProperties = css(
  "width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;",
);
const scroll: CSSProperties = css("flex:1;min-height:0;overflow:auto;");
const pad: CSSProperties = css("padding:12px 13px;");
const stack: CSSProperties = css("display:flex;flex-direction:column;gap:10px;");
const emptyNote: CSSProperties = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);
const inputStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:5px 8px;min-width:0;outline:none;",
);
const selectStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:5px 8px;min-width:0;outline:none;appearance:none;",
);
const textareaStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:6px 8px;min-width:0;outline:none;resize:vertical;min-height:60px;",
);
const labelStyle: CSSProperties = css(
  "display:flex;flex-direction:column;gap:3px;font-family:var(--font-mono);font-size:9px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);min-width:0;",
);
const btnPrimary: CSSProperties = css(
  "padding:5px 12px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);
const btnPrimaryDisabled: CSSProperties = css(
  "padding:5px 12px;border:1px solid var(--border-faint);border-radius:2px;background:transparent;color:var(--text-faint);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:not-allowed;",
);
const btnGhost: CSSProperties = css(
  "padding:4px 10px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);
const btnGhostDisabled: CSSProperties = css(
  "padding:4px 10px;border:1px solid var(--border-faint);border-radius:2px;background:transparent;color:var(--text-faint);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:not-allowed;",
);
const chip: CSSProperties = css(
  "display:inline-block;padding:1px 6px;border:1px solid var(--border-soft);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;color:var(--text-primary);background:var(--surface-sunk);word-break:break-word;",
);
const chipAccent: CSSProperties = css(
  "display:inline-block;padding:1px 6px;border:1px solid color-mix(in srgb,var(--accent) 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;color:var(--accent);background:color-mix(in srgb,var(--accent) 10%,transparent);word-break:break-word;",
);
const chipFaint: CSSProperties = css(
  "display:inline-block;padding:1px 6px;border:1px solid var(--border-faint);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;color:var(--text-faint);background:transparent;word-break:break-word;",
);
const chipOk: CSSProperties = css(
  "display:inline-block;padding:1px 6px;border:1px solid color-mix(in srgb,var(--status-ok) 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;letter-spacing:0.08em;text-transform:uppercase;color:var(--status-ok);background:color-mix(in srgb,var(--status-ok) 10%,transparent);",
);
const chipWarn: CSSProperties = css(
  `display:inline-block;padding:1px 6px;border:1px solid color-mix(in srgb,${H_WARN} 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;letter-spacing:0.08em;text-transform:uppercase;color:${H_WARN};background:color-mix(in srgb,${H_WARN} 12%,transparent);`,
);
const chipRow: CSSProperties = css(
  "display:inline-flex;flex-wrap:wrap;gap:5px;max-width:100%;align-items:center;",
);
const monoBlock: CSSProperties = css(
  "margin:0;padding:8px 10px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);font-family:var(--font-mono);font-size:10.5px;line-height:1.5;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-height:280px;overflow:auto;",
);
const kvGrid: CSSProperties = css(
  "display:grid;grid-template-columns:minmax(120px,140px) 1fr;gap:5px 12px;font-size:10.5px;font-family:var(--font-mono);color:var(--text-primary);align-content:start;",
);
const kvLabel: CSSProperties = css(
  "color:var(--text-faint);letter-spacing:0.04em;text-transform:uppercase;font-size:9px;",
);
const kvVal: CSSProperties = css("color:var(--text-primary);word-break:break-word;min-width:0;");
const twoUp: CSSProperties = css(
  "display:grid;grid-template-columns:1fr 1fr;gap:12px;min-height:0;min-width:0;",
);
const checkRow: CSSProperties = css(
  "display:grid;grid-template-columns:auto 1fr;gap:6px 10px;align-items:baseline;padding:5px 0;border-bottom:1px solid var(--border-faint);font-family:var(--font-mono);font-size:10.5px;",
);
const configRow: CSSProperties = css(
  "display:grid;grid-template-columns:minmax(180px,220px) 1fr auto;gap:8px 12px;align-items:center;padding:7px 0;border-bottom:1px solid var(--border-faint);font-family:var(--font-mono);font-size:11px;",
);
const configMeta: CSSProperties = css(
  "display:flex;flex-wrap:wrap;gap:4px;font-family:var(--font-mono);font-size:8.5px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);margin-top:2px;",
);

/* ----------------------------- helpers ---------------------------------- */

function ctlBtn(label: string, title: string, onClick: () => void): JSX.Element {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      style={css(
        "width:30px;flex:0 0 auto;display:flex;align-items:center;justify-content:center;border:0;border-left:1px solid var(--border-soft);background:transparent;color:var(--text-muted);cursor:pointer;font-family:inherit;font-size:12px;",
      )}
    >
      {label}
    </button>
  );
}

/** Sub-second durations render as ms, longer as seconds -- one glance
 *  reads either as a number an operator can compare to their timeout. */
function fmtDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return "\u2014";
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
  return `${seconds.toFixed(2)}s`;
}

/** ApiError carries the HTTP status; other Error subclasses only carry
 *  a message. Used by both the config editor and the exec console to
 *  render the same message text for every backend rejection shape. */
function apiErrMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message || `HTTP ${err.status}`;
  if (err instanceof Error) return err.message;
  return String(err);
}

/** Static string-keyed lookup of the canonical position for each
 *  sandbox_* key; keys outside the list fall through to
 *  Number.POSITIVE_INFINITY and sort by name at the tail. */
const SANDBOX_KEY_RANK: Record<string, number> = Object.fromEntries(
  SANDBOX_KEY_ORDER.map((k, i) => [k, i]),
);

/* --------------------------- BACKEND & HEALTH ---------------------------- */

function HealthPanel({ status }: { status: SandboxStatus | undefined | null }): JSX.Element | null {
  if (!status) return null;
  const backendChip = status.backend === "none" ? chipFaint : chipAccent;
  const provisionedChip = status.provisioned ? chipOk : chipWarn;
  const reachable = status.ssh_reachable;
  return (
    <div style={{ ...stack, ...pad }}>
      <div style={kvGrid}>
        <span style={kvLabel}>backend</span>
        <span style={kvVal}><span style={backendChip}>{status.backend}</span></span>
        <span style={kvLabel}>provisioned</span>
        <span style={kvVal}>
          <span style={provisionedChip}>{status.provisioned ? "ready" : "not provisioned"}</span>
        </span>
        <span style={kvLabel}>ssh host</span>
        <span style={kvVal}>
          {status.ssh_host ? <span style={chip}>{status.ssh_host}</span> : <span style={chipFaint}>unset</span>}
        </span>
        <span style={kvLabel}>ssh reachable</span>
        <span style={kvVal}>
          {reachable === null ? (
            <span style={chipFaint}>not probed</span>
          ) : reachable ? (
            <span style={chipOk}>reachable</span>
          ) : (
            <span style={chipWarn}>unreachable</span>
          )}
        </span>
      </div>

      {status.backend === "none" ? (
        <div style={css(`padding:8px 10px;border:1px solid color-mix(in srgb,${H_WARN} 55%,transparent);border-radius:2px;background:color-mix(in srgb,${H_WARN} 8%,transparent);color:${H_WARN};font-family:var(--font-mono);font-size:10.5px;`)}>
          backend not provisioned (sandbox_backend=none). set sandbox_backend
          to <code>nsjail</code> or <code>firecracker</code> in the config
          editor below to enable exec.
        </div>
      ) : null}

      <div style={css("display:flex;flex-direction:column;")}>
        <div style={css("font-family:var(--font-mono);font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);padding:0 0 4px;")}>
          checks
        </div>
        {status.checks.length === 0 ? (
          <div style={emptyNote}>no checks returned by /platform/sandbox/status.</div>
        ) : (
          status.checks.map((c, i) => (
            <div key={`${c.name}-${i}`} style={checkRow}>
              <span style={c.ok ? chipOk : chipWarn}>{c.ok ? "pass" : "fail"}</span>
              <span style={css("color:var(--text-primary);word-break:break-word;")}>
                <span style={css("color:var(--text-muted);font-weight:600;")}>{c.name}</span>
                {c.detail ? (
                  <span style={css("color:var(--text-faint);")}>
                    {"\u00a0\u2014\u00a0"}
                    {c.detail}
                  </span>
                ) : null}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function StatusPanel(): JSX.Element {
  const q = useSandboxStatus();
  return (
    <div style={panelBox}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>backend &amp; health</span>
        <span style={css("flex:1;")} />
        <button
          type="button"
          onClick={() => void q.refetch()}
          style={q.isFetching ? btnGhostDisabled : btnGhost}
          disabled={q.isFetching}
        >
          {q.isFetching ? "probing\u2026" : "re-probe"}
        </button>
      </div>
      <div style={scroll}>
        {q.isLoading && !q.data ? (
          <div style={emptyNote}>probing /platform/sandbox/status&#8230;</div>
        ) : q.isError ? (
          <div style={{ ...emptyNote, color: H_WARN }}>
            could not load /platform/sandbox/status &mdash; {apiErrMessage(q.error)}
          </div>
        ) : (
          <HealthPanel status={q.data} />
        )}
      </div>
    </div>
  );
}

/* ------------------------------ CONFIG EDITOR ---------------------------- */

function ConfigEditor(): JSX.Element {
  const q = useSandboxConfig();
  const rows = useMemo(() => {
    const data = q.data ?? [];
    return [...data].sort((a, b) => {
      const ra = SANDBOX_KEY_RANK[a.key] ?? Number.POSITIVE_INFINITY;
      const rb = SANDBOX_KEY_RANK[b.key] ?? Number.POSITIVE_INFINITY;
      if (ra !== rb) return ra - rb;
      return a.key.localeCompare(b.key);
    });
  }, [q.data]);

  return (
    <div style={panelBox}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>config editor</span>
        <span style={css("flex:1;")} />
        <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>
          platform.sandbox_* &middot; {rows.length} keys
        </span>
      </div>
      <div style={scroll}>
        {q.isLoading && !q.data ? (
          <div style={emptyNote}>loading /config/platform&#8230;</div>
        ) : q.isError ? (
          <div style={{ ...emptyNote, color: H_WARN }}>
            could not load /config/platform &mdash; {apiErrMessage(q.error)}
          </div>
        ) : rows.length === 0 ? (
          <div style={emptyNote}>no sandbox_* keys returned by the config registry.</div>
        ) : (
          <div style={pad}>
            {rows.map((row) => (
              <ConfigRowEditor key={row.key} row={row} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ConfigRowEditor({ row }: { row: SandboxConfigRow }): JSX.Element {
  const [draft, setDraft] = useState<string>(row.effective_value);
  const [dirty, setDirty] = useState<boolean>(false);
  const mut = useUpdateSandboxConfig();

  // Reset local draft when the row's effective value changes (e.g. after a
  // sibling write or a refetch). Skip when the user has an in-flight edit
  // so their typing isn't clobbered by a background refetch.
  useEffect(() => {
    if (!dirty) setDraft(row.effective_value);
  }, [row.effective_value, dirty]);

  const commit = (): void => {
    if (!dirty) return;
    mut.mutate(
      { key: row.key, body: { value: draft, value_type: row.value_type } },
      {
        onSuccess: () => setDirty(false),
      },
    );
  };

  const revert = (): void => {
    setDraft(row.effective_value);
    setDirty(false);
    mut.reset();
  };

  const sourceChip =
    row.effective_source === "env"
      ? chipWarn
      : row.effective_source === "default"
        ? chipFaint
        : chipAccent;

  return (
    <div style={configRow}>
      <div style={css("min-width:0;")}>
        <div style={css("color:var(--text-primary);word-break:break-word;")}>{row.key}</div>
        <div style={configMeta}>
          <span style={chip}>{row.value_type}</span>
          <span style={sourceChip}>src: {row.effective_source}</span>
          {row.overridden_by_env ? (
            <span style={chipWarn} title={row.env_key}>
              env override
            </span>
          ) : null}
        </div>
      </div>

      <div style={css("min-width:0;")}>
        <ConfigInput
          row={row}
          value={draft}
          onChange={(v: string) => {
            setDraft(v);
            setDirty(v !== row.effective_value);
          }}
        />
        {mut.isError ? (
          <div style={css(`color:${H_WARN};font-family:var(--font-mono);font-size:9.5px;padding:3px 0 0;`)}>
            write failed &mdash; {apiErrMessage(mut.error)}
          </div>
        ) : null}
        {row.overridden_by_env ? (
          <div style={css("color:var(--text-faint);font-family:var(--font-mono);font-size:9px;letter-spacing:0.05em;padding:3px 0 0;")}>
            written value is shadowed by env var <span style={chipFaint}>{row.env_key}</span>
          </div>
        ) : null}
      </div>

      <div style={css("display:flex;gap:4px;justify-self:end;")}>
        <button
          type="button"
          onClick={commit}
          disabled={!dirty || mut.isPending}
          style={dirty && !mut.isPending ? btnPrimary : btnPrimaryDisabled}
        >
          {mut.isPending ? "\u2026" : "save"}
        </button>
        <button
          type="button"
          onClick={revert}
          disabled={!dirty && !mut.isError}
          style={dirty || mut.isError ? btnGhost : btnGhostDisabled}
        >
          revert
        </button>
      </div>
    </div>
  );
}

function ConfigInput({
  row,
  value,
  onChange,
}: {
  row: SandboxConfigRow;
  value: string;
  onChange: (v: string) => void;
}): JSX.Element {
  // sandbox_backend is a fixed enum: never trust a free-text edit for a
  // key that only accepts three values.
  if (row.key === "sandbox_backend") {
    return (
      <select
        style={selectStyle}
        value={value}
        onChange={(e: ChangeEvent<HTMLSelectElement>) => onChange(e.target.value)}
      >
        {SANDBOX_BACKEND_CHOICES.map((choice) => (
          <option key={choice} value={choice}>
            {choice}
          </option>
        ))}
        {SANDBOX_BACKEND_CHOICES.includes(value) ? null : (
          <option key={value} value={value}>
            {value} (unknown)
          </option>
        )}
      </select>
    );
  }

  if (row.value_type === "bool") {
    const checked = value === "true" || value === "True" || value === "1";
    return (
      <label style={css("display:inline-flex;align-items:center;gap:6px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);")}>
        <input
          type="checkbox"
          checked={checked}
          onChange={(e: ChangeEvent<HTMLInputElement>) => onChange(e.target.checked ? "true" : "false")}
        />
        <span style={css("color:var(--text-faint);")}>{value}</span>
      </label>
    );
  }

  if (row.value_type === "int" || row.value_type === "float") {
    return (
      <input
        type="number"
        step={row.value_type === "float" ? "any" : 1}
        value={value}
        onChange={(e: ChangeEvent<HTMLInputElement>) => onChange(e.target.value)}
        style={{ ...inputStyle, width: "100%" }}
      />
    );
  }

  return (
    <input
      type="text"
      value={value}
      onChange={(e: ChangeEvent<HTMLInputElement>) => onChange(e.target.value)}
      style={{ ...inputStyle, width: "100%" }}
      autoComplete="off"
      spellCheck={false}
    />
  );
}

/* ------------------------------ EXEC CONSOLE ----------------------------- */

interface ExecFormState {
  argvLine: string;
  stdin: string;
  timeoutS: string;
  network: boolean;
  vcpu: string;
  memMb: string;
  workdir: string;
}

const DEFAULT_EXEC_FORM: ExecFormState = {
  argvLine: "",
  stdin: "",
  timeoutS: "30",
  network: false,
  vcpu: "1",
  memMb: "512",
  workdir: "/work",
};

/** Tokenize an argv line the way an operator expects: split on whitespace
 *  but honor single/double-quoted segments so an argument with a space in
 *  it can still be passed. Backslash escapes are intentionally NOT
 *  supported -- the operator has a stdin textarea and an env dictionary
 *  is a separate future concern; the goal here is one honest way to type
 *  a command, not a full shell parser. */
function parseArgv(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: '"' | "'" | null = null;
  for (const ch of line) {
    if (quote) {
      if (ch === quote) {
        quote = null;
        continue;
      }
      cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === " " || ch === "\t" || ch === "\n") {
      if (cur !== "") {
        out.push(cur);
        cur = "";
      }
      continue;
    }
    cur += ch;
  }
  if (cur !== "") out.push(cur);
  return out;
}

function ExecConsole(): JSX.Element {
  const [form, setForm] = useState<ExecFormState>(DEFAULT_EXEC_FORM);
  const [argvError, setArgvError] = useState<string | null>(null);
  const mut = useSandboxExec();

  const setField = <K extends keyof ExecFormState>(key: K, value: ExecFormState[K]): void => {
    setForm((f) => ({ ...f, [key]: value }));
  };

  const submit = (e: FormEvent<HTMLFormElement>): void => {
    e.preventDefault();
    const argv = parseArgv(form.argvLine);
    if (argv.length === 0) {
      setArgvError("argv is required (at least one token).");
      return;
    }
    setArgvError(null);

    const spec: SandboxSpec = {
      argv,
      timeout_s: Number(form.timeoutS) || 30,
      network: form.network,
      vcpu: Number(form.vcpu) || 1,
      mem_mb: Number(form.memMb) || 512,
      workdir: form.workdir || "/work",
    };
    if (form.stdin !== "") spec.stdin = form.stdin;

    mut.mutate(spec);
  };

  const reset = (): void => {
    setForm(DEFAULT_EXEC_FORM);
    setArgvError(null);
    mut.reset();
  };

  return (
    <div style={panelBox}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>exec console</span>
        <span style={css("flex:1;")} />
        <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>
          POST /platform/sandbox/exec &middot; 10/min
        </span>
      </div>
      <div style={{ ...scroll, ...pad, ...stack }}>
        <form onSubmit={submit} style={css("display:flex;flex-direction:column;gap:8px;")}>
          <label style={labelStyle}>
            argv
            <input
              type="text"
              value={form.argvLine}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setField("argvLine", e.target.value)}
              placeholder="/bin/echo hello 'a b c'"
              style={inputStyle}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          {argvError ? (
            <div style={css(`color:${H_WARN};font-family:var(--font-mono);font-size:9.5px;`)}>{argvError}</div>
          ) : null}

          <label style={labelStyle}>
            stdin
            <textarea
              value={form.stdin}
              onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setField("stdin", e.target.value)}
              placeholder="(optional) data piped to argv on stdin"
              style={textareaStyle}
              spellCheck={false}
            />
          </label>

          <div style={css("display:grid;grid-template-columns:repeat(4,1fr);gap:8px;")}>
            <label style={labelStyle}>
              timeout_s
              <input
                type="number"
                min={1}
                value={form.timeoutS}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setField("timeoutS", e.target.value)}
                style={inputStyle}
              />
            </label>
            <label style={labelStyle}>
              vcpu
              <input
                type="number"
                min={1}
                value={form.vcpu}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setField("vcpu", e.target.value)}
                style={inputStyle}
              />
            </label>
            <label style={labelStyle}>
              mem_mb
              <input
                type="number"
                min={1}
                value={form.memMb}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setField("memMb", e.target.value)}
                style={inputStyle}
              />
            </label>
            <label style={labelStyle}>
              workdir
              <input
                type="text"
                value={form.workdir}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setField("workdir", e.target.value)}
                style={inputStyle}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
          </div>

          <label style={css("display:inline-flex;align-items:center;gap:6px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);")}>
            <input
              type="checkbox"
              checked={form.network}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setField("network", e.target.checked)}
            />
            <span>enable network egress inside the sandbox</span>
          </label>

          <div style={css("display:flex;gap:6px;")}>
            <button type="submit" disabled={mut.isPending} style={mut.isPending ? btnPrimaryDisabled : btnPrimary}>
              {mut.isPending ? "running\u2026" : "run"}
            </button>
            <button type="button" onClick={reset} style={btnGhost}>
              reset
            </button>
          </div>
        </form>

        <ExecResultView pending={mut.isPending} error={mut.error} data={mut.data ?? null} />
      </div>
    </div>
  );
}

function ExecResultView({
  pending,
  error,
  data,
}: {
  pending: boolean;
  error: Error | null;
  data: SandboxResult | null;
}): JSX.Element {
  if (pending) {
    return <div style={emptyNote}>{"waiting on backend exec\u2026"}</div>;
  }
  if (error) {
    const status = error instanceof ApiError ? error.status : null;
    const msg = apiErrMessage(error);
    let banner: string;
    if (status === 503) {
      banner = "backend not provisioned \u2014 set sandbox_backend and configure the SSH host in the config editor above.";
    } else if (status === 502) {
      banner = "sandbox backend transport error \u2014 the SSH host or the backend binary rejected the run.";
    } else {
      banner = `request failed${status !== null ? ` (HTTP ${status})` : ""}`;
    }
    return (
      <div style={css(`padding:9px 10px;border:1px solid color-mix(in srgb,${H_WARN} 55%,transparent);border-radius:2px;background:color-mix(in srgb,${H_WARN} 8%,transparent);color:${H_WARN};font-family:var(--font-mono);font-size:10.5px;display:flex;flex-direction:column;gap:4px;`)}>
        <span style={css("font-weight:700;letter-spacing:0.06em;")}>{banner}</span>
        <span style={css("color:var(--text-faint);word-break:break-word;")}>{msg}</span>
      </div>
    );
  }
  if (!data) {
    return <div style={emptyNote}>{"no result yet \u2014 fill argv and press run."}</div>;
  }
  return (
    <div style={stack}>
      <div style={chipRow}>
        <span style={data.exit_code === 0 ? chipOk : chipWarn}>
          exit {data.exit_code === null ? "\u2014" : data.exit_code}
        </span>
        <span style={chipAccent}>{data.backend}</span>
        <span style={chip}>{fmtDuration(data.duration_s)}</span>
        {data.timed_out ? <span style={chipWarn}>timed out</span> : null}
        {data.oom ? <span style={chipWarn}>oom</span> : null}
        {data.truncated ? <span style={chipWarn}>truncated</span> : null}
      </div>

      <div style={twoUp}>
        <div style={stack}>
          <div style={css("font-family:var(--font-mono);font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
            stdout
          </div>
          {data.stdout === "" ? (
            <div style={emptyNote}>(empty)</div>
          ) : (
            <pre style={monoBlock}>{data.stdout}</pre>
          )}
        </div>
        <div style={stack}>
          <div style={css("font-family:var(--font-mono);font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
            stderr
          </div>
          {data.stderr === "" ? (
            <div style={emptyNote}>(empty)</div>
          ) : (
            <pre style={monoBlock}>{data.stderr}</pre>
          )}
        </div>
      </div>

      <div style={stack}>
        <div style={css("font-family:var(--font-mono);font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
          output files
        </div>
        {Object.keys(data.output_files).length === 0 ? (
          <div style={emptyNote}>no matches for output_globs.</div>
        ) : (
          <StructuredValue value={data.output_files} />
        )}
      </div>
    </div>
  );
}

/* ---------------------------- RECENT EXECUTIONS -------------------------- */

function RecentExecutionsPanel(): JSX.Element {
  return (
    <div style={panelBox}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>recent executions</span>
        <span style={css("flex:1;")} />
        <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>
          not persisted
        </span>
      </div>
      <div style={scroll}>
        <div style={{ ...emptyNote, textAlign: "left", padding: 16 }}>
          execution history is not persisted yet: /platform/sandbox/exec
          runs are dispatched one-shot and the SandboxResult is returned
          to the caller only. add a history table + list endpoint to
          light this panel up.
        </div>
      </div>
    </div>
  );
}

/* --------------------------------- page ---------------------------------- */

export default function SandboxPage(props: ModulePageProps): JSX.Element {
  const { onBack, onMinimize, isFullscreen, onToggleFullscreen } = props;

  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        display: "flex",
        flexDirection: "column",
        background: "transparent",
        fontFamily: "var(--font-mono)",
        color: "var(--text-primary)",
      }}
    >
      <header
        style={{
          flex: "0 0 auto",
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "8px 14px",
          background: "var(--surface-chrome)",
          borderBottom: "1px solid var(--border)",
          fontSize: 10.5,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          color: "var(--text-muted)",
        }}
      >
        <span
          style={{
            width: 9,
            height: 9,
            borderRadius: 1,
            background: "var(--accent)",
            boxShadow: "0 0 7px var(--accent)",
          }}
        />
        <span style={{ color: "var(--text-primary)", fontWeight: 700, letterSpacing: "0.16em" }}>
          admin &middot; sandbox
        </span>
        <span style={{ color: "var(--text-faint)", textTransform: "none", letterSpacing: "0.04em" }}>
          platform isolation &mdash; nsjail / firecracker over SSH
        </span>
      </header>

      <main
        style={{
          flex: 1,
          minHeight: 0,
          display: "grid",
          gridTemplateRows: "minmax(220px,34%) minmax(240px,32%) minmax(240px,34%)",
          gap: 10,
          padding: 12,
        }}
      >
        <div style={twoUp}>
          <StatusPanel />
          <ConfigEditor />
        </div>
        <ExecConsole />
        <RecentExecutionsPanel />
      </main>

      <footer
        style={{
          flex: "0 0 24px",
          height: 24,
          display: "flex",
          alignItems: "stretch",
          background: "var(--surface-chrome)",
          borderTop: "2px solid var(--border)",
          fontSize: 9.5,
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          color: "var(--text-faint)",
        }}
      >
        <span
          style={{
            display: "flex",
            alignItems: "center",
            padding: "0 11px",
            background: "var(--status-ok)",
            color: "var(--text-on-accent)",
            fontWeight: 700,
            letterSpacing: "0.14em",
          }}
        >
          admin &middot; sandbox
        </span>
        <span
          style={{
            display: "flex",
            alignItems: "center",
            padding: "0 11px",
            textTransform: "none",
            letterSpacing: "0.03em",
            color: "var(--text-muted)",
          }}
        >
          SandboxService &middot; nsjail &middot; firecracker &middot; SSH
        </span>
        <span style={{ flex: 1 }} />
        {onToggleFullscreen
          ? ctlBtn(
              isFullscreen ? "\u2921" : "\u2922",
              isFullscreen ? "exit fullscreen" : "fullscreen",
              onToggleFullscreen,
            )
          : null}
        {ctlBtn("\u2014", "minimize", onMinimize)}
        {ctlBtn("\u2715", "close", onBack)}
      </footer>
    </div>
  );
}
