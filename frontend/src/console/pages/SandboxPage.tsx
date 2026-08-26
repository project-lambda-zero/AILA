/**
 * SandboxPage -- Dedicated platform isolation & sandbox terminal window.
 *
 * Designed around an interactive terminal window backed by the platform's
 * Systems Registry (`ManagedSystemRecord` / `SystemService`) and remote
 * isolation backends (`nsjail` + `firecracker` over SSH).
 */

import { useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties, FormEvent, JSX } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

import { ApiError } from "../../api/client";
import {
  useBootstrapSandboxTooling,
  useSandboxConfig,
  useSandboxExec,
  useSandboxHistory,
  useSandboxProbe,
  useSandboxStatus,
  useUpdateSandboxConfig,
} from "../../api/sandbox";
import type {
  SandboxConfigRow,
  SandboxHistoryRow,
  SandboxResult,
  SandboxStatus,
} from "../../api/sandbox";
import { useSystems, type SystemEnriched } from "../../api/systems";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import StructuredValue from "./StructuredValue";

/* ------------------------------ constants -------------------------------- */

const H_WARN = "#ffb85f";
const H_OK = "var(--status-ok, #4ade80)";

/* ------------------------------- styles ---------------------------------- */

const topBar: CSSProperties = css(
  "flex:0 0 auto;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:8px 14px;background:var(--surface-chrome);border-bottom:1px solid var(--border);flex-wrap:wrap;",
);

const controlGroup: CSSProperties = css(
  "display:flex;align-items:center;gap:8px;flex-wrap:wrap;",
);

const selectStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:4px 8px;min-width:160px;outline:none;",
);

const btnPrimary: CSSProperties = css(
  "padding:4px 12px;border:1px solid var(--accent);border-radius:2px;background:color-mix(in srgb,var(--accent) 15%,transparent);color:var(--accent);font-family:var(--font-mono);font-size:10.5px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;",
);

const btnPrimaryDisabled: CSSProperties = css(
  "padding:4px 12px;border:1px solid var(--border-faint);border-radius:2px;background:transparent;color:var(--text-faint);font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.06em;text-transform:uppercase;cursor:not-allowed;",
);

const btnGhost: CSSProperties = css(
  "padding:4px 9px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;letter-spacing:0.04em;cursor:pointer;",
);

const btnGhostActive: CSSProperties = css(
  "padding:4px 9px;border:1px solid var(--accent);border-radius:2px;background:color-mix(in srgb,var(--accent) 12%,transparent);color:var(--accent);font-family:var(--font-mono);font-size:10px;font-weight:600;letter-spacing:0.04em;cursor:pointer;",
);

const chipOk: CSSProperties = css(
  "display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border:1px solid color-mix(in srgb,var(--status-ok,#4ade80) 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;letter-spacing:0.04em;color:var(--status-ok,#4ade80);background:color-mix(in srgb,var(--status-ok,#4ade80) 10%,transparent);",
);

const chipWarn: CSSProperties = css(
  `display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border:1px solid color-mix(in srgb,${H_WARN} 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;letter-spacing:0.04em;color:${H_WARN};background:color-mix(in srgb,${H_WARN} 10%,transparent);`,
);

const chipFaint: CSSProperties = css(
  "display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border:1px solid var(--border-faint);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;color:var(--text-faint);background:transparent;",
);

const chipAccent: CSSProperties = css(
  "display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border:1px solid color-mix(in srgb,var(--accent) 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;letter-spacing:0.04em;color:var(--accent);background:color-mix(in srgb,var(--accent) 10%,transparent);",
);

const inputStyle: CSSProperties = css(
  "flex:1;background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;padding:6px 10px;outline:none;",
);

/* ------------------------------ helpers ---------------------------------- */

function apiErrMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message || `HTTP ${err.status}`;
  if (err instanceof Error) return err.message;
  return String(err);
}

function fmtDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return "\u2014";
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
  return `${seconds.toFixed(2)}s`;
}

/* ------------------------ INTERACTIVE TERMINAL --------------------------- */

function InteractiveSandboxTerminal({
  status,
  onRunSuccess,
}: {
  status: SandboxStatus | undefined;
  onRunSuccess?: () => void;
}): JSX.Element {
  const terminalElRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  const [commandInput, setCommandInput] = useState<string>("");
  const [networkEgress, setNetworkEgress] = useState<boolean>(false);
  const [timeoutS, setTimeoutS] = useState<number>(30);
  const execMut = useSandboxExec();

  useEffect(() => {
    if (!terminalElRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: "var(--font-mono, 'Spline Sans Mono', monospace)",
      fontSize: 12,
      lineHeight: 1.3,
      theme: {
        background: "#080808",
        foreground: "#d4d4d4",
        cursor: "#00ff66",
        selectionBackground: "rgba(255, 255, 255, 0.2)",
        black: "#000000",
        red: "#ff5555",
        green: "#50fa7b",
        yellow: "#f1fa8c",
        blue: "#bd93f9",
        magenta: "#ff79c6",
        cyan: "#8be9fd",
        white: "#bfbfbf",
        brightBlack: "#4d4d4d",
        brightRed: "#ff6e6e",
        brightGreen: "#69ff94",
        brightYellow: "#ffffa5",
        brightBlue: "#d6acff",
        brightMagenta: "#ff92df",
        brightCyan: "#a4ffff",
        brightWhite: "#ffffff",
      },
      convertEol: true,
      scrollback: 5000,
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalElRef.current);

    try {
      fitAddon.fit();
    } catch {
      // ignore
    }

    term.writeln("\x1b[38;2;120;220;140m\x1b[1mAILA Platform Sandbox Isolation Terminal\x1b[0m");
    term.writeln(
      `\x1b[90mBackend: ${status?.backend || "none"} \u00b7 Target: ${status?.ssh_host || "not configured"} \u00b7 State: ${status?.provisioned ? "READY" : "NOT PROVISIONED"}\x1b[0m\n`,
    );

    termRef.current = term;
    fitAddonRef.current = fitAddon;

    const handleResize = () => {
      try {
        fitAddon.fit();
      } catch {
        // ignore
      }
    };
    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
      term.dispose();
      termRef.current = null;
      fitAddonRef.current = null;
    };
  }, [status?.backend, status?.ssh_host, status?.provisioned]);

  const runCommand = async (cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    const term = termRef.current;
    if (term) {
      term.writeln(`\r\n\x1b[38;2;0;200;255m$\x1b[0m \x1b[1m${trimmed}\x1b[0m`);
    }

    // Convert bash-style command string to argv array
    const argv = trimmed.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)?.map((s) => s.replace(/^['"]|['"]$/g, "")) || [trimmed];

    try {
      const res: SandboxResult = await execMut.mutateAsync({
        argv,
        timeout_s: timeoutS,
        network: networkEgress,
      });

      if (term) {
        if (res.stdout) {
          term.write(res.stdout);
          if (!res.stdout.endsWith("\n")) term.writeln("");
        }
        if (res.stderr) {
          term.write(`\x1b[31m${res.stderr}\x1b[0m`);
          if (!res.stderr.endsWith("\n")) term.writeln("");
        }
        const statusColor = res.exit_code === 0 ? "\x1b[32m" : "\x1b[31m";
        term.writeln(
          `\x1b[90m[\x1b[0m${statusColor}exit ${res.exit_code ?? "\u2014"}\x1b[90m \u00b7 duration: ${fmtDuration(res.duration_s)}${res.timed_out ? " \u00b7 \x1b[33mTIMED OUT\x1b[90m" : ""}${res.oom ? " \u00b7 \x1b[31mOOM\x1b[90m" : ""}]\x1b[0m`,
        );
      }

      if (onRunSuccess) onRunSuccess();
    } catch (err) {
      if (term) {
        term.writeln(`\x1b[31m[EXEC ERROR]\x1b[0m ${apiErrMessage(err)}`);
      }
    }
  };

  const handleFormSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!commandInput.trim() || execMut.isPending) return;
    const cmd = commandInput;
    setCommandInput("");
    await runCommand(cmd);
  };

  const handleClear = () => {
    termRef.current?.clear();
  };

  return (
    <div style={css("flex:1;min-height:0;display:flex;flex-direction:column;background:#080808;overflow:hidden;")}>
      {/* Quick Action Preset Chips */}
      <div
        style={css(
          "flex:0 0 auto;display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 12px;background:#0d0d0d;border-bottom:1px solid #1a1a1a;flex-wrap:wrap;",
        )}
      >
        <div style={css("display:flex;align-items:center;gap:6px;flex-wrap:wrap;")}>
          <span style={css("font-family:var(--font-mono);font-size:9.5px;color:var(--text-faint);text-transform:uppercase;letter-spacing:0.06em;")}>
            quick exec:
          </span>
          <button type="button" onClick={() => void runCommand("uname -a")} style={btnGhost} disabled={execMut.isPending}>
            uname -a
          </button>
          <button type="button" onClick={() => void runCommand("id && whoami")} style={btnGhost} disabled={execMut.isPending}>
            id &amp; whoami
          </button>
          <button type="button" onClick={() => void runCommand("nsjail --help")} style={btnGhost} disabled={execMut.isPending}>
            nsjail --help
          </button>
          <button type="button" onClick={() => void runCommand("gcc --version || clang --version")} style={btnGhost} disabled={execMut.isPending}>
            compiler check
          </button>
          <button type="button" onClick={() => void runCommand("cat /etc/os-release")} style={btnGhost} disabled={execMut.isPending}>
            os-release
          </button>
        </div>

        <div style={css("display:flex;align-items:center;gap:10px;")}>
          <label style={css("display:flex;align-items:center;gap:4px;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);cursor:pointer;")}>
            <input
              type="checkbox"
              checked={networkEgress}
              onChange={(e) => setNetworkEgress(e.target.checked)}
            />
            enable network egress
          </label>
          <button type="button" onClick={handleClear} style={btnGhost}>
            clear
          </button>
        </div>
      </div>

      {/* Main Terminal View */}
      <div ref={terminalElRef} style={css("flex:1;min-height:0;padding:6px 10px;overflow:hidden;")} />

      {/* Terminal Input Bar */}
      <form
        onSubmit={handleFormSubmit}
        style={css(
          "flex:0 0 auto;display:flex;align-items:center;gap:8px;padding:8px 12px;background:#0d0d0d;border-top:1px solid #1a1a1a;",
        )}
      >
        <span style={css("font-family:var(--font-mono);font-size:13px;font-weight:700;color:var(--accent);")}>
          $
        </span>
        <input
          type="text"
          value={commandInput}
          onChange={(e) => setCommandInput(e.target.value)}
          placeholder={
            status?.provisioned
              ? "Type command to execute inside sandbox (e.g. gcc -O2 poc.c -o poc && ./poc)..."
              : "Sandbox not provisioned \u2014 select a registered fleet host above."
          }
          style={inputStyle}
          disabled={execMut.isPending}
          autoFocus
        />
        <button
          type="submit"
          disabled={execMut.isPending || !commandInput.trim() || !status?.provisioned}
          style={execMut.isPending || !commandInput.trim() || !status?.provisioned ? btnPrimaryDisabled : btnPrimary}
        >
          {execMut.isPending ? "executing\u2026" : "run \u23ce"}
        </button>
      </form>
    </div>
  );
}

/* ------------------------- SETTINGS & POLICY ----------------------------- */

function SandboxSettingsTab(): JSX.Element {
  const configQ = useSandboxConfig();
  const updateConfig = useUpdateSandboxConfig();
  const rows: SandboxConfigRow[] = configQ.data ?? [];

  const [editKey, setEditKey] = useState<string | null>(null);
  const [editVal, setEditVal] = useState<string>("");

  const handleStartEdit = (row: SandboxConfigRow) => {
    setEditKey(row.key);
    setEditVal(row.effective_value ?? row.value ?? "");
  };

  const handleSave = async (row: SandboxConfigRow) => {
    try {
      await updateConfig.mutateAsync({
        key: row.key,
        body: { value: editVal, value_type: row.value_type },
      });
      setEditKey(null);
    } catch {
      // handled by mutation state
    }
  };

  return (
    <div style={css("flex:1;min-height:0;overflow:auto;padding:16px 20px;display:flex;flex-direction:column;gap:14px;")}>
      <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-muted);")}>
        Platform isolation policies, limits, and binary path configurations:
      </div>

      <div style={css("border:1px solid var(--border);border-radius:3px;background:var(--surface-card);overflow:hidden;")}>
        <table style={css("width:100%;border-collapse:collapse;font-family:var(--font-mono);font-size:11px;")}>
          <thead>
            <tr style={css("background:var(--surface-chrome);border-bottom:1px solid var(--border);text-align:left;color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:0.06em;")}>
              <th style={css("padding:8px 12px;")}>Key</th>
              <th style={css("padding:8px 12px;")}>Effective Value</th>
              <th style={css("padding:8px 12px;")}>Source</th>
              <th style={css("padding:8px 12px;text-align:right;")}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key} style={css("border-bottom:1px solid var(--border-soft);")}>
                <td style={css("padding:8px 12px;color:var(--text-primary);font-weight:600;")}>
                  {r.key}
                </td>
                <td style={css("padding:8px 12px;color:var(--text-muted);")}>
                  {editKey === r.key ? (
                    <input
                      type="text"
                      value={editVal}
                      onChange={(e) => setEditVal(e.target.value)}
                      style={css("background:var(--surface-sunk);border:1px solid var(--accent);color:var(--text-primary);padding:3px 6px;border-radius:2px;width:100%;")}
                    />
                  ) : (
                    <span>{r.effective_value || r.value || "\u2014"}</span>
                  )}
                </td>
                <td style={css("padding:8px 12px;color:var(--text-faint);")}>
                  {r.effective_source}
                </td>
                <td style={css("padding:8px 12px;text-align:right;")}>
                  {editKey === r.key ? (
                    <div style={css("display:inline-flex;gap:4px;")}>
                      <button type="button" onClick={() => void handleSave(r)} style={btnPrimary} disabled={updateConfig.isPending}>
                        save
                      </button>
                      <button type="button" onClick={() => setEditKey(null)} style={btnGhost}>
                        cancel
                      </button>
                    </div>
                  ) : (
                    <button type="button" onClick={() => handleStartEdit(r)} style={btnGhost}>
                      edit
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* -------------------------- HISTORY TAB ---------------------------------- */

function SandboxHistoryTab(): JSX.Element {
  const q = useSandboxHistory();
  const rows: SandboxHistoryRow[] = q.data ?? [];

  return (
    <div style={css("flex:1;min-height:0;overflow:auto;padding:16px 20px;display:flex;flex-direction:column;gap:12px;")}>
      <div style={css("display:flex;align-items:center;justify-content:space-between;gap:8px;")}>
        <span style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-muted);")}>
          Recent executions dispatched across the platform ({rows.length} records):
        </span>
        <button type="button" onClick={() => void q.refetch()} style={btnGhost}>
          refresh
        </button>
      </div>

      <div style={css("border:1px solid var(--border);border-radius:3px;background:var(--surface-card);overflow:hidden;")}>
        <table style={css("width:100%;border-collapse:collapse;font-family:var(--font-mono);font-size:11px;")}>
          <thead>
            <tr style={css("background:var(--surface-chrome);border-bottom:1px solid var(--border);text-align:left;color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:0.06em;")}>
              <th style={css("padding:8px 12px;")}>Time</th>
              <th style={css("padding:8px 12px;")}>Command (argv)</th>
              <th style={css("padding:8px 12px;")}>Exit</th>
              <th style={css("padding:8px 12px;")}>Duration</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={4} style={css("padding:24px;text-align:center;color:var(--text-faint);")}>
                  No recent execution records found.
                </td>
              </tr>
            ) : (
              rows.map((r) => (
                <tr key={r.id} style={css("border-bottom:1px solid var(--border-soft);")}>
                  <td style={css("padding:8px 12px;color:var(--text-faint);white-space:nowrap;")}>
                    {new Date(r.created_at).toLocaleTimeString()}
                  </td>
                  <td style={css("padding:8px 12px;color:var(--text-primary);font-family:var(--font-mono);word-break:break-all;")}>
                    <code>{r.argv.join(" ")}</code>
                  </td>
                  <td style={css("padding:8px 12px;")}>
                    <span style={r.exit_code === 0 ? chipOk : chipWarn}>
                      exit {r.exit_code ?? "\u2014"}
                    </span>
                  </td>
                  <td style={css("padding:8px 12px;color:var(--text-muted);white-space:nowrap;")}>
                    {fmtDuration(r.duration_s)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ----------------------------- MAIN PAGE --------------------------------- */

export default function SandboxPage(props: ModulePageProps): JSX.Element {
  const { windowId, title, isFocused, onFocus, onBack, onMinimize, isFullscreen, onToggleFullscreen } = props;

  const [activeTab, setActiveTab] = useState<"terminal" | "history" | "settings">("terminal");
  const [bootstrapOutput, setBootstrapOutput] = useState<string | null>(null);

  const statusQ = useSandboxStatus();
  const probe = useSandboxProbe();
  const systemsQ = useSystems(1, 200);
  const updateConfig = useUpdateSandboxConfig();
  const bootstrapTool = useBootstrapSandboxTooling();

  const status = statusQ.data;
  const probeData = probe.data;
  const systemsList = systemsQ.data?.items ?? [];

  const activeSys = systemsList.find(
    (s) => s.host === status?.ssh_host || s.name === status?.ssh_host,
  );

  const handleSelectSystem = async (sysId: string) => {
    if (!sysId) return;

    const found = systemsList.find((s) => String(s.id) === sysId);
    if (found) {
      if (status?.backend === "none" || !status?.backend) {
        await updateConfig.mutateAsync({
          key: "sandbox_backend",
          body: { value: "nsjail", value_type: "str" },
        });
      }
      await updateConfig.mutateAsync({
        key: "sandbox_system_id",
        body: { value: String(found.id), value_type: "str" },
      });
      await updateConfig.mutateAsync({
        key: "sandbox_system_name",
        body: { value: found.name || "", value_type: "str" },
      });
      await updateConfig.mutateAsync({
        key: "sandbox_ssh_host",
        body: { value: found.host || "", value_type: "str" },
      });
      await updateConfig.mutateAsync({
        key: "sandbox_ssh_user",
        body: { value: found.username || "root", value_type: "str" },
      });
      await updateConfig.mutateAsync({
        key: "sandbox_ssh_port",
        body: { value: String(found.port || 22), value_type: "str" },
      });

      await probe.mutateAsync();
      await statusQ.refetch();
    }
  };

  const handleBackendChange = async (newBackend: string) => {
    await updateConfig.mutateAsync({
      key: "sandbox_backend",
      body: { value: newBackend, value_type: "str" },
    });
    await probe.mutateAsync();
    await statusQ.refetch();
  };

  const handleInstallTooling = async () => {
    setBootstrapOutput(null);
    const targetTool = status?.backend === "firecracker" ? "firecracker" : "nsjail";
    try {
      const res = await bootstrapTool.mutateAsync({ tool: targetTool });
      setBootstrapOutput(res.output || res.detail);
      await probe.mutateAsync();
      await statusQ.refetch();
    } catch (err) {
      setBootstrapOutput(`Install failed: ${apiErrMessage(err)}`);
    }
  };

  const statusStrip = (
    <>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, letterSpacing: "0.14em" }}>
        admin &middot; sandbox
      </span>
      <span style={{ display: "flex", alignItems: "center", padding: "0 11px", textTransform: "none", letterSpacing: "0.03em", color: "var(--text-muted)" }}>
        {status?.backend || "nsjail"} &middot; {status?.ssh_host || "no target host"}
      </span>
      <span style={{ flex: 1 }} />
    </>
  );

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={title}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
      footerExtras={statusStrip}
    >
      {/* Top Controls: Systems Registry Binding, Backend Switcher, Live Health */}
      <div style={topBar}>
        <div style={controlGroup}>
          <span style={css("font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-muted);")}>
            fleet host:
          </span>
          <select
            value={activeSys ? String(activeSys.id) : ""}
            onChange={(e) => void handleSelectSystem(e.target.value)}
            style={selectStyle}
          >
            <option value="">
              {activeSys
                ? `${activeSys.name} (${activeSys.host}:${activeSys.port})`
                : status?.ssh_host
                  ? `custom (${status.ssh_host})`
                  : "-- select registered fleet system --"}
            </option>
            {systemsList.map((s) => (
              <option key={s.id} value={String(s.id)}>
                {s.name} ({s.host}:{s.port}{s.role ? ` \u00b7 ${s.role}` : ""})
              </option>
            ))}
          </select>

          <span style={css("font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-muted);")}>
            backend:
          </span>
          <select
            value={status?.backend || "nsjail"}
            onChange={(e) => void handleBackendChange(e.target.value)}
            style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:4px 8px;outline:none;")}
          >
            <option value="nsjail">nsjail</option>
            <option value="firecracker">firecracker</option>
          </select>

          {/* Live Status Indicators */}
          {probe.isPending ? (
            <span style={chipFaint}>probing&#8230;</span>
          ) : probeData ? (
            probeData.ok ? (
              <span style={chipOk}>
                {"\u2713"} {probeData.installed_path ? `${status?.backend || "nsjail"} ready` : "reachable"}
              </span>
            ) : probeData.tool_missing ? (
              <span style={chipWarn}>
                {"\u26a0"} {status?.backend || "nsjail"} missing
              </span>
            ) : (
              <span style={chipWarn}>unreachable</span>
            )
          ) : status?.provisioned ? (
            <span style={chipOk}>ready</span>
          ) : (
            <span style={chipFaint}>unprobed</span>
          )}

          {/* 1-Click Install Tooling Button */}
          {probeData?.tool_missing ? (
            <button
              type="button"
              onClick={handleInstallTooling}
              disabled={bootstrapTool.isPending}
              style={bootstrapTool.isPending ? btnPrimaryDisabled : btnPrimary}
            >
              {bootstrapTool.isPending
                ? "installing\u2026"
                : `\u26a1 install ${status?.backend === "firecracker" ? "firecracker" : "nsjail"} on host`}
            </button>
          ) : null}

          <button
            type="button"
            onClick={() => void probe.mutate()}
            disabled={probe.isPending}
            style={btnGhost}
          >
            probe
          </button>
        </div>

        {/* View Switcher Tabs */}
        <div style={controlGroup}>
          <button
            type="button"
            onClick={() => setActiveTab("terminal")}
            style={activeTab === "terminal" ? btnGhostActive : btnGhost}
          >
            &gt;_ Terminal
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("history")}
            style={activeTab === "history" ? btnGhostActive : btnGhost}
          >
            Recent Runs
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("settings")}
            style={activeTab === "settings" ? btnGhostActive : btnGhost}
          >
            Settings &amp; Policy
          </button>
        </div>
      </div>

      {/* Bootstrap Installer Log Output Banner */}
      {bootstrapOutput ? (
        <div
          style={css(
            "flex:0 0 auto;padding:8px 14px;background:#0d0d0d;border-bottom:1px solid #222;display:flex;flex-direction:column;gap:4px;",
          )}
        >
          <div style={css("display:flex;align-items:center;justify-content:space-between;")}>
            <span style={css("font-family:var(--font-mono);font-size:10px;font-weight:700;color:var(--accent);")}>
              Installer Output:
            </span>
            <button type="button" onClick={() => setBootstrapOutput(null)} style={btnGhost}>
              dismiss
            </button>
          </div>
          <pre
            style={{
              margin: 0,
              padding: "6px 8px",
              background: "#050505",
              border: "1px solid #1a1a1a",
              borderRadius: 2,
              fontFamily: "var(--font-mono, monospace)",
              fontSize: 10,
              color: "#e0e0e0",
              maxHeight: 120,
              overflow: "auto",
              whiteSpace: "pre-wrap",
            }}
          >
            {bootstrapOutput}
          </pre>
        </div>
      ) : null}

      {/* Main Surface Body */}
      {activeTab === "terminal" ? (
        <InteractiveSandboxTerminal status={status} />
      ) : activeTab === "history" ? (
        <SandboxHistoryTab />
      ) : (
        <SandboxSettingsTab />
      )}
    </ConsoleWindow>
  );
}