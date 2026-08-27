/**
 * SandboxPage -- Dedicated platform isolation & sandbox terminal window.
 *
 * Backed by the platform Systems Registry (`ManagedSystemRecord`) and
 * remote isolation backends (`nsjail` + `firecracker` over SSH).
 */

import { useEffect, useRef, useState } from "react";
import type { CSSProperties, FormEvent, JSX, KeyboardEvent } from "react";

import { ApiError } from "../../api/client";
import {
  useBootstrapSandboxTooling,
  useSandboxConfig,
  useSandboxExec,
  useSandboxHistory,
  useSandboxProbe,
  useSandboxStatus,
  useSetSandboxTarget,
  useUpdateSandboxConfig,
} from "../../api/sandbox";
import type {
  SandboxConfigRow,
  SandboxHistoryRow,
  SandboxResult,
  SandboxStatus,
} from "../../api/sandbox";
import { useSystems } from "../../api/systems";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";

/* ------------------------------ constants -------------------------------- */

const H_WARN = "#ffb85f";

/* ------------------------------- styles ---------------------------------- */

const topBar: CSSProperties = css(
  "flex:0 0 auto;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:8px 14px;background:var(--surface-chrome);border-bottom:1px solid var(--border);flex-wrap:wrap;",
);

const controlGroup: CSSProperties = css(
  "display:flex;align-items:center;gap:8px;flex-wrap:wrap;",
);

const selectStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:4px 8px;min-width:180px;outline:none;",
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

const inputStyle: CSSProperties = css(
  "flex:1;background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;padding:6px 10px;outline:none;",
);

/* ------------------------------ helpers ---------------------------------- */

function apiErrMessage(err: unknown): string {
  if (err instanceof Error) {
    try {
      const parsed = JSON.parse(err.message);
      if (parsed && typeof parsed === "object" && parsed.detail) {
        return String(parsed.detail);
      }
    } catch {
      // not JSON, use message directly
    }
    return err.message;
  }
  return String(err);
}

function fmtDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return "\u2014";
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
  return `${seconds.toFixed(2)}s`;
}

interface TerminalEntry {
  id: string;
  kind: "system" | "input" | "stdout" | "stderr" | "meta";
  text: string;
  exitCode?: number | null;
  durationS?: number;
  showInstallButton?: boolean;
}

/* ------------------------ INTERACTIVE TERMINAL --------------------------- */

function InteractiveSandboxTerminal({
  status,
  onRunSuccess,
  onInstallTooling,
  isInstalling,
}: {
  status: SandboxStatus | undefined;
  onRunSuccess?: () => void;
  onInstallTooling?: () => void;
  isInstalling?: boolean;
}): JSX.Element {
  const terminalScrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const [commandInput, setCommandInput] = useState<string>("");
  const [historyStack, setHistoryStack] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [networkEgress, setNetworkEgress] = useState<boolean>(false);
  const [timeoutS] = useState<number>(30);
  const [entries, setEntries] = useState<TerminalEntry[]>([]);

  const execMut = useSandboxExec();

  useEffect(() => {
    if (terminalScrollRef.current) {
      terminalScrollRef.current.scrollTop = terminalScrollRef.current.scrollHeight;
    }
  }, [entries]);

  const runCommand = async (cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    const inputId = `cmd-${Date.now()}`;
    setEntries((prev) => [
      ...prev,
      { id: inputId, kind: "input", text: trimmed },
    ]);

    setHistoryStack((prev) => [...prev, trimmed]);
    setHistoryIndex(-1);

    // Interactive sandbox terminal commands run through the host's shell
    // so PATH lookup, pipes, redirections, and multi-word commands execute naturally.
    const argv = ["/bin/sh", "-c", trimmed];

    try {
      const res: SandboxResult = await execMut.mutateAsync({
        argv,
        timeout_s: timeoutS,
        network: networkEgress,
      });

      setEntries((prev) => {
        const next = [...prev];
        if (res.stdout) {
          next.push({
            id: `out-${Date.now()}`,
            kind: "stdout",
            text: res.stdout,
          });
        }
        if (res.stderr) {
          next.push({
            id: `err-${Date.now()}`,
            kind: "stderr",
            text: res.stderr,
          });
        }
        next.push({
          id: `meta-${Date.now()}`,
          kind: "meta",
          text: `[exit ${res.exit_code ?? "\u2014"} \u00b7 duration: ${fmtDuration(res.duration_s)}${res.timed_out ? " \u00b7 TIMED OUT" : ""}${res.oom ? " \u00b7 OOM" : ""}]`,
          exitCode: res.exit_code,
          durationS: res.duration_s,
        });
        return next;
      });

      if (onRunSuccess) onRunSuccess();
    } catch (err) {
      const errMsg = apiErrMessage(err);
      const isMissingTool =
        errMsg.toLowerCase().includes("missing required binary") ||
        errMsg.toLowerCase().includes("not installed");

      setEntries((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          kind: "stderr",
          text: `[EXEC ERROR] ${errMsg}`,
          showInstallButton: isMissingTool,
        },
      ]);
    } finally {
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  };

  const handleFormSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!commandInput.trim() || execMut.isPending) return;
    const cmd = commandInput;
    setCommandInput("");
    await runCommand(cmd);
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (historyStack.length === 0) return;
      const nextIdx = historyIndex === -1 ? historyStack.length - 1 : Math.max(0, historyIndex - 1);
      setHistoryIndex(nextIdx);
      setCommandInput(historyStack[nextIdx] || "");
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIndex === -1) return;
      const nextIdx = historyIndex + 1;
      if (nextIdx >= historyStack.length) {
        setHistoryIndex(-1);
        setCommandInput("");
      } else {
        setHistoryIndex(nextIdx);
        setCommandInput(historyStack[nextIdx] || "");
      }
    }
  };

  const handleClear = () => {
    setEntries([]);
  };

  const targetTool = status?.backend === "firecracker" ? "firecracker" : "nsjail";

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

      {/* Main Terminal Output View */}
      <div
        ref={terminalScrollRef}
        style={css(
          "flex:1;min-height:0;padding:12px 14px;overflow-y:auto;font-family:var(--font-mono, monospace);font-size:12px;line-height:1.45;color:#d4d4d4;",
        )}
      >
        {/* Dynamic Reactive Banner Header */}
        <div style={css("color:#50fa7b;font-weight:700;padding-bottom:2px;")}>
          AILA Platform Sandbox Isolation Terminal
        </div>
        <div style={css("color:#888;font-size:11px;padding-bottom:8px;border-bottom:1px solid #1a1a1a;margin-bottom:8px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;")}>
          <div>
            Backend: <span style={css("color:#fff;font-weight:600;")}>{status?.backend || "none"}</span>
            {" \u00b7 "}
            Target: <span style={css("color:#00ffff;font-weight:600;")}>{status?.ssh_host || "not selected"}</span>
            {" \u00b7 "}
            Status: <span style={css(`color:${status?.provisioned ? "#50fa7b" : H_WARN};font-weight:600;`)}>
              {status?.provisioned ? "READY" : "NOT PROVISIONED"}
            </span>
          </div>

          {!status?.provisioned && status?.ssh_host ? (
            <button
              type="button"
              onClick={() => void onInstallTooling?.()}
              disabled={isInstalling}
              style={isInstalling ? btnPrimaryDisabled : btnPrimary}
            >
              {isInstalling ? "installing tooling over ssh..." : `\u26a1 install ${targetTool} on host`}
            </button>
          ) : null}
        </div>

        {entries.map((entry) => {
          if (entry.kind === "system") {
            return (
              <div key={entry.id} style={css("color:#50fa7b;font-weight:700;padding-bottom:2px;")}>
                {entry.text}
              </div>
            );
          }
          if (entry.kind === "input") {
            return (
              <div key={entry.id} style={css("padding:6px 0 2px;color:#f8f8f2;display:flex;gap:6px;")}>
                <span style={css("color:#00ffff;font-weight:700;")}>$</span>
                <span style={css("font-weight:600;word-break:break-all;")}>{entry.text}</span>
              </div>
            );
          }
          if (entry.kind === "stdout") {
            return (
              <pre
                key={entry.id}
                style={{
                  margin: 0,
                  padding: 0,
                  fontFamily: "inherit",
                  fontSize: "inherit",
                  color: "#d4d4d4",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {entry.text}
              </pre>
            );
          }
          if (entry.kind === "stderr") {
            return (
              <div key={entry.id} style={css("display:flex;flex-direction:column;gap:6px;")}>
                <pre
                  style={{
                    margin: 0,
                    padding: 0,
                    fontFamily: "inherit",
                    fontSize: "inherit",
                    color: "#ff5555",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                  }}
                >
                  {entry.text}
                </pre>
                {entry.showInstallButton ? (
                  <div style={css("padding:4px 0 6px;")}>
                    <button
                      type="button"
                      onClick={() => void onInstallTooling?.()}
                      disabled={isInstalling}
                      style={isInstalling ? btnPrimaryDisabled : btnPrimary}
                    >
                      {isInstalling
                        ? "installing tooling over ssh..."
                        : `\u26a1 1-Click: Install ${targetTool} on ${status?.ssh_host || "host"}`}
                    </button>
                  </div>
                ) : null}
              </div>
            );
          }
          return (
            <div
              key={entry.id}
              style={css(
                `color:${entry.exitCode === 0 ? "#50fa7b" : entry.exitCode !== undefined ? "#ff5555" : "#666"};font-size:10px;padding:2px 0 6px;`,
              )}
            >
              {entry.text}
            </div>
          );
        })}
      </div>

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
          ref={inputRef}
          type="text"
          value={commandInput}
          onChange={(e) => setCommandInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={
            status?.provisioned
              ? "Type command to execute inside sandbox (e.g. gcc -O2 poc.c -o poc && ./poc)..."
              : "Sandbox not provisioned \u2014 select a fleet host or click install above."
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
  const rawRows: SandboxConfigRow[] = configQ.data ?? [];

  // Internal connection strings managed directly by the Systems Registry
  const hiddenKeys = new Set([
    "sandbox_ssh_host",
    "sandbox_ssh_user",
    "sandbox_ssh_port",
    "sandbox_system_id",
    "sandbox_system_name",
  ]);

  const rows = rawRows.filter((r) => !hiddenKeys.has(r.key));

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
        Platform isolation limits, execution timeouts, and guest binary paths:
      </div>

      <div style={css("border:1px solid var(--border);border-radius:3px;background:var(--surface-card);overflow:hidden;")}>
        <table style={css("width:100%;border-collapse:collapse;font-family:var(--font-mono);font-size:11px;")}>
          <thead>
            <tr style={css("background:var(--surface-chrome);border-bottom:1px solid var(--border);text-align:left;color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:0.06em;")}>
              <th style={css("padding:8px 12px;")}>Setting Key</th>
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
  const [targetError, setTargetError] = useState<string | null>(null);

  const statusQ = useSandboxStatus();
  const probe = useSandboxProbe();
  const systemsQ = useSystems(1, 200);
  const setTarget = useSetSandboxTarget();
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
    setTargetError(null);

    const found = systemsList.find((s) => String(s.id) === sysId);
    if (found) {
      const targetBackend = (status?.backend === "none" || !status?.backend) ? "nsjail" : status.backend;
      try {
        await setTarget.mutateAsync({
          system_id: String(found.id),
          system_name: found.name || "",
          host: found.host,
          username: found.username || "root",
          port: found.port || 22,
          backend: targetBackend,
        });
        await statusQ.refetch();
      } catch (err) {
        setTargetError(`Failed to bind host: ${apiErrMessage(err)}`);
      }
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

  const targetTool = status?.backend === "firecracker" ? "firecracker" : "nsjail";

  const handleInstallTooling = async () => {
    setBootstrapOutput(null);
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
        {status?.backend || "nsjail"} &middot; {activeSys ? activeSys.name : status?.ssh_host || "no host"}
      </span>
      <span style={{ flex: 1 }} />
    </>
  );

  const isMissingTool = probeData?.tool_missing || (!status?.provisioned && Boolean(status?.ssh_host));

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
      {/* Top Controls: Fleet Host Selector, Backend, Live Status */}
      <div style={topBar}>
        <div style={controlGroup}>
          <span style={css("font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-muted);")}>
            fleet host:
          </span>
          <select
            value={activeSys ? String(activeSys.id) : ""}
            onChange={(e) => void handleSelectSystem(e.target.value)}
            disabled={setTarget.isPending || systemsQ.isLoading}
            style={selectStyle}
          >
            <option value="" disabled>
              {systemsQ.isLoading
                ? "Loading fleet systems..."
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
          {setTarget.isPending || probe.isPending ? (
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

          {/* 1-Click Install Tooling Button in Top Toolbar */}
          {isMissingTool ? (
            <button
              type="button"
              onClick={handleInstallTooling}
              disabled={bootstrapTool.isPending}
              style={bootstrapTool.isPending ? btnPrimaryDisabled : btnPrimary}
            >
              {bootstrapTool.isPending
                ? "installing on host\u2026"
                : `\u26a1 install ${targetTool} on host`}
            </button>
          ) : null}

          <button
            type="button"
            onClick={() => void probe.mutate()}
            disabled={probe.isPending || setTarget.isPending}
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

      {/* Target Binding Error Banner */}
      {targetError ? (
        <div
          style={css(
            `flex:0 0 auto;padding:8px 14px;background:color-mix(in srgb,${H_WARN} 10%,transparent);border-bottom:1px solid ${H_WARN};color:${H_WARN};font-family:var(--font-mono);font-size:11px;display:flex;align-items:center;justify-content:space-between;`,
          )}
        >
          <span>{"\u26a0"} {targetError}</span>
          <button type="button" onClick={() => setTargetError(null)} style={btnGhost}>
            dismiss
          </button>
        </div>
      ) : null}

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
              maxHeight: 140,
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
        <InteractiveSandboxTerminal
          status={status}
          onInstallTooling={handleInstallTooling}
          isInstalling={bootstrapTool.isPending}
        />
      ) : activeTab === "history" ? (
        <SandboxHistoryTab />
      ) : (
        <SandboxSettingsTab />
      )}
    </ConsoleWindow>
  );
}