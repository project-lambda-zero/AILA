/** The sandbox interactive terminal: quick-exec chips, scrollback with
 * stdout/stderr/meta entries, shell-history navigation, and the command
 * input bar. Commands run through the host's shell so PATH lookup, pipes,
 * and redirections execute naturally. */

import { useEffect, useRef, useState } from "react";
import type { FormEvent, JSX, KeyboardEvent } from "react";

import { useSandboxExec } from "../../../api/sandbox";
import type { SandboxResult, SandboxStatus } from "../../../api/sandbox";
import { css } from "../../css";
import { apiErrMessage, fmtDuration } from "./helpers";
import { btnGhost, btnPrimary, btnPrimaryDisabled, H_WARN, inputStyle } from "./styles";

interface TerminalEntry {
  id: string;
  kind: "system" | "input" | "stdout" | "stderr" | "meta";
  text: string;
  exitCode?: number | null;
  durationS?: number;
  showInstallButton?: boolean;
}

export function InteractiveSandboxTerminal({
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
          <span style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);text-transform:uppercase;letter-spacing:0.06em;")}>
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
          <label style={css("display:flex;align-items:center;gap:4px;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);cursor:pointer;")}>
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
                `color:${entry.exitCode === 0 ? "#50fa7b" : entry.exitCode !== undefined ? "#ff5555" : "#666"};font-size:11px;padding:2px 0 6px;`,
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
