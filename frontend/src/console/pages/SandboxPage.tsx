/**
 * SandboxPage -- Dedicated platform isolation & sandbox terminal window.
 *
 * Backed by the platform Systems Registry (`ManagedSystemRecord`) and
 * remote isolation backends (`nsjail` + `firecracker` over SSH). The tab
 * bodies live under ./sandbox/.
 */

import { useState } from "react";
import type { JSX } from "react";

import {
  useBootstrapSandboxTooling,
  useSandboxProbe,
  useSandboxStatus,
  useSetSandboxTarget,
  useUpdateSandboxConfig,
} from "../../api/sandbox";
import { useSystems } from "../../api/systems";
import type { WindowChromeProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import { apiErrMessage } from "./sandbox/helpers";
import { InteractiveSandboxTerminal } from "./sandbox/InteractiveSandboxTerminal";
import { SandboxHistoryTab } from "./sandbox/SandboxHistoryTab";
import { SandboxSettingsTab } from "./sandbox/SandboxSettingsTab";
import {
  btnGhost,
  btnGhostActive,
  btnPrimary,
  btnPrimaryDisabled,
  chipFaint,
  chipOk,
  chipWarn,
  controlGroup,
  H_WARN,
  selectStyle,
  topBar,
} from "./sandbox/styles";

export default function SandboxPage(props: WindowChromeProps): JSX.Element {
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
    >
      {/* Top Controls: Fleet Host Selector, Backend, Live Status */}
      <div style={topBar}>
        <div style={controlGroup}>
          <span style={css("font-family:var(--font-mono);font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-muted);")}>
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

          <span style={css("font-family:var(--font-mono);font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-muted);")}>
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
            <span style={css("font-family:var(--font-mono);font-size:11px;font-weight:700;color:var(--accent);")}>
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
              fontSize: 11,
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
