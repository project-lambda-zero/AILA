/** The sandbox Settings & Policy tab: the platform isolation config rows
 * (limits, timeouts, guest binary paths) with inline editing. */

import { useState } from "react";
import type { JSX } from "react";

import { useSandboxConfig, useUpdateSandboxConfig } from "../../../api/sandbox";
import type { SandboxConfigRow } from "../../../api/sandbox";
import { css } from "../../css";
import { btnGhost, btnPrimary } from "./styles";

export function SandboxSettingsTab(): JSX.Element {
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
            <tr style={css("background:var(--surface-chrome);border-bottom:1px solid var(--border);text-align:left;color:var(--text-muted);font-size:11px;text-transform:uppercase;letter-spacing:0.06em;")}>
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
