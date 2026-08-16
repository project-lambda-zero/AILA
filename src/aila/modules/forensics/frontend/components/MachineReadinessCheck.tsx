import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { DataGrid, MonoBadge } from "@/components/aila/mock";

import type { MachineReadinessResult } from "../types";

interface Props {
  readinessResult: MachineReadinessResult | null;
  isLoading: boolean;
  onRetry: () => void;
  onContinue: () => void;
}

const STATUS_ICON: Record<string, string> = {
  installed: "\u2714",
  missing: "\u2718",
  install_failed: "\u26A0",
  installing: "\u23F3",
};

const STATUS_TONE: Record<string, string> = {
  installed: "ok",
  missing: "critical",
  install_failed: "high",
  installing: "medium",
};

const CHROME_BTN: React.CSSProperties = {
  height: 28,
  padding: "0 14px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

const ACCENT_BTN: React.CSSProperties = {
  height: 28,
  padding: "0 14px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-on-accent)",
  background: "var(--accent)",
  border: "1px solid var(--accent)",
  borderRadius: 3,
  cursor: "pointer",
  boxShadow: "var(--bevel-key)",
};

type ToolRow = MachineReadinessResult["tools"][number];

export function MachineReadinessCheck({
  readinessResult,
  isLoading,
  onRetry,
  onContinue,
}: Props) {
  if (isLoading) {
    return (
      <WindowPanel title="machine readiness" status="readiness ; checking tools">
        <div className="space-y-3">
          <LoadingSkeleton size="md" width="full" />
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            Connecting to analyzer machine and checking installed tools.
          </p>
        </div>
      </WindowPanel>
    );
  }

  if (!readinessResult) {
    return (
      <WindowPanel
        title="machine readiness"
        tone="muted"
        status="readiness ; no result"
      >
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          No readiness check result available.
        </p>
      </WindowPanel>
    );
  }

  return (
    <WindowPanel
      title="machine readiness"
      tone={readinessResult.ready ? "ok" : "warn"}
      actions={
        <MonoBadge tone={readinessResult.ready ? "ok" : "high"}>
          {readinessResult.ready ? "ready" : "not ready"}
        </MonoBadge>
      }
    >
      <div className="space-y-4">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}
        >
          {readinessResult.message}
        </p>

        <div aria-label="Machine readiness checks">
          <DataGrid<ToolRow>
            columns={[
              { label: "tool", width: "minmax(0, 1.4fr)" },
              { label: "required", width: "100px" },
              { label: "status", width: "160px" },
              { label: "version", width: "minmax(0, 1.6fr)" },
            ]}
            rows={readinessResult.tools}
            getKey={(t) => t.tool_name}
            renderCells={(t) => [
              <span
                key="n"
                className="font-mono"
                style={{ fontSize: 11, color: "var(--text-primary)" }}
              >
                {t.tool_name}
              </span>,
              <span
                key="r"
                className="font-mono"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {t.required ? "Yes" : "No"}
              </span>,
              <MonoBadge key="s" tone={STATUS_TONE[t.status] ?? "info"}>
                {STATUS_ICON[t.status] ?? ""} {t.status}
              </MonoBadge>,
              <span
                key="v"
                className="font-mono"
                style={{
                  fontSize: 10.5,
                  color: "var(--text-faint)",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
                title={t.version ?? t.message ?? undefined}
              >
                {t.version ?? t.message ?? "--"}
              </span>,
            ]}
          />
        </div>

        <div className="flex justify-end" style={{ gap: 8 }}>
          <button
            type="button"
            onClick={onRetry}
            className="font-mono uppercase"
            style={CHROME_BTN}
          >
            retry check
          </button>
          <button
            type="button"
            onClick={onContinue}
            className="font-mono uppercase"
            style={ACCENT_BTN}
          >
            continue
          </button>
        </div>
      </div>
    </WindowPanel>
  );
}
