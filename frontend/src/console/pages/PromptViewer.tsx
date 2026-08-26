import type { JSX, ReactNode } from "react";
import { useState } from "react";

import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "../../api/client";
import { css } from "../css";

export interface PromptDetailPayload {
  key: string;
  version: string;
  body: string;
  content_hash: string;
  author: string;
  notes: string;
  aliases: string[];
  created_at: string;
}

export function usePromptBody(key: string | null) {
  return useQuery({
    queryKey: ["admin-prompt-body", key ?? ""],
    queryFn: () => apiFetch<PromptDetailPayload>(`/admin/prompts/body?key=${encodeURIComponent(key ?? "")}`),
    enabled: Boolean(key && key.trim()),
    staleTime: 30_000,
    retry: false,
  });
}

const wrapStyle = css(
  "display:flex;flex-direction:column;gap:12px;padding:16px;height:100%;min-height:0;box-sizing:border-box;font-family:var(--font-mono);color:var(--text-primary);"
);

const chipStrip = css(
  "display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:8px 12px;background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;font-size:11px;"
);

const chip = css(
  "display:inline-flex;align-items:center;gap:5px;padding:2px 7px;background:var(--surface-subtle);border:1px solid var(--border-soft);border-radius:2px;"
);

const labelText = css("color:var(--text-faint);text-transform:uppercase;font-size:9.5px;letter-spacing:0.06em;");
const valueText = css("color:var(--text-primary);font-weight:500;");

const btnStyle = css(
  "padding:4px 10px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;display:inline-flex;align-items:center;gap:6px;"
);

const bodyBox = css(
  "flex:1;min-height:0;overflow:auto;margin:0;padding:12px 14px;background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;font-family:var(--font-mono);font-size:11px;line-height:1.5;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;"
);

function Chip({ label, value }: { label: string; value: ReactNode }): JSX.Element {
  return (
    <span style={chip}>
      <span style={labelText}>{label}</span>
      <span style={valueText}>{value}</span>
    </span>
  );
}

export function CopyButton({ text }: { text: string }): JSX.Element {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button type="button" onClick={handleCopy} style={btnStyle}>
      {copied ? "✓ copied" : "copy prompt"}
    </button>
  );
}

/** Floating viewer opened from the Specialist Agents table. */
export function AgentPromptViewer({
  row,
  close: _close,
}: {
  row: Record<string, unknown>;
  close: () => void;
}): JSX.Element {
  const promptKey = String(row["prompt_key"] || "");
  const agentName = String(row["name"] || "agent");
  const modelRole = String(row["model_role"] || "default");
  const strategyFamily = String(row["strategy_family"] || "default");
  const description = String(row["description"] || "");

  const { data, isLoading, isError, error } = usePromptBody(promptKey);

  const promptText = data?.body || description || "";

  return (
    <div style={wrapStyle}>
      <div style={chipStrip}>
        <Chip label="agent" value={agentName} />
        <Chip label="model role" value={modelRole} />
        <Chip label="strategy" value={strategyFamily} />
        <Chip label="key" value={promptKey || "custom"} />
        {data?.version ? <Chip label="version" value={data.version} /> : null}
        {data?.aliases && data.aliases.length > 0 ? (
          <Chip label="alias" value={data.aliases.join(", ")} />
        ) : null}
        <span style={css("flex:1;")} />
        {promptText ? <CopyButton text={promptText} /> : null}
      </div>

      {isLoading ? (
        <div style={css("padding:24px;text-align:center;color:var(--text-muted);font-size:11px;")}>
          loading prompt body from store...
        </div>
      ) : isError ? (
        <div style={css("display:flex;flex-direction:column;gap:8px;")}>
          <div style={css("padding:8px 12px;background:color-mix(in srgb,#d64545 10%,transparent);border:1px solid #d6454566;border-radius:2px;color:#d64545;font-size:11px;")}>
            {error instanceof Error ? error.message : "prompt body not found in version store"}
          </div>
          {description ? (
            <div style={css("display:flex;flex-direction:column;gap:4px;")}>
              <span style={labelText}>fallback agent instruction description:</span>
              <pre style={bodyBox}>{description}</pre>
            </div>
          ) : null}
        </div>
      ) : (
        <pre style={bodyBox}>{promptText || "no prompt body registered"}</pre>
      )}
    </div>
  );
}

/** Floating viewer opened from the Prompts table. */
export function PromptFullViewer({
  row,
  close: _close,
}: {
  row: Record<string, unknown>;
  close: () => void;
}): JSX.Element {
  const key = String(row["key"] || "");
  const body = String(row["body"] || row["body_snippet"] || "");
  const version = String(row["version"] || "");
  const prodVersion = row["production_version"] ? String(row["production_version"]) : null;
  const author = String(row["author"] || "system");

  const { data } = usePromptBody(key);
  const fullText = data?.body || body;

  return (
    <div style={wrapStyle}>
      <div style={chipStrip}>
        <Chip label="key" value={key} />
        {version ? <Chip label="version" value={version} /> : null}
        {prodVersion ? <Chip label="production" value={prodVersion} /> : null}
        <Chip label="author" value={author} />
        <Chip label="chars" value={fullText.length} />
        <span style={css("flex:1;")} />
        {fullText ? <CopyButton text={fullText} /> : null}
      </div>

      <pre style={bodyBox}>{fullText || "no prompt text"}</pre>
    </div>
  );
}

/** Detail renderer for prompt text in DataPage detail grids. */
export function PromptBodyDetail({ body }: { body: string }): JSX.Element {
  return (
    <div style={css("display:flex;flex-direction:column;gap:6px;width:100%;min-width:0;")}>
      <div style={css("display:flex;justify-content:flex-end;")}>
        <CopyButton text={body} />
      </div>
      <pre style={css("margin:0;padding:8px 12px;background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;font-family:var(--font-mono);font-size:10.5px;line-height:1.45;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-height:360px;overflow:auto;")}>
        {body}
      </pre>
    </div>
  );
}
