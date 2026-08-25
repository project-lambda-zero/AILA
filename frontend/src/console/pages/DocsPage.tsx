/**
 * DocsPage -- read-only console window over the platform docs corpus.
 *
 *   GET /docs/topics             -- left rail (topics that exist on disk)
 *   GET /docs/topics/{slug}      -- right pane raw markdown body
 *
 * v1 renders the raw markdown text inside a mono <pre>. No markdown
 * renderer is currently in the workspace (react-markdown / marked /
 * markdown-it / remark are all absent from frontend/package.json) and
 * the slice ships with no new dependencies. A future renderer can be
 * dropped in without touching the fetch layer.
 *
 * Follows the SandboxPage window-chrome convention: self-wraps in
 * <ConsoleWindow>, spreads ModulePageProps for the shell-provided
 * focus / minimize / close controls, header row with dot + display
 * title, two-pane body (topic rail | selected topic body).
 */

import { useEffect, useState } from "react";
import type { CSSProperties, JSX } from "react";

import { ApiError } from "../../api/client";
import { useDocTopic, useDocTopics } from "../../api/docs";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";

/* ------------------------------- styles ---------------------------------- */

const panelBox: CSSProperties = css(
  "min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;",
);
const panelTitle: CSSProperties = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:9.5px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
const dot: CSSProperties = css(
  "width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;",
);
const scroll: CSSProperties = css("flex:1;min-height:0;overflow:auto;");
const emptyNote: CSSProperties = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);
const errNote: CSSProperties = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--status-err,#ff6b6b);letter-spacing:0.04em;text-align:center;",
);
const monoBlock: CSSProperties = css(
  "margin:0;padding:14px 16px;font-family:var(--font-mono);font-size:11.5px;line-height:1.55;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;",
);
const topicBtnBase: CSSProperties = css(
  "display:block;width:100%;text-align:left;padding:7px 12px;border:none;border-bottom:1px solid var(--border-faint);background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.04em;cursor:pointer;",
);
const topicBtnActive: CSSProperties = css(
  "display:block;width:100%;text-align:left;padding:7px 12px;border:none;border-bottom:1px solid var(--border-faint);background:color-mix(in srgb,var(--accent) 14%,transparent);color:var(--accent);font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.04em;cursor:pointer;",
);

/* ------------------------------- helpers --------------------------------- */

function errMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message || `HTTP ${err.status}`;
  if (err instanceof Error) return err.message;
  return String(err);
}

/* --------------------------------- page ---------------------------------- */

export default function DocsPage(props: ModulePageProps): JSX.Element {
  const {
    windowId,
    title,
    isFocused,
    isFullscreen,
    onFocus,
    onBack,
    onMinimize,
    onToggleFullscreen,
  } = props;

  const topics = useDocTopics();
  const [selected, setSelected] = useState<string | null>(null);

  // Auto-select the first topic once the list resolves so the right pane
  // is never blank when a topic is available. Only fires on the initial
  // load; a manual click always wins after that.
  useEffect(() => {
    if (selected === null && topics.data && topics.data.length > 0) {
      setSelected(topics.data[0].slug);
    }
  }, [topics.data, selected]);

  const body = useDocTopic(selected);

  const rail = (
    <div style={{ ...panelBox, flex: "0 0 220px" }}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>topics</span>
      </div>
      <div style={scroll}>
        {topics.isLoading ? (
          <div style={emptyNote}>loading topics</div>
        ) : topics.isError ? (
          <div style={errNote}>{errMessage(topics.error)}</div>
        ) : !topics.data || topics.data.length === 0 ? (
          <div style={emptyNote}>no docs available</div>
        ) : (
          topics.data.map((t) => {
            const active = t.slug === selected;
            return (
              <button
                key={t.slug}
                type="button"
                style={active ? topicBtnActive : topicBtnBase}
                onClick={() => setSelected(t.slug)}
              >
                {t.title}
              </button>
            );
          })
        )}
      </div>
    </div>
  );

  const bodyPane = (
    <div style={{ ...panelBox, flex: 1, minWidth: 0 }}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>
          {body.data?.title ?? (selected ?? "document")}
        </span>
        <span style={css("flex:1;")} />
        {selected ? (
          <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>
            {selected}
          </span>
        ) : null}
      </div>
      <div style={scroll}>
        {!selected ? (
          <div style={emptyNote}>select a topic</div>
        ) : body.isLoading ? (
          <div style={emptyNote}>loading document</div>
        ) : body.isError ? (
          <div style={errNote}>{errMessage(body.error)}</div>
        ) : body.data ? (
          <pre style={monoBlock}>{body.data.body}</pre>
        ) : (
          <div style={emptyNote}>no content</div>
        )}
      </div>
    </div>
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
        <span
          style={{
            fontFamily: "var(--font-display)",
            color: "var(--text-primary)",
            fontWeight: 400,
            letterSpacing: "0.16em",
          }}
        >
          docs
        </span>
        <span style={{ color: "var(--text-faint)", textTransform: "none", letterSpacing: "0.04em" }}>
          platform reference &mdash; read-only
        </span>
      </header>
      <main
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          gap: 10,
          padding: 12,
        }}
      >
        {rail}
        {bodyPane}
      </main>
    </ConsoleWindow>
  );
}
