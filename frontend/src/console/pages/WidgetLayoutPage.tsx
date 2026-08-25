/** WidgetLayoutPage -- bespoke admin editor for the widget layout (req 32).
 *
 * Rows list every kind (parseLayout backfills missing kinds hidden), with a
 * hide/show checkbox and up/down reorder buttons. Reset restores the default
 * layout in the local draft; save persists via `useSaveWidgetLayout` which
 * calls PUT /widgets/layout and primes the query cache so the host reflects
 * the change immediately. Loading, saving, and error states are all live. */

import { useEffect, useMemo, useState, type CSSProperties, type JSX } from "react";

import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import { WIDGET_CATALOG } from "../widgets/catalog";
import { DEFAULT_LAYOUT, useSaveWidgetLayout, useWidgetLayout } from "../widgets/useWidgetLayout";
import type { WidgetLayout, WidgetLayoutEntry } from "../widgets/types";

const bodyStyle: CSSProperties = css(
  "position:absolute;inset:0;display:flex;flex-direction:column;background:var(--surface-page);font-family:var(--font-mono);color:var(--text-primary);overflow:hidden;",
);
const headerStyle: CSSProperties = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;padding:8px 14px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-size:10.5px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-muted);",
);
const dotStyle: CSSProperties = css(
  "width:9px;height:9px;border-radius:1px;background:var(--accent);box-shadow:0 0 7px var(--accent);",
);
const titleStyle: CSSProperties = css(
  "color:var(--text-primary);font-weight:700;letter-spacing:0.16em;",
);
const subtitleStyle: CSSProperties = css(
  "color:var(--text-faint);text-transform:none;letter-spacing:0.04em;",
);
const scrollStyle: CSSProperties = css("flex:1;min-height:0;overflow:auto;padding:14px 16px;");
const blurbStyle: CSSProperties = css(
  "margin:0 0 14px 0;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);line-height:1.55;max-width:640px;",
);
const listStyle: CSSProperties = css(
  "display:flex;flex-direction:column;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-card);max-width:720px;",
);
const rowStyle: CSSProperties = css(
  "display:grid;grid-template-columns:auto 1fr auto auto;gap:12px;align-items:center;padding:9px 12px;border-bottom:1px solid var(--border-faint);font-family:var(--font-mono);font-size:11px;",
);
const rowLastStyle: CSSProperties = css(
  "display:grid;grid-template-columns:auto 1fr auto auto;gap:12px;align-items:center;padding:9px 12px;font-family:var(--font-mono);font-size:11px;",
);
const nameStyle: CSSProperties = css(
  "display:flex;flex-direction:column;gap:3px;min-width:0;",
);
const nameTitleStyle: CSSProperties = css(
  "color:var(--text-primary);font-size:11.5px;letter-spacing:0.04em;",
);
const nameMetaStyle: CSSProperties = css(
  "color:var(--text-faint);font-size:9px;letter-spacing:0.1em;text-transform:uppercase;",
);
const checkStyle: CSSProperties = css(
  "width:14px;height:14px;accent-color:var(--accent);cursor:pointer;",
);
const arrowBtnStyle: CSSProperties = css(
  "background:transparent;border:1px solid var(--border-soft);border-radius:2px;color:var(--text-muted);font-family:var(--font-mono);font-size:11px;cursor:pointer;width:24px;height:22px;display:inline-flex;align-items:center;justify-content:center;",
);
const arrowBtnDisabled: CSSProperties = css(
  "background:transparent;border:1px solid var(--border-faint);border-radius:2px;color:var(--text-faint);font-family:var(--font-mono);font-size:11px;cursor:not-allowed;width:24px;height:22px;display:inline-flex;align-items:center;justify-content:center;",
);
const actionsRowStyle: CSSProperties = css(
  "display:flex;align-items:center;gap:10px;margin-top:14px;max-width:720px;",
);
const btnPrimary: CSSProperties = css(
  "padding:6px 14px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.12em;text-transform:uppercase;cursor:pointer;",
);
const btnPrimaryDisabled: CSSProperties = css(
  "padding:6px 14px;border:1px solid var(--border-faint);border-radius:2px;background:transparent;color:var(--text-faint);font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.12em;text-transform:uppercase;cursor:not-allowed;",
);
const btnGhost: CSSProperties = css(
  "padding:6px 12px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.12em;text-transform:uppercase;cursor:pointer;",
);
const statusOk: CSSProperties = css(
  "font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:var(--status-ok);",
);
const statusErr: CSSProperties = css(
  "font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:var(--status-signal);",
);
const statusMuted: CSSProperties = css(
  "font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);",
);
const loadingBox: CSSProperties = css(
  "flex:1;display:flex;align-items:center;justify-content:center;color:var(--text-faint);font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;",
);

function cloneDefault(): WidgetLayout {
  return { version: 1, widgets: DEFAULT_LAYOUT.widgets.map((w) => ({ ...w })) };
}

function reindex(widgets: WidgetLayoutEntry[]): WidgetLayoutEntry[] {
  return widgets.map((w, i) => ({ ...w, order: i }));
}

export default function WidgetLayoutPage(p: ModulePageProps): JSX.Element {
  const { windowId, title, isFocused, onFocus, onBack, onMinimize, isFullscreen, onToggleFullscreen } = p;
  const query = useWidgetLayout();
  const save = useSaveWidgetLayout();

  const [draft, setDraft] = useState<WidgetLayout | null>(null);
  const [seeded, setSeeded] = useState(false);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  useEffect(() => {
    if (seeded || !query.data) return;
    setDraft({ version: 1, widgets: query.data.widgets.map((w) => ({ ...w })) });
    setSeeded(true);
  }, [query.data, seeded]);

  const rows = useMemo(() => draft?.widgets ?? [], [draft]);

  const toggleHidden = (id: string) => {
    if (!draft) return;
    setDraft({
      version: 1,
      widgets: draft.widgets.map((w) => (w.id === id ? { ...w, hidden: !w.hidden } : w)),
    });
  };

  const move = (index: number, delta: number) => {
    if (!draft) return;
    const next = draft.widgets.slice();
    const target = index + delta;
    if (target < 0 || target >= next.length) return;
    const [row] = next.splice(index, 1);
    next.splice(target, 0, row);
    setDraft({ version: 1, widgets: reindex(next) });
  };

  const onReset = () => {
    setDraft(cloneDefault());
    setSavedAt(null);
  };

  const onSave = () => {
    if (!draft) return;
    save.mutate(reindexLayout(draft), {
      onSuccess: () => setSavedAt(Date.now()),
    });
  };

  const dirty = useMemo(() => {
    if (!draft || !query.data) return false;
    return JSON.stringify(draft) !== JSON.stringify(query.data);
  }, [draft, query.data]);

  const body = (() => {
    if (query.isLoading && !draft) {
      return <div style={loadingBox}>loading layout&hellip;</div>;
    }
    if (query.isError && !draft) {
      return <div style={loadingBox}>failed to load widget layout</div>;
    }
    if (!draft) {
      return <div style={loadingBox}>&nbsp;</div>;
    }
    return (
      <div style={scrollStyle}>
        <p style={blurbStyle}>
          Widgets dock around the chat panel as always-on-top floaters. This editor controls which kinds
          show and their stacking order. Reorder with the up/down buttons; uncheck a row to hide it.
          Layout persists per user.
        </p>
        <div style={listStyle}>
          {rows.map((entry, i) => {
            const cat = WIDGET_CATALOG[entry.kind];
            const cellStyle = i === rows.length - 1 ? rowLastStyle : rowStyle;
            const upDisabled = i === 0;
            const downDisabled = i === rows.length - 1;
            return (
              <div key={entry.id} style={cellStyle}>
                <input
                  type="checkbox"
                  checked={!entry.hidden}
                  onChange={() => toggleHidden(entry.id)}
                  style={checkStyle}
                  aria-label={`show ${cat?.title ?? entry.kind}`}
                />
                <div style={nameStyle}>
                  <span style={nameTitleStyle}>{cat?.title ?? entry.kind}</span>
                  <span style={nameMetaStyle}>
                    {entry.kind} &middot; {entry.side}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => move(i, -1)}
                  disabled={upDisabled}
                  style={upDisabled ? arrowBtnDisabled : arrowBtnStyle}
                  title="move up"
                  aria-label="move up"
                >
                  {"\u2191"}
                </button>
                <button
                  type="button"
                  onClick={() => move(i, 1)}
                  disabled={downDisabled}
                  style={downDisabled ? arrowBtnDisabled : arrowBtnStyle}
                  title="move down"
                  aria-label="move down"
                >
                  {"\u2193"}
                </button>
              </div>
            );
          })}
        </div>
        <div style={actionsRowStyle}>
          <button
            type="button"
            onClick={onSave}
            disabled={save.isPending || !dirty}
            style={save.isPending || !dirty ? btnPrimaryDisabled : btnPrimary}
          >
            {save.isPending ? "saving\u2026" : "save"}
          </button>
          <button type="button" onClick={onReset} style={btnGhost}>
            reset to default
          </button>
          <span style={{ flex: 1 }} />
          {save.isError ? <span style={statusErr}>save failed</span> : null}
          {savedAt && !save.isPending && !save.isError ? <span style={statusOk}>saved</span> : null}
          {dirty && !save.isPending && !save.isError && !savedAt ? (
            <span style={statusMuted}>unsaved changes</span>
          ) : null}
        </div>
      </div>
    );
  })();

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={title}
      isFocused={isFocused}
      isFullscreen={isFullscreen}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
    >
      <div style={bodyStyle}>
        <header style={headerStyle}>
          <span style={dotStyle} />
          <span style={titleStyle}>admin &middot; widget layout</span>
          <span style={subtitleStyle}>chat-panel floaters &mdash; visibility and order</span>
        </header>
        {body}
      </div>
    </ConsoleWindow>
  );
}

function reindexLayout(layout: WidgetLayout): WidgetLayout {
  return { version: 1, widgets: reindex(layout.widgets) };
}
