/**
 * KnowledgePage -- bespoke admin window over the platform RAG corpus
 * (KnowledgeEntryRecord + KnowledgeEntryEdge).
 *
 * Three panels, all backed by real endpoints, honest empty/loading/error:
 *   SEARCH          POST /platform/knowledge/search   (mutation)
 *   CORPUS STATS    GET  /platform/knowledge/stats    (query)
 *   ENTRIES BROWSER GET  /platform/knowledge/entries  (paged query)
 *
 * The panels live under ./knowledge/. Structured metadata renders via
 * <StructuredValue>, never as a raw JSON blob. Follows the DataPage
 * window-chrome convention: absolute-fill body + a footer strip that carries
 * the min / fullscreen / close controls the shell wired through
 * ModulePageProps.
 */

import { useState } from "react";
import type { JSX } from "react";

import type { WindowChromeProps } from "../contract";
import { ConsoleWindow } from "../window";
import { EntriesPanel } from "./knowledge/EntriesPanel";
import { IngestModal } from "./knowledge/IngestModal";
import { SearchPanel } from "./knowledge/SearchPanel";
import { StatsPanel } from "./knowledge/StatsPanel";
import { headerBtn, twoUp } from "./knowledge/styles";

export default function KnowledgePage(props: WindowChromeProps): JSX.Element {
  const {
    onBack,
    onMinimize,
    isFullscreen,
    onToggleFullscreen,
    windowId,
    title,
    isFocused,
    onFocus,
  } = props;
  const [ingestOpen, setIngestOpen] = useState(false);

  const statusStrip = (
    <>
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
        admin &middot; knowledge
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
        KnowledgeEntryRecord &middot; KnowledgeEntryEdge &middot; retrieve_routed
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
      {ingestOpen ? <IngestModal onClose={() => setIngestOpen(false)} /> : null}
      <header
        style={{
          flex: "0 0 auto",
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "8px 14px",
          background: "var(--surface-chrome)",
          borderBottom: "1px solid var(--border)",
          fontSize: 11,
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
        <span style={{ fontFamily: "var(--font-display)", color: "var(--text-primary)", fontWeight: 400, letterSpacing: "0.16em" }}>
          admin &middot; knowledge
        </span>
        <span style={{ color: "var(--text-faint)", textTransform: "none", letterSpacing: "0.04em" }}>
          platform RAG corpus &mdash; entries, retrieval, edges
        </span>
        <span style={{ flex: 1 }} />
        <button type="button" style={headerBtn} onClick={() => setIngestOpen(true)}>
          + operator note
        </button>
      </header>

      <main
        style={{
          flex: 1,
          minHeight: 0,
          display: "grid",
          gridTemplateRows: "minmax(260px,42%) minmax(260px,58%)",
          gap: 10,
          padding: 12,
        }}
      >
        <div style={twoUp}>
          <SearchPanel />
          <StatsPanel />
        </div>
        <EntriesPanel />
      </main>

    </ConsoleWindow>
  );
}
