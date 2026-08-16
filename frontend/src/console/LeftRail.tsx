import { Fragment, useMemo, useState } from "react";
import type { MouseEvent, ReactElement } from "react";

import { useForensicsProjects } from "../api/forensicsRail";
import type { RailRow } from "../api/forensicsRail";
import { useInvestigations } from "../api/hooks";
import { useMalwareInvestigations } from "../api/malwareHooks";
import type { LeftRailProps } from "./contract";
import { css } from "./css";
import { shortCaseId } from "./ids";
import { ADMIN_CATS, MODULES } from "./nav";

/** Literal accent hex, mirrors --accent (#ff5f87). Needed where the mock
 * concatenates an alpha suffix onto the color (T.acc+"66"), which var()
 * refs cannot express in a raw CSS declaration. */
const ACCENT_HEX_A66 = "#ff5f8766";
const ACCENT_HEX_A73 = "#ff5f8773";

function toneForStatus(status: string | undefined | null): string {
  const s = (status ?? "").toLowerCase();
  if (s === "running" || s === "active") return "var(--status-ok)";
  if (s === "review" || s === "triage") return "var(--status-info)";
  if (s === "completed" || s === "shipped" || s === "resolved" || s === "done") {
    return "var(--text-faint)";
  }
  if (s === "failed" || s === "paused") return "var(--status-warn)";
  return "var(--text-faint)";
}

export default function LeftRail(props: LeftRailProps): ReactElement {
  const {
    moduleId,
    onSelectModule,
    bound,
    onBind,
    pagesOpen,
    onTogglePages,
    adminOpen,
    onToggleAdmin,
    onOpenIntake,
    onOpenSettings,
    onOpenPage,
  } = props;

  const activeModule = MODULES.find((m) => m.id === moduleId) ?? MODULES[0];
  // Every hook runs unconditionally so hook order is stable across module
  // switches; a per-module `source` selection below picks which one drives
  // the rail. The vulnerability module has no per-case list endpoint --
  // it renders an honest empty state instead of borrowing VR data.
  const vrInvestigations = useInvestigations();
  const malwareInvestigations = useMalwareInvestigations();
  const forensicsProjects = useForensicsProjects();

  const source: { data?: RailRow[]; isLoading: boolean; isError: boolean } =
    moduleId === "malware"
      ? malwareInvestigations
      : moduleId === "forensics"
        ? forensicsProjects
        : moduleId === "vulnerability"
          ? { data: [], isLoading: false, isError: false }
          : vrInvestigations;

  const [pinned, setPinned] = useState<string[]>([]);

  const rows: RailRow[] = useMemo(() => {
    const raw = source.data ?? [];
    // Pinned / favorite first, then by activity (branches weigh heavily, then
    // messages) so the data-rich investigations surface at the top -- clicking
    // one opens a full X-Ray rather than an empty case. For forensics, the
    // hook synthesises branch_count/message_count from evidence + investigation
    // + lead counts so the busiest projects sort to the top.
    const score = (v: RailRow): number =>
      (v.branch_count ?? 0) * 1000 + (v.message_count ?? 0);
    return raw
      .slice()
      .sort((a, b) => {
        const ap = pinned.includes(a.id) || a.is_favorite ? 1 : 0;
        const bp = pinned.includes(b.id) || b.is_favorite ? 1 : 0;
        if (ap !== bp) return bp - ap;
        return score(b) - score(a);
      })
      .slice(0, 40);
  }, [source.data, pinned]);

  // Per-module honest empty-state copy. Vulnerability has no case list; the
  // scan/findings/systems windows opened from the PAGES section above are the
  // real workflow.
  const emptyLabel =
    moduleId === "vulnerability"
      ? "no advisories -- use the pages above"
      : moduleId === "forensics"
        ? "no cases yet"
        : moduleId === "malware"
          ? "no reports yet"
          : "no investigations yet";

  return (
    <aside
      style={css(
        `height:100%;display:flex;flex-direction:column;overflow:hidden;background:color-mix(in srgb,var(--surface-card) 72%,transparent);border-right:1px solid var(--border-soft);`,
      )}
    >
      {/* 1. module header */}
      <div
        style={css(
          `flex:0 0 auto;padding:9px 11px;border-bottom:1px solid var(--border-soft);display:flex;align-items:center;gap:8px;`,
        )}
      >
        <span
          style={css(
            `font-size:9px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-muted);`,
          )}
        >
          module
        </span>
      </div>

      {/* 2. modules */}
      <div style={css(`flex:0 0 auto;display:flex;flex-direction:column;`)}>
        {MODULES.map((m) => {
          const on = m.id === moduleId;
          const dot = css(
            `width:7px;height:7px;flex:0 0 auto;background:${on ? "var(--accent)" : "var(--text-faint)"};${on ? "box-shadow:0 0 7px var(--accent);" : ""}`,
          );
          const style = css(
            `display:flex;align-items:center;gap:8px;padding:7px 11px;border:0;border-left:2px solid ${on ? "var(--accent)" : "transparent"};background:${on ? "color-mix(in srgb,var(--accent) 8%,transparent)" : "transparent"};color:${on ? "var(--text-primary)" : "var(--text-muted)"};font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.06em;text-align:left;cursor:pointer;width:100%;`,
          );
          return (
            <button key={m.id} type="button" onClick={() => onSelectModule(m.id)} style={style}>
              <span style={dot} />
              {m.id}
            </button>
          );
        })}
      </div>

      {/* 3. collapsible pages (only when the module has pages, mirroring the mock) */}
      {activeModule.pages.length > 0 ? (
        <div
          style={css(
            `flex:0 0 auto;max-height:190px;display:flex;flex-direction:column;min-height:0;border-top:1px solid var(--border-soft);`,
          )}
        >
          <button
            type="button"
            onClick={onTogglePages}
            style={css(
              `display:flex;align-items:center;gap:7px;width:100%;padding:10px 11px 6px;background:transparent;border:0;cursor:pointer;font-family:var(--font-mono);font-size:9px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-muted);`,
            )}
          >
            <span style={css(`color:var(--accent);font-size:8px;`)}>{pagesOpen ? "\u25bc" : "\u25b6"}</span>
            pages
          </button>
          <div
            style={css(
              `max-height:150px;overflow:auto;flex-direction:column;padding:0 7px 6px;gap:2px;display:${pagesOpen ? "flex" : "none"};`,
            )}
          >
            {activeModule.pages.map((p) => {
              // Every page now resolves to a real window (a DataPage or a
              // bespoke screen), so all page rows are clickable.
              const enabled = true;
              const style = css(
                `display:flex;align-items:center;gap:8px;padding:6px 8px;border-radius:2px;font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.03em;color:${enabled ? "var(--text-muted)" : "var(--text-faint)"};text-align:left;text-decoration:none;border:1px solid transparent;background:var(--surface-card);cursor:${enabled ? "pointer" : "default"};opacity:${enabled ? "1" : "0.55"};`,
              );
              return (
                <button
                  key={p.id}
                  type="button"
                  disabled={!enabled}
                  onClick={
                    enabled
                      ? () => {
                          const section = p.href ? p.href.split("#")[1] ?? p.id : p.id;
                          onOpenPage(activeModule.id, section, p.label);
                        }
                      : undefined
                  }
                  style={style}
                >
                  <span
                    style={css(
                      `width:5px;height:5px;flex:0 0 auto;background:${enabled ? "var(--accent)" : "var(--text-faint)"};`,
                    )}
                  />
                  {p.label}
                </button>
              );
            })}
          </div>
        </div>
      ) : null}

      {/* 4. investigations / advisories / cases / reports header */}
      <div
        style={css(
          `flex:0 0 auto;padding:11px 11px 5px;display:flex;align-items:center;gap:8px;border-top:1px solid var(--border-soft);`,
        )}
      >
        <span
          style={css(
            `font-size:9px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-muted);`,
          )}
        >
          {activeModule.noun}
        </span>
        <span style={css(`flex:1;`)} />
        <span
          onClick={onOpenIntake}
          style={css(
            `border:1px solid var(--border);padding:0 5px;font-size:12px;color:var(--accent);cursor:pointer;`,
          )}
        >
          +
        </span>
      </div>

      {/* 5. investigation list */}
      <div
        style={css(
          `flex:1;min-height:0;overflow:auto;padding:0 7px 7px;display:flex;flex-direction:column;gap:5px;`,
        )}
      >
        {source.isLoading ? (
          <div
            style={css(
              `padding:8px;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);letter-spacing:0.04em;`,
            )}
          >
            loading...
          </div>
        ) : source.isError ? (
          <div
            style={css(
              `padding:8px;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);letter-spacing:0.04em;`,
            )}
          >
            unavailable
          </div>
        ) : rows.length === 0 ? (
          <div
            style={css(
              `padding:8px;font-family:var(--font-mono);font-size:10px;color:var(--text-faint);letter-spacing:0.04em;`,
            )}
          >
            {emptyLabel}
          </div>
        ) : (
          rows.map((inv) => {
            const isPinned = pinned.includes(inv.id) || Boolean(inv.is_favorite);
            const isActive = bound?.id === inv.id;
            const tone = toneForStatus(inv.status);
            const borderColor = isPinned
              ? ACCENT_HEX_A73
              : isActive
                ? ACCENT_HEX_A66
                : "var(--border-soft)";
            const bg = isPinned || isActive
              ? "color-mix(in srgb,var(--accent) 7%,transparent)"
              : "var(--surface-card)";
            const rowStyle = css(
              `padding:6px 8px;border:1px solid ${borderColor};background:${bg};border-radius:2px;cursor:pointer;`,
            );
            const dot = css(
              `width:7px;height:7px;flex:0 0 auto;border-radius:1px;background:${tone};`,
            );
            const pinStyle = css(
              `flex:0 0 auto;font-size:8px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;padding:0 3px;border:1px solid ${isPinned ? ACCENT_HEX_A66 : "transparent"};color:${isPinned ? "var(--accent)" : "var(--text-faint)"};border-radius:2px;`,
            );
            const stateStyle = css(
              `font-size:8.5px;letter-spacing:0.08em;text-transform:uppercase;color:${tone};`,
            );
            return (
              <div
                key={inv.id}
                onClick={() => onBind({ id: inv.id, title: inv.title })}
                style={rowStyle}
              >
                <div style={css(`display:flex;align-items:center;gap:7px;`)}>
                  <span style={dot} />
                  <span
                    style={css(
                      `font-size:10.5px;color:var(--text-primary);letter-spacing:0.04em;white-space:nowrap;`,
                    )}
                  >
                    {shortCaseId(activeModule.id, inv.id)}
                  </span>
                  <span style={css(`flex:1;`)} />
                  <span
                    onClick={(e: MouseEvent<HTMLSpanElement>) => {
                      e.stopPropagation();
                      setPinned((prev) =>
                        prev.includes(inv.id)
                          ? prev.filter((x) => x !== inv.id)
                          : [...prev, inv.id],
                      );
                    }}
                    style={pinStyle}
                  >
                    {isPinned ? "\u25c6 pin" : "\u25c7"}
                  </span>
                  <span style={stateStyle}>{(inv.status ?? "").toUpperCase()}</span>
                </div>
                <div
                  style={css(
                    `margin-top:3px;font-size:9.5px;color:var(--text-faint);letter-spacing:0.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;`,
                  )}
                >
                  {inv.title}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* 6. collapsible admin settings */}
      <div style={css(`flex:0 0 auto;max-height:230px;display:flex;flex-direction:column;min-height:0;`)}>
        <button
          type="button"
          onClick={onToggleAdmin}
          style={css(
            `display:flex;align-items:center;gap:7px;width:100%;padding:9px 11px;background:var(--surface-chrome);border:0;border-top:1px solid var(--border-soft);cursor:pointer;font-family:var(--font-mono);font-size:9px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-muted);`,
          )}
        >
          <span style={css(`color:var(--accent);font-size:8px;`)}>{adminOpen ? "\u25bc" : "\u25b6"}</span>
          admin settings
        </button>
        <div
          style={css(
            `max-height:190px;overflow:auto;flex-direction:column;padding:0 7px 7px;gap:2px;display:${adminOpen ? "flex" : "none"};`,
          )}
        >
          {ADMIN_CATS.map((g) => (
            <Fragment key={g.cat}>
              <div
                style={css(
                  `padding:7px 9px 3px;font-size:8px;letter-spacing:0.18em;text-transform:uppercase;color:var(--accent);`,
                )}
              >
                {g.cat}
              </div>
              {g.items.map((label) => (
                <button
                  key={`${g.cat}:${label}`}
                  type="button"
                  onClick={() => onOpenPage("admin", label.replace(/\s+/g, "-"), label)}
                  style={css(
                    `display:flex;align-items:center;gap:8px;padding:5px 8px;border:0;border-radius:2px;background:var(--surface-card);font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.03em;color:var(--text-muted);cursor:pointer;text-align:left;`,
                  )}
                >
                  <span
                    style={css(`width:5px;height:5px;flex:0 0 auto;background:var(--text-faint);`)}
                  />
                  {label}
                </button>
              ))}
            </Fragment>
          ))}
        </div>
      </div>

      {/* 7. user settings */}
      <button
        type="button"
        onClick={onOpenSettings}
        style={css(
          `display:flex;align-items:center;gap:7px;width:100%;flex:0 0 auto;padding:9px 11px;border:0;border-top:1px solid var(--border-soft);background:var(--surface-chrome);color:var(--text-muted);font-family:var(--font-mono);font-size:9px;letter-spacing:0.16em;text-transform:uppercase;cursor:pointer;`,
        )}
      >
        <span style={css(`color:var(--accent);`)}>{"\u2699"}</span>
        user settings
      </button>
    </aside>
  );
}
