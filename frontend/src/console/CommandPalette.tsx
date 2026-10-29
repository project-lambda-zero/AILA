/** Global Ctrl/Cmd+K command palette (#212): jump to any nav page (module
 * pages + every admin settings entry) or open the global search window.
 * Registered in the bubble phase so capture-phase handlers that already ran
 * (the X-Ray palettes, which preventDefault Ctrl+K) keep ownership of the
 * shortcut inside their windows; this palette only fires on unhandled events. */
import { useEffect, useMemo, useRef, useState } from "react";
import type { JSX } from "react";

import { css } from "./css";
import { ADMIN_CATS, MODULES } from "./nav";

interface Command {
  key: string;
  label: string;
  hint: string;
  run: () => void;
}

const MONO = "font-family:var(--font-mono);";
const FAINT = "color:var(--text-faint);";

function isEditableTarget(tgt: EventTarget | null): boolean {
  return (
    tgt instanceof HTMLInputElement ||
    tgt instanceof HTMLTextAreaElement ||
    tgt instanceof HTMLSelectElement ||
    (tgt instanceof HTMLElement && tgt.isContentEditable)
  );
}

export default function CommandPalette({ onNavigate }: { onNavigate: (moduleKey: string, section: string, label: string) => void }): JSX.Element | null {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
        if (e.defaultPrevented || isEditableTarget(e.target)) return;
        e.preventDefault();
        setOpen((o) => {
          if (!o) {
            setQuery("");
            setSel(0);
          }
          return !o;
        });
      } else if (e.key === "Escape") {
        if (!open || e.defaultPrevented) return;
        e.preventDefault();
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  const commands = useMemo<Command[]>(() => {
    const out: Command[] = [
      {
        key: "search",
        label: "open global search",
        hint: "admin",
        run: () => onNavigate("admin", "global-search", "global search"),
      },
    ];
    for (const m of MODULES) {
      for (const p of m.pages) {
        if (p.href) continue;
        out.push({ key: `${m.id}:${p.id}`, label: p.label, hint: m.label, run: () => onNavigate(m.id, p.id, p.label) });
      }
    }
    for (const g of ADMIN_CATS) {
      for (const item of g.items) {
        out.push({ key: `admin:${item}`, label: item, hint: `admin · ${g.cat}`, run: () => onNavigate("admin", item.replace(/\s+/g, "-"), item) });
      }
    }
    return out;
  }, [onNavigate]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (q === "") return commands;
    return commands.filter((c) => c.label.toLowerCase().includes(q) || c.hint.toLowerCase().includes(q));
  }, [commands, query]);

  if (!open) return null;

  const pick = (c: Command): void => {
    setOpen(false);
    c.run();
  };

  return (
    <div
      role="dialog"
      aria-label="command palette"
      style={css("position:fixed;inset:0;z-index:1000;background:color-mix(in srgb,var(--surface-chrome) 55%,transparent);display:flex;justify-content:center;padding-top:12vh;")}
      onClick={() => setOpen(false)}
    >
      <div
        style={css("width:min(560px,90vw);height:fit-content;background:var(--surface-card);border:1px solid var(--border);border-radius:4px;box-shadow:var(--bevel-raised);display:flex;flex-direction:column;overflow:hidden;")}
        onClick={(e) => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setSel(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setSel((s) => Math.min(filtered.length - 1, s + 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setSel((s) => Math.max(0, s - 1));
            } else if (e.key === "Enter") {
              e.preventDefault();
              const c = filtered[sel];
              if (c) pick(c);
            }
          }}
          placeholder="jump to a page or action"
          style={css("border:0;border-bottom:1px solid var(--border-soft);background:transparent;padding:10px 12px;font-family:var(--font-mono);font-size:12px;color:var(--text-primary);outline:none;")}
        />
        <div style={css("max-height:320px;overflow:auto;display:flex;flex-direction:column;")}>
          {filtered.length === 0 ? (
            <div style={css(FAINT + MONO + "font-size:11px;padding:10px 12px;")}>no matching page</div>
          ) : (
            filtered.map((c, i) => (
              <button
                key={c.key}
                type="button"
                onMouseEnter={() => setSel(i)}
                onClick={() => pick(c)}
                style={css(
                  `display:flex;align-items:baseline;gap:10px;text-align:left;border:0;padding:7px 12px;cursor:pointer;font-family:var(--font-mono);font-size:11.5px;${i === sel ? "background:color-mix(in srgb,var(--accent) 12%,transparent);color:var(--text-primary);" : "background:transparent;color:var(--text-muted);"}`,
                )}
              >
                <span style={css("flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{c.label}</span>
                <span style={css(FAINT + "font-size:11px;flex:0 0 auto;")}>{c.hint}</span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
