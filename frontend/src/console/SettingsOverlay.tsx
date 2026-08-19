import { useState } from "react";
import { useAuth } from "../api/auth";
import { THEMES, applyTheme, loadTheme } from "../theme";
import type { SettingsOverlayProps } from "./contract";
import { css } from "./css";

/**
 * User settings overlay. Ported from AILA Console.dc.html (raw lines 118-160
 * for JSX). All inline styles copied through the css() helper. The theme list
 * and switching live in ../theme; selecting a card applies + persists the theme.
 */

export default function SettingsOverlay(props: SettingsOverlayProps) {
  const { user, onClose, onOpenPage } = props;
  const logout = useAuth((s) => s.logout);
  const [theme, setTheme] = useState<string>(() => loadTheme());

  const username = user?.username ?? "admin";
  const role = user?.role ?? "Admin";
  const userId = user?.id ?? "--";

  return (
    <div
      style={css(
        `position:absolute;inset:0;z-index:16;overflow:auto;background:var(--surface-page);display:block;`,
      )}
    >
      <button
        type="button"
        onClick={onClose}
        title="close"
        style={css(
          `position:absolute;top:10px;right:14px;z-index:2;width:24px;height:24px;display:flex;align-items:center;justify-content:center;background:var(--surface-chrome);border:1px solid var(--border-soft);color:var(--text-muted);font-family:var(--font-mono);font-size:12px;cursor:pointer;border-radius:3px;`,
        )}
      >
        ✕
      </button>
      <div
        style={css(
          `max-width:760px;margin:0 auto;padding:22px 20px;display:flex;flex-direction:column;gap:15px;`,
        )}
      >
        {/* Profile ---------------------------------------------------------- */}
        <div
          style={css(
            `display:flex;align-items:center;gap:8px;color:var(--accent);font-size:13px;`,
          )}
        >
          <span>◔</span>
          <span style={css(`font-weight:700;`)}>Profile</span>
        </div>
        <div
          style={css(
            `border:1px solid var(--border);background:var(--surface-card);border-radius:4px;padding:14px 16px;`,
          )}
        >
          <div
            style={css(
              `display:flex;align-items:center;padding:8px 0;border-bottom:1px solid var(--border-faint);`,
            )}
          >
            <span style={css(`font-size:12px;color:var(--text-muted);`)}>Username</span>
            <span style={css(`flex:1;`)}></span>
            <span style={css(`font-size:12px;color:var(--text-primary);`)}>{username}</span>
          </div>
          <div
            style={css(
              `display:flex;align-items:center;padding:8px 0;border-bottom:1px solid var(--border-faint);`,
            )}
          >
            <span style={css(`font-size:12px;color:var(--text-muted);`)}>Role</span>
            <span style={css(`flex:1;`)}></span>
            <span
              style={css(
                `font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:var(--accent);border:1px solid color-mix(in srgb,var(--accent) 40%,transparent);background:color-mix(in srgb,var(--accent) 14%,transparent);padding:2px 8px;border-radius:10px;`,
              )}
            >
              {role}
            </span>
          </div>
          <div style={css(`display:flex;align-items:center;padding:8px 0;`)}>
            <span style={css(`font-size:12px;color:var(--text-muted);`)}>User ID</span>
            <span style={css(`flex:1;`)}></span>
            <span style={css(`font-size:11px;color:var(--text-faint);`)}>{userId}</span>
          </div>
          <div style={css(`margin-top:8px;font-size:11px;color:var(--text-faint);`)}>
            Contact your administrator to change your role or username.
          </div>
        </div>

        {/* Sessions --------------------------------------------------------- */}
        <div
          style={css(
            `display:flex;align-items:center;gap:8px;color:var(--accent);font-size:13px;`,
          )}
        >
          <span>▭</span>
          <span style={css(`font-weight:700;`)}>Sessions</span>
        </div>
        <div
          style={css(
            `border:1px solid var(--border);background:var(--surface-card);border-radius:4px;padding:14px 16px;`,
          )}
        >
          <div style={css(`font-size:12px;color:var(--text-muted);line-height:1.5;`)}>
            Review and revoke active login sessions across all your devices.
          </div>
          <div style={css(`margin-top:10px;display:flex;align-items:center;gap:16px;`)}>
            <button
              type="button"
              onClick={() => {
                onClose();
                onOpenPage?.("admin", "sessions", "admin · sessions");
              }}
              style={css(
                `font-family:var(--font-mono);font-size:12px;color:var(--accent);background:transparent;border:0;padding:0;cursor:pointer;text-align:left;`,
              )}
            >
              manage active sessions →
            </button>
            <button
              type="button"
              onClick={() => logout()}
              style={css(
                `font-family:var(--font-mono);font-size:12px;color:var(--accent);background:transparent;border:0;padding:0;cursor:pointer;`,
              )}
            >
              sign out →
            </button>
          </div>
        </div>

        {/* Appearance ------------------------------------------------------- */}
        <div
          style={css(
            `display:flex;align-items:center;gap:8px;color:var(--accent);font-size:13px;`,
          )}
        >
          <span>◈</span>
          <span style={css(`font-weight:700;`)}>Appearance</span>
        </div>
        <div
          style={css(
            `border:1px solid var(--border);background:var(--surface-card);border-radius:4px;padding:14px 16px;`,
          )}
        >
          <div style={css(`display:flex;align-items:center;`)}>
            <span style={css(`font-size:11px;color:var(--text-muted);`)}>
              Twelve themes. Each its own era. Click a preview to switch.
            </span>
          </div>
          <div
            style={css(
              `margin-top:12px;display:grid;grid-template-columns:repeat(3,1fr);gap:10px;`,
            )}
          >
            {THEMES.map((t) => {
              const [name, sub, mode, gradient] = t;
              const selected = theme === name;
              const cardStyle = selected
                ? `border:1px solid var(--accent);background:var(--surface-sunk);border-radius:3px;overflow:hidden;cursor:pointer;box-shadow:0 0 0 1px color-mix(in srgb,var(--accent) 33%,transparent);`
                : `border:1px solid var(--border-soft);background:var(--surface-sunk);border-radius:3px;overflow:hidden;cursor:pointer;`;
              const swatch = `height:60px;display:flex;align-items:flex-start;padding:8px 9px;background:${gradient};`;
              const tagStyle = selected
                ? `font-size:8px;letter-spacing:0.06em;text-transform:uppercase;color:var(--status-ok);`
                : `font-size:8px;letter-spacing:0.06em;text-transform:uppercase;color:transparent;`;
              return (
                <div
                  key={name}
                  onClick={() => {
                    setTheme(name);
                    applyTheme(name);
                  }}
                  style={css(cardStyle)}
                >
                  <div style={css(swatch)}>
                    <span
                      style={css(
                        `font-family:var(--font-mono);font-size:9px;letter-spacing:0.1em;color:#fff;text-shadow:0 1px 3px rgba(0,0,0,0.6);`,
                      )}
                    >
                      AILA
                    </span>
                  </div>
                  <div style={css(`padding:8px 9px;`)}>
                    <div style={css(`display:flex;align-items:center;gap:6px;`)}>
                      <span style={css(`font-size:11px;color:var(--text-primary);`)}>{name}</span>
                      <span style={css(`flex:1;`)}></span>
                      <span style={css(tagStyle)}>{selected ? "✓ active" : ""}</span>
                    </div>
                    <div
                      style={css(
                        `margin-top:3px;font-size:9.5px;color:var(--text-faint);line-height:1.35;`,
                      )}
                    >
                      {sub}
                    </div>
                    <div
                      style={css(
                        `margin-top:5px;font-size:8px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);`,
                      )}
                    >
                      natural mode · {mode}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
