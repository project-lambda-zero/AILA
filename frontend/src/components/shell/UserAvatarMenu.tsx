/**
 * UserAvatarMenu -- header user chip + OS-window dropdown.
 *
 * Composes the mock kit: raw <button> trigger with a 28x28 mono initial
 * square, absolute-positioned dropdown panel wrapped in <WindowPanel>,
 * MonoBadge for the role. No shadcn primitives.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { SignOut } from "@phosphor-icons/react/dist/csr/SignOut";
import { User } from "@phosphor-icons/react/dist/csr/User";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { MonoBadge } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

const MENU_ITEM_STYLE: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 8,
  width: "100%",
  height: 28,
  padding: "0 10px",
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  letterSpacing: "0.04em",
  color: "var(--text-primary)",
  background: "transparent",
  border: 0,
  cursor: "pointer",
  textAlign: "left",
};

export function UserAvatarMenu() {
  const { username, role, logout } = useAuthStore();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);

  const handleSignOut = useCallback(() => {
    setOpen(false);
    logout();
    navigate("/login");
  }, [logout, navigate]);

  const handleSettings = useCallback(() => {
    setOpen(false);
    navigate("/settings");
  }, [navigate]);

  // Click outside + Escape dismiss.
  useEffect(() => {
    if (!open) return;
    function onDown(event: MouseEvent) {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(event.target as Node)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const initials = username ? username.charAt(0).toUpperCase() : "?";

  return (
    <div ref={rootRef} style={{ position: "relative", display: "inline-flex" }}>
      <button
        type="button"
        aria-label="User menu"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((prev) => !prev)}
        className="touch-target flex items-center justify-center font-mono"
        style={{
          width: 28,
          height: 28,
          padding: 0,
          fontSize: 12,
          fontWeight: 600,
          letterSpacing: "0.04em",
          color: "var(--text-primary)",
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-soft)",
          borderRadius: 3,
          cursor: "pointer",
        }}
      >
        {initials}
      </button>

      {open && (
        <div
          role="menu"
          style={{
            position: "absolute",
            top: "calc(100% + 6px)",
            right: 0,
            zIndex: 60,
            width: 240,
          }}
        >
          <WindowPanel title="account" tone="muted" flush>
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: 4,
                padding: "10px 10px 8px 10px",
                borderBottom: "1px solid var(--border-faint)",
              }}
            >
              <span
                className="font-mono"
                style={{
                  fontSize: 11,
                  color: "var(--text-primary)",
                  letterSpacing: "0.02em",
                }}
              >
                {username ?? "Unknown"}
              </span>
              <span style={{ display: "inline-flex" }}>
                <MonoBadge tone="muted">{role ?? "\u2014"}</MonoBadge>
              </span>
            </div>

            <div style={{ display: "flex", flexDirection: "column", padding: "4px 0" }}>
              <button
                type="button"
                role="menuitem"
                onClick={handleSettings}
                style={MENU_ITEM_STYLE}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "var(--surface-hover)";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "transparent";
                }}
              >
                <User size={14} />
                <span>Profile &amp; Settings</span>
              </button>
              <button
                type="button"
                role="menuitem"
                onClick={handleSignOut}
                style={{ ...MENU_ITEM_STYLE, color: "var(--status-warn)" }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "var(--surface-hover)";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "transparent";
                }}
              >
                <SignOut size={14} />
                <span>Sign out</span>
              </button>
            </div>
          </WindowPanel>
        </div>
      )}
    </div>
  );
}
