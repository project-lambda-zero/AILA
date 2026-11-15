import { useQuery } from "@tanstack/react-query";
import { type CSSProperties, type FormEvent, useState } from "react";

import { listOidcProviders, startOidcSignIn, useAuth } from "../api/auth";
import { FaultyTerminal } from "../desktop/FaultyTerminal";

const inputStyle: CSSProperties = {
  display: "block",
  width: "100%",
  marginTop: 4,
  height: 32,
  padding: "0 10px",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: "var(--radius-sm)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  fontSize: 13,
  outline: "none",
};

const labelStyle: CSSProperties = {
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "0.1em",
  color: "var(--text-muted)",
};

const dividerStyle: CSSProperties = {
  fontSize: 10,
  textTransform: "uppercase",
  letterSpacing: "0.14em",
  color: "var(--text-faint)",
  textAlign: "center",
};

const oidcButtonStyle: CSSProperties = {
  height: 34,
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-sm)",
  fontSize: 12,
  textTransform: "uppercase",
  letterSpacing: "0.1em",
};

export default function Login() {
  const login = useAuth((s) => s.login);
  const busy = useAuth((s) => s.busy);
  const error = useAuth((s) => s.error);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const providersQuery = useQuery({
    queryKey: ["oidc-providers"],
    queryFn: listOidcProviders,
    retry: false,
  });
  const providers = providersQuery.data ?? [];

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) return;
    void login(username, password);
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "var(--surface-page)",
        fontFamily: "var(--font-mono)",
      }}
    >
      <FaultyTerminal />
      <form
        onSubmit={submit}
        style={{
          position: "relative",
          zIndex: 10,
          width: 340,
          background: "var(--surface-card)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-md)",
          boxShadow: "var(--shadow-window)",
          padding: 24,
          display: "flex",
          flexDirection: "column",
          gap: 14,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ width: 12, height: 12, background: "var(--accent)", boxShadow: "0 0 10px var(--accent)" }} />
          <span
            style={{
              fontFamily: "var(--font-display)",
              fontSize: 24,
              color: "var(--text-primary)",
              letterSpacing: "0.04em",
            }}
          >
            AILA
          </span>
        </div>
        <div style={{ fontSize: 11, letterSpacing: "0.14em", textTransform: "uppercase", color: "var(--text-faint)" }}>
          ai lab assistant -- console
        </div>
        <label style={labelStyle}>
          username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            style={inputStyle}
          />
        </label>
        <label style={labelStyle}>
          password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            style={inputStyle}
          />
        </label>
        {error ? <div style={{ fontSize: 11, color: "var(--accent)" }}>{error}</div> : null}
        <button
          type="submit"
          disabled={busy}
          style={{
            marginTop: 4,
            height: 34,
            background: "var(--accent)",
            color: "var(--text-on-accent)",
            border: 0,
            borderRadius: "var(--radius-sm)",
            fontSize: 12,
            textTransform: "uppercase",
            letterSpacing: "0.1em",
            fontWeight: 700,
            cursor: busy ? "default" : "pointer",
            opacity: busy ? 0.6 : 1,
          }}
        >
          {busy ? "signing in..." : "sign in"}
        </button>
        {providers.length > 0 ? (
          <>
            <div style={dividerStyle}>or</div>
            {providers.map((provider) => (
              <button
                key={provider.id}
                type="button"
                disabled={busy}
                onClick={() => void startOidcSignIn(provider.id)}
                style={{ ...oidcButtonStyle, cursor: busy ? "default" : "pointer", opacity: busy ? 0.6 : 1 }}
              >
                sign in with {provider.name}
              </button>
            ))}
          </>
        ) : null}
      </form>
    </div>
  );
}
