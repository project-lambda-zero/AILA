/**
 * SystemForm -- typed create / edit modal for a registered SSH system.
 *
 * Bound to the exact SystemCreateRequest / SystemUpdateRequest field spec:
 *   name         text     required (min 1, max 128)
 *   host         text     required
 *   username     text     default 'root'
 *   port         number   1..65535, default 22
 *   distro       select   default 'unknown'  (ubuntu|debian|arch|rhel|alpine|unknown)
 *   description  textarea default ''
 *   private_key  textarea PEM (optional; encrypted via SecretRecord)
 *   password     password (optional; encrypted)
 *   private_key_passphrase password (optional; encrypted)
 *
 * Every request body carries ONLY declared keys (server has extra="forbid").
 * On PUT, empty secret fields are omitted so the existing secret is
 * preserved; explicit "clear" buttons send null.
 *
 * Deletion is a separate red action inside the edit form -- confirmed inline.
 *
 * The form body renders inside the shared WizardShell as one step so the
 * operator gets the guided chrome + invalid-field summary (AC4).
 */

import { useState, type CSSProperties, type JSX } from "react";

import {
  useCreateSystem,
  useDeleteSystem,
  useUpdateSystem,
  type SystemBase,
  type SystemCreateRequest,
  type SystemUpdateRequest,
} from "../../../api/systems";
import { css } from "../../css";
import { WizardShell, FieldHelp, type WizardFieldIssue } from "../../wizards";

const DISTRO_OPTIONS: readonly string[] = ["unknown", "ubuntu", "debian", "arch", "rhel", "alpine"];

type Mode = "create" | { edit: SystemBase };

interface SystemFormProps {
  mode: Mode;
  onClose: () => void;
  /** Fired after a successful create/update/delete so the parent can refetch. */
  onDone?: (system: SystemBase | null) => void;
}

interface FieldsState {
  name: string;
  host: string;
  username: string;
  port: string;
  distro: string;
  description: string;
  role: string;
  private_key: string;
  password: string;
  private_key_passphrase: string;
  /** Set to true when the operator explicitly clears the value; on PUT we
   *  send `null` for the flagged field to instruct the backend to wipe it. */
  clearKey: boolean;
  clearPassword: boolean;
  clearPassphrase: boolean;
}

function seedFromExisting(row: SystemBase): FieldsState {
  return {
    name: row.name,
    host: row.host,
    username: row.username,
    port: String(row.port),
    distro: row.distro,
    description: row.description,
    role: row.role,
    private_key: "",
    password: "",
    private_key_passphrase: "",
    clearKey: false,
    clearPassword: false,
    clearPassphrase: false,
  };
}

const EMPTY: FieldsState = {
  name: "",
  host: "",
  username: "root",
  port: "22",
  distro: "unknown",
  description: "",
  role: "",
  private_key: "",
  password: "",
  private_key_passphrase: "",
  clearKey: false,
  clearPassword: false,
  clearPassphrase: false,
};

function computeIssues(f: FieldsState): WizardFieldIssue[] {
  const out: WizardFieldIssue[] = [];
  if (!f.name.trim()) out.push({ label: "system name", reason: "required" });
  else if (f.name.length > 128) out.push({ label: "system name", reason: "128 characters or fewer" });
  if (!f.host.trim()) out.push({ label: "ssh host / ip", reason: "required" });
  const portNum = Number.parseInt(f.port, 10);
  if (!Number.isFinite(portNum) || portNum < 1 || portNum > 65535) {
    out.push({ label: "ssh port", reason: "must be between 1 and 65535" });
  }
  if (f.role.length > 64) out.push({ label: "role", reason: "64 characters or fewer" });
  return out;
}

export default function SystemForm(props: SystemFormProps): JSX.Element {
  const isEdit = props.mode !== "create";
  const editRow = props.mode === "create" ? null : props.mode.edit;
  const [f, setF] = useState<FieldsState>(() => (editRow ? seedFromExisting(editRow) : EMPTY));
  const [confirmDelete, setConfirmDelete] = useState<boolean>(false);

  const create = useCreateSystem();
  const update = useUpdateSystem(editRow?.id ?? null);
  const del = useDeleteSystem();

  const busy = create.isPending || update.isPending || del.isPending;
  const err = create.error ?? update.error ?? del.error;
  const errText = err instanceof Error ? err.message : null;

  const set = <K extends keyof FieldsState>(k: K, v: FieldsState[K]): void => {
    setF((prev) => ({ ...prev, [k]: v }));
  };

  const issues = computeIssues(f);

  const doSubmit = (): void => {
    if (issues.length > 0) return;
    const portNum = Number.parseInt(f.port, 10);
    if (isEdit && editRow) {
      const body: SystemUpdateRequest = {};
      if (f.name !== editRow.name) body.name = f.name.trim();
      if (f.host !== editRow.host) body.host = f.host.trim();
      if (f.username !== editRow.username) body.username = f.username;
      if (portNum !== editRow.port) body.port = portNum;
      if (f.distro !== editRow.distro) body.distro = f.distro;
      if (f.description !== editRow.description) body.description = f.description;
      if (f.role !== editRow.role) body.role = f.role.trim();
      if (f.private_key.trim()) body.private_key = f.private_key;
      else if (f.clearKey) body.private_key = null;
      if (f.password) body.password = f.password;
      else if (f.clearPassword) body.password = null;
      if (f.private_key_passphrase) body.private_key_passphrase = f.private_key_passphrase;
      else if (f.clearPassphrase) body.private_key_passphrase = null;
      update.mutate(body, { onSuccess: (row) => { props.onDone?.(row); props.onClose(); } });
    } else {
      const body: SystemCreateRequest = {
        name: f.name.trim(),
        host: f.host.trim(),
        username: f.username || "root",
        port: portNum,
        distro: f.distro || "unknown",
        description: f.description,
        role: f.role.trim(),
      };
      if (f.private_key.trim()) body.private_key = f.private_key;
      if (f.password) body.password = f.password;
      if (f.private_key_passphrase) body.private_key_passphrase = f.private_key_passphrase;
      create.mutate(body, { onSuccess: (row) => { props.onDone?.(row); props.onClose(); } });
    }
  };

  const doDelete = (): void => {
    if (!editRow) return;
    del.mutate(editRow.id, { onSuccess: () => { props.onDone?.(null); props.onClose(); } });
  };

  const stepTitle = isEdit ? `edit system \u00b7 ${editRow?.name ?? ""}` : "register system";
  const finishLabel = isEdit
    ? (update.isPending ? "saving \u2026" : "save changes")
    : (create.isPending ? "creating \u2026" : "register system");

  return (
    <div
      style={css(
        "position:fixed;inset:0;z-index:60;background:rgba(0,0,0,0.55);display:flex;align-items:center;justify-content:center;padding:24px;",
      )}
      onClick={props.onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={css(
          "width:100%;max-width:640px;height:min(720px,calc(100vh - 48px));background:var(--surface-card);border:1px solid var(--border);border-radius:4px;box-shadow:0 12px 60px rgba(0,0,0,0.6);display:flex;flex-direction:column;position:relative;",
        )}
      >
        <button
          type="button"
          onClick={props.onClose}
          aria-label="close"
          style={{
            ...btnGhost(),
            position: "absolute",
            top: 8,
            right: 8,
            zIndex: 2,
          }}
        >
          {"\u2715"}
        </button>
        <WizardShell
          steps={[{ id: "system", title: stepTitle, purpose: "connection details for an SSH-reachable host." }]}
          current={0}
          issues={issues}
          onBack={() => {}}
          backLabel="cancel"
          onNext={() => {}}
          onFinish={doSubmit}
          finishLabel={finishLabel}
          busy={busy}
          error={errText}
        >
          {isEdit ? (
            <div
              style={css(
                "display:flex;align-items:center;gap:9px;padding:8px 10px;border:1px solid var(--border-soft);border-radius:3px;background:var(--surface-sunk);",
              )}
            >
              {confirmDelete ? (
                <>
                  <span style={css("font-size:10px;color:var(--status-warn);letter-spacing:0.04em;")}>
                    delete this system?
                  </span>
                  <span style={css("flex:1;")} />
                  <button type="button" onClick={doDelete} disabled={busy} style={btnDanger()}>
                    {del.isPending ? "deleting \u2026" : "confirm delete"}
                  </button>
                  <button type="button" onClick={() => setConfirmDelete(false)} style={btnSecondary()}>
                    keep
                  </button>
                </>
              ) : (
                <>
                  <span style={css("font-size:10px;color:var(--text-faint);letter-spacing:0.04em;")}>
                    remove this system from the registry
                  </span>
                  <span style={css("flex:1;")} />
                  <button type="button" onClick={() => setConfirmDelete(true)} style={btnDanger()}>
                    delete
                  </button>
                </>
              )}
            </div>
          ) : null}

          <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:12px;")}>
            {textField("name", "system name", f.name, (v) => set("name", v), true)}
            {textField("host", "ssh host / ip", f.host, (v) => set("host", v), true)}
            {textFieldWithHelp(
              "username",
              "ssh username",
              f.username,
              (v) => set("username", v),
              "Account the scanner logs in as over SSH. Defaults to root.",
            )}
            {textFieldWithHelp(
              "port",
              "ssh port",
              f.port,
              (v) => set("port", v.replace(/[^0-9]/g, "")),
              "TCP port sshd listens on. Standard is 22.",
            )}
          </div>

          <label style={FIELD_LABEL}>
            <span style={FIELD_LABEL_ROW}>
              <span style={FIELD_SPAN}>distribution</span>
              <FieldHelp text="Selects the OS-specific package-manager commands the scanner runs. Pick 'unknown' if you are not sure." />
            </span>
            <select
              value={f.distro}
              onChange={(e) => set("distro", e.target.value)}
              style={inputStyle()}
            >
              {DISTRO_OPTIONS.map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
          </label>

          <label style={FIELD_LABEL}>
            <span style={FIELD_LABEL_ROW}>
              <span style={FIELD_SPAN}>role</span>
              <FieldHelp text="Free-text host role or kind (e.g. vuln-scan, analysis, poc, fuzz, forensics, sandbox). Drives the role filter on the registry list. Leave blank if unspecified." />
            </span>
            <input
              type="text"
              value={f.role}
              onChange={(e) => set("role", e.target.value)}
              maxLength={64}
              placeholder="unspecified"
              style={inputStyle()}
            />
          </label>

          <label style={FIELD_LABEL}>
            <span style={FIELD_SPAN}>description</span>
            <textarea
              value={f.description}
              onChange={(e) => set("description", e.target.value)}
              rows={2}
              style={css(
                "resize:vertical;background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:9px 11px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;line-height:1.45;border-radius:3px;",
              )}
            />
          </label>

          <div
            style={css(
              "border:1px dashed var(--border-soft);border-radius:3px;padding:10px 12px;display:flex;flex-direction:column;gap:9px;",
            )}
          >
            <span style={css("font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
              ssh secrets {isEdit ? "\u00b7 leave blank to keep existing" : ""}
            </span>
            <label style={FIELD_LABEL}>
              <span style={FIELD_LABEL_ROW}>
                <span style={FIELD_SPAN}>private key (PEM)</span>
                <FieldHelp text="OpenSSH or PEM-format private key. Stored encrypted server-side via SecretRecord; the raw value never leaves the operator's browser except over this HTTPS submit." />
              </span>
              <textarea
                value={f.private_key}
                onChange={(e) => set("private_key", e.target.value)}
                rows={4}
                placeholder={isEdit ? "\u2014" : "-----BEGIN OPENSSH PRIVATE KEY-----\n\u2026\n-----END OPENSSH PRIVATE KEY-----"}
                style={css(
                  "resize:vertical;background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:9px 11px;color:var(--text-primary);font-family:var(--font-mono);font-size:10.5px;line-height:1.4;border-radius:3px;white-space:pre;",
                )}
              />
              {isEdit ? clearToggle(f.clearKey, (v) => set("clearKey", v), "clear stored key") : null}
            </label>
            <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:12px;")}>
              <label style={FIELD_LABEL}>
                <span style={FIELD_LABEL_ROW}>
                  <span style={FIELD_SPAN}>password</span>
                  <FieldHelp text="Optional password auth. Only used when no private key is stored; encrypted at rest." />
                </span>
                <input
                  type="password"
                  value={f.password}
                  onChange={(e) => set("password", e.target.value)}
                  autoComplete="new-password"
                  style={inputStyle()}
                />
                {isEdit ? clearToggle(f.clearPassword, (v) => set("clearPassword", v), "clear stored password") : null}
              </label>
              <label style={FIELD_LABEL}>
                <span style={FIELD_LABEL_ROW}>
                  <span style={FIELD_SPAN}>key passphrase</span>
                  <FieldHelp text="Passphrase that unlocks the private key above. Leave blank if the key is unencrypted." />
                </span>
                <input
                  type="password"
                  value={f.private_key_passphrase}
                  onChange={(e) => set("private_key_passphrase", e.target.value)}
                  autoComplete="new-password"
                  style={inputStyle()}
                />
                {isEdit ? clearToggle(f.clearPassphrase, (v) => set("clearPassphrase", v), "clear stored passphrase") : null}
              </label>
            </div>
          </div>
        </WizardShell>
      </div>
    </div>
  );
}

function textField(
  name: string,
  label: string,
  value: string,
  onChange: (v: string) => void,
  required: boolean = false,
): JSX.Element {
  return (
    <label key={name} style={FIELD_LABEL}>
      <span style={required ? FIELD_SPAN_REQUIRED : FIELD_SPAN}>{label}</span>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={inputStyle()}
      />
    </label>
  );
}

function textFieldWithHelp(
  name: string,
  label: string,
  value: string,
  onChange: (v: string) => void,
  helpText: string,
): JSX.Element {
  return (
    <label key={name} style={FIELD_LABEL}>
      <span style={FIELD_LABEL_ROW}>
        <span style={FIELD_SPAN}>{label}</span>
        <FieldHelp text={helpText} />
      </span>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={inputStyle()}
      />
    </label>
  );
}

function clearToggle(on: boolean, set: (v: boolean) => void, label: string): JSX.Element {
  return (
    <label
      style={css(
        "display:inline-flex;align-items:center;gap:6px;margin-top:4px;font-size:10px;color:var(--text-faint);letter-spacing:0.04em;cursor:pointer;",
      )}
    >
      <input type="checkbox" checked={on} onChange={(e) => set(e.target.checked)} />
      {label}
    </label>
  );
}

const FIELD_LABEL = css("display:flex;flex-direction:column;gap:5px;");
const FIELD_LABEL_ROW = css("display:inline-flex;align-items:center;gap:6px;position:relative;");
const FIELD_SPAN = css("font-size:10.5px;letter-spacing:0.06em;color:var(--text-primary);");
const FIELD_SPAN_REQUIRED = css("font-size:10.5px;letter-spacing:0.06em;color:var(--text-primary);");

function inputStyle(): CSSProperties {
  return css(
    "background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:9px 11px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;border-radius:3px;",
  );
}

function btnSecondary(): CSSProperties {
  return css(
    "padding:0 12px;height:30px;font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-muted);background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:3px;cursor:pointer;",
  );
}

function btnDanger(): CSSProperties {
  return css(
    "padding:0 12px;height:30px;font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.06em;text-transform:uppercase;color:#ff5f87;background:#ff5f871c;border:1px solid #ff5f8759;border-radius:3px;cursor:pointer;",
  );
}

function btnGhost(): CSSProperties {
  return css(
    "width:24px;height:24px;display:flex;align-items:center;justify-content:center;background:transparent;border:0;color:var(--text-muted);cursor:pointer;font-family:inherit;font-size:12px;",
  );
}
