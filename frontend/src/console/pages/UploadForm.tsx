/**
 * UploadForm -- honest multipart target-upload window for the VR and malware
 * modules. Opens as a bespoke registry page (`vr:new-target` /
 * `malware:new-target`) and drives creation via the three upload endpoints:
 *
 *   VR android_apk           POST /vr/targets/upload-apk        (single-shot)
 *   VR file-binary kinds     POST /vr/targets  ->  POST /vr/targets/{id}/upload
 *   VR descriptor kinds      POST /vr/targets                    (JSON only)
 *   Malware every kind       POST /malware/targets/upload        (single-shot)
 *
 * The kind picker drives which body a submit builds. File kinds render a real
 * `<input type=file>` and disable submit until a file is picked; descriptor
 * kinds render typed scalar inputs and post a JSON descriptor. There is no
 * raw-JSON editor and no fabricated payload -- every field maps 1:1 to a
 * declared Pydantic field on the corresponding Create model.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent, JSX, ReactNode } from "react";

import type { ApiError } from "../../api/client";
import {
  useCreateMalwareTarget,
  useCreateVrTarget,
  useUploadApkTarget,
  useUploadMalwareTarget,
  useUploadVrBinary,
  useWorkspaces,
} from "../../api/intake";
import type {
  MalwareTargetKind,
  VRTargetKind,
} from "../../api/intake";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import { WizardShell, FieldHelp } from "../wizards";
import type { WizardFieldIssue, WizardStepDef } from "../wizards";

/* -------------------------------------------------------------------------- *
 * Per-kind spec
 * -------------------------------------------------------------------------- */

interface DescField {
  name: string;
  label: string;
  placeholder: string;
  required?: boolean;
}

/** Which shape of submit this kind uses. Drives the render + the mutation. */
type KindMode =
  | "vr-apk"         // POST /vr/targets/upload-apk
  | "vr-upload"      // POST /vr/targets  ->  POST /vr/targets/{id}/upload
  | "vr-descriptor"  // POST /vr/targets  (JSON only)
  | "mal-upload";    // POST /malware/targets/upload

interface KindSpec {
  key: string;
  label: string;
  group: string;
  mode: KindMode;
  /** File input hint (accept, hint text). Omitted for descriptor kinds. */
  file?: { accept: string; hint: string };
  /** Extra scalar descriptor fields carried alongside the file / on the JSON body. */
  descriptor: DescField[];
}

/** VR kinds, laid out in the same groups as IntakeWizard's kind grid so the
 * operator experience is consistent. */
const VR_KINDS: KindSpec[] = [
  {
    key: "source_repo",
    label: "source repo",
    group: "source",
    mode: "vr-descriptor",
    descriptor: [
      { name: "repo_url", label: "repo url", placeholder: "https://github.com/org/proj", required: true },
      { name: "ref", label: "ref / branch", placeholder: "main" },
    ],
  },
  {
    key: "patch_diff",
    label: "patch diff",
    group: "source",
    mode: "vr-descriptor",
    descriptor: [
      { name: "repo_url", label: "repo url", placeholder: "", required: true },
      { name: "vulnerable_ref", label: "vulnerable ref", placeholder: "", required: true },
      { name: "patched_ref", label: "patched ref", placeholder: "", required: true },
    ],
  },
  {
    key: "cve",
    label: "cve",
    group: "n-day",
    mode: "vr-descriptor",
    descriptor: [
      { name: "cve_id", label: "cve id", placeholder: "CVE-2026-1234", required: true },
      { name: "vendor", label: "vendor", placeholder: "" },
    ],
  },
  {
    key: "protocol_capture",
    label: "protocol capture",
    group: "capture",
    mode: "vr-descriptor",
    descriptor: [
      { name: "pcap_path", label: "pcap path", placeholder: "", required: true },
      { name: "protocol", label: "protocol", placeholder: "rtsp" },
    ],
  },
  {
    key: "crash_input",
    label: "crash input",
    group: "capture",
    mode: "vr-descriptor",
    descriptor: [
      { name: "crash_artifact_path", label: "crash artifact", placeholder: "", required: true },
      { name: "parent_finding_id", label: "parent finding", placeholder: "" },
    ],
  },
  {
    key: "native_binary",
    label: "native binary",
    group: "binary",
    mode: "vr-upload",
    file: { accept: "", hint: "any executable / library" },
    descriptor: [],
  },
  {
    key: "jar",
    label: "jar",
    group: "binary",
    mode: "vr-upload",
    file: { accept: ".jar", hint: "JVM archive" },
    descriptor: [],
  },
  {
    key: "dotnet_assembly",
    label: ".net assembly",
    group: "binary",
    mode: "vr-upload",
    file: { accept: ".dll,.exe", hint: ".dll or .exe assembly" },
    descriptor: [],
  },
  {
    key: "ipa",
    label: "ios ipa",
    group: "mobile",
    mode: "vr-upload",
    file: { accept: ".ipa", hint: "iOS application archive" },
    descriptor: [],
  },
  {
    key: "android_apk",
    label: "android apk",
    group: "mobile",
    mode: "vr-apk",
    file: { accept: ".apk", hint: "runs the APK_DECODE / JADX / STATIC_SUMMARY pipeline" },
    descriptor: [],
  },
  {
    key: "kernel_image",
    label: "kernel image",
    group: "kernel",
    mode: "vr-upload",
    file: { accept: "", hint: "vmlinuz / bzImage / raw image" },
    descriptor: [
      { name: "kernel_version", label: "kernel version", placeholder: "" },
      { name: "arch", label: "arch", placeholder: "x86_64" },
    ],
  },
  {
    key: "kernel_module",
    label: "kernel module",
    group: "kernel",
    mode: "vr-upload",
    file: { accept: ".ko", hint: "loadable kernel module" },
    descriptor: [
      { name: "module_name", label: "module name", placeholder: "" },
    ],
  },
  {
    key: "hypervisor_image",
    label: "hypervisor image",
    group: "kernel",
    mode: "vr-upload",
    file: { accept: "", hint: "hypervisor / vmm binary" },
    descriptor: [
      { name: "hypervisor_kind", label: "kind", placeholder: "kvm" },
      { name: "version", label: "version", placeholder: "" },
    ],
  },
];

const MAL_KINDS: KindSpec[] = [
  { key: "pe_sample",       label: "pe sample",       group: "sample", mode: "mal-upload", file: { accept: ".exe,.dll,.sys", hint: "windows PE" },     descriptor: [] },
  { key: "elf_sample",      label: "elf sample",      group: "sample", mode: "mal-upload", file: { accept: "",                hint: "linux ELF" },     descriptor: [] },
  { key: "mach_o_sample",   label: "mach-o sample",   group: "sample", mode: "mal-upload", file: { accept: "",                hint: "macOS mach-o" },  descriptor: [] },
  { key: "shellcode",       label: "shellcode",       group: "sample", mode: "mal-upload", file: { accept: "",                hint: "raw blob" },      descriptor: [] },
  { key: "android_apk",     label: "android apk",     group: "sample", mode: "mal-upload", file: { accept: ".apk",            hint: "APK -> android-mcp" }, descriptor: [] },
  { key: "dotnet_assembly", label: ".net assembly",   group: "sample", mode: "mal-upload", file: { accept: ".dll,.exe",       hint: ".dll or .exe" },  descriptor: [] },
  { key: "script_sample",   label: "script sample",   group: "sample", mode: "mal-upload", file: { accept: "",                hint: "ps1 / py / js / vbs" }, descriptor: [] },
  { key: "document_sample", label: "document sample", group: "sample", mode: "mal-upload", file: { accept: "",                hint: "doc / xls / pdf carrier" }, descriptor: [] },
];

const GROUPS_VR: Array<[string, string]> = [
  ["source", "source"],
  ["binary", "binary"],
  ["mobile", "mobile"],
  ["n-day", "cve / n-day"],
  ["capture", "capture"],
  ["kernel", "kernel \u00b7 hv"],
];
const GROUPS_MAL: Array<[string, string]> = [["sample", "sample"]];

/* -------------------------------------------------------------------------- *
 * Props
 * -------------------------------------------------------------------------- */

export interface UploadFormProps extends ModulePageProps {
  module: "vr" | "malware";
  /** Called with the created target after a successful upload / descriptor
   * create. When omitted the window simply reports the success payload; the
   * parent shell also closes on onBack. */
  onDone?: (created: { id: string; display_name: string; kind: string }) => void;
}

/* -------------------------------------------------------------------------- *
 * Small style helpers -- mirrors XRayPage / DataPage / IntakeWizard
 * -------------------------------------------------------------------------- */

const panelBox =
  "min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));";
const panelTitle = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:9.5px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
const dot = css(
  "width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;",
);
const labelStyle = css(
  "font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);",
);
const inputStyle = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:7px 9px;color:var(--text-primary);font-family:var(--font-mono);font-size:11.5px;border-radius:2px;",
);
const selectStyle = inputStyle;

/* -------------------------------------------------------------------------- *
 * Component
 * -------------------------------------------------------------------------- */

export default function UploadForm(props: UploadFormProps): JSX.Element {
  const { module, onBack, onMinimize, isFullscreen, onToggleFullscreen, onDone, windowId, title: windowTitle, isFocused, onFocus } = props;
  const kinds = module === "vr" ? VR_KINDS : MAL_KINDS;
  const groups = module === "vr" ? GROUPS_VR : GROUPS_MAL;

  const workspaces = useWorkspaces(module);

  const defaultKind = module === "vr" ? "native_binary" : "pe_sample";
  const [kindKey, setKindKey] = useState<string>(defaultKind);
  const [workspaceId, setWorkspaceId] = useState<string>("");
  const [displayName, setDisplayName] = useState<string>("");
  const [descriptor, setDescriptor] = useState<Record<string, string>>({});
  const [tagsRaw, setTagsRaw] = useState<string>("");
  const [file, setFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Success payload (per-branch: keep raw fields visible so the operator sees
  // the sha256 the server actually stored).
  const [created, setCreated] = useState<null | {
    id: string;
    display_name: string;
    kind: string;
    sha256?: string;
    uploaded_filename?: string;
    apk_path?: string;
    bytes_written?: number;
    enqueue_error?: string | null;
  }>(null);
  const [error, setError] = useState<string | null>(null);

  // Default workspace once the list arrives (idempotent).
  useEffect(() => {
    if (workspaces.data && workspaces.data.length > 0 && workspaceId === "") {
      setWorkspaceId(workspaces.data[0].id);
    }
  }, [workspaces.data, workspaceId]);

  const spec = kinds.find((k) => k.key === kindKey) ?? kinds[0];

  const uploadApk = useUploadApkTarget();
  const createVrTarget = useCreateVrTarget();
  const uploadVrBin = useUploadVrBinary();
  const uploadMal = useUploadMalwareTarget();
  const createMal = useCreateMalwareTarget();

  const busy =
    uploadApk.isPending ||
    createVrTarget.isPending ||
    uploadVrBin.isPending ||
    uploadMal.isPending ||
    createMal.isPending;

  const setDescField = (name: string, value: string): void => {
    setDescriptor((d) => ({ ...d, [name]: value }));
  };

  const onPickKind = (k: string): void => {
    setKindKey(k);
    setDescriptor({});
    setFile(null);
    setCreated(null);
    setError(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  // Compute submit gating so the button reflects real completeness.
  const descriptorReady = spec.descriptor.every(
    (f) => !f.required || (descriptor[f.name] ?? "").trim() !== "",
  );
  const wantsFile = spec.mode !== "vr-descriptor";
  const canSubmit =
    !busy &&
    workspaceId.trim() !== "" &&
    displayName.trim() !== "" &&
    (!wantsFile || file !== null) &&
    descriptorReady;

  const tags = useMemo(
    () =>
      tagsRaw
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t.length > 0),
    [tagsRaw],
  );

  // Convert the submit-gating conditions into named-field WizardShell issues so
  // the shared shell can render the invalid-field summary and disable Finish
  // without a silent bare-disabled control.
  const wsRowsForIssues = workspaces.data ?? [];
  const issues: WizardFieldIssue[] = useMemo(() => {
    if (created) return [];
    const out: WizardFieldIssue[] = [];
    if (!workspaces.isLoading) {
      if (wsRowsForIssues.length === 0) {
        out.push({ label: "workspace", reason: "none available -- create one first" });
      } else if (workspaceId.trim() === "") {
        out.push({ label: "workspace", reason: "required" });
      }
    }
    if (displayName.trim() === "") {
      out.push({ label: "display name", reason: "required" });
    }
    if (wantsFile && !file) {
      out.push({
        label: spec.mode === "vr-apk" ? "apk file" : "file",
        reason: "pick a file",
      });
    }
    for (const f of spec.descriptor) {
      if (f.required && (descriptor[f.name] ?? "").trim() === "") {
        out.push({ label: f.label, reason: "required" });
      }
    }
    return out;
    // wsRowsForIssues is derived from workspaces.data each render; workspaces.data
    // is the true dep.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    created,
    workspaces.data,
    workspaces.isLoading,
    workspaceId,
    displayName,
    wantsFile,
    file,
    spec,
    descriptor,
  ]);

  const wizardSteps: WizardStepDef[] = useMemo(
    () => [
      {
        id: "upload",
        title: "register target",
        purpose: `pick a ${module} kind, fill the required fields, and submit an upload or descriptor to the backend.`,
      },
    ],
    [module],
  );

  async function onSubmit(): Promise<void> {
    if (!canSubmit) return;
    setError(null);
    setCreated(null);
    try {
      if (module === "vr" && spec.mode === "vr-apk" && file) {
        const r = await uploadApk.mutateAsync({
          workspace_id: workspaceId,
          display_name: displayName,
          file,
        });
        setCreated({
          id: r.target_id,
          display_name: displayName,
          kind: spec.key,
          sha256: r.uploaded_sha256,
          uploaded_filename: r.uploaded_filename,
          apk_path: r.apk_path,
          bytes_written: r.bytes_written,
          enqueue_error: r.enqueue_error,
        });
        onDone?.({ id: r.target_id, display_name: displayName, kind: spec.key });
        return;
      }
      if (module === "vr" && spec.mode === "vr-upload" && file) {
        const desc: Record<string, unknown> = {};
        for (const f of spec.descriptor) {
          const v = (descriptor[f.name] ?? "").trim();
          if (v !== "") desc[f.name] = v;
        }
        const t = await createVrTarget.mutateAsync({
          workspace_id: workspaceId,
          display_name: displayName,
          kind: spec.key as VRTargetKind,
          descriptor: desc,
          tags,
        });
        const u = await uploadVrBin.mutateAsync({ target_id: t.id, file });
        setCreated({
          id: t.id,
          display_name: displayName,
          kind: spec.key,
          uploaded_filename: u.uploaded_filename,
        });
        onDone?.({ id: t.id, display_name: displayName, kind: spec.key });
        return;
      }
      if (module === "vr" && spec.mode === "vr-descriptor") {
        const desc: Record<string, unknown> = {};
        for (const f of spec.descriptor) {
          const v = (descriptor[f.name] ?? "").trim();
          if (v !== "") desc[f.name] = v;
        }
        const t = await createVrTarget.mutateAsync({
          workspace_id: workspaceId,
          display_name: displayName,
          kind: spec.key as VRTargetKind,
          descriptor: desc,
          tags,
        });
        setCreated({ id: t.id, display_name: displayName, kind: spec.key });
        onDone?.({ id: t.id, display_name: displayName, kind: spec.key });
        return;
      }
      if (module === "malware" && spec.mode === "mal-upload" && file) {
        const t = await uploadMal.mutateAsync({
          workspace_id: workspaceId,
          display_name: displayName,
          kind: spec.key as MalwareTargetKind,
          sample: file,
          tags,
        });
        setCreated({
          id: t.id,
          display_name: t.display_name,
          kind: t.kind,
          uploaded_filename: t.uploaded_filename ?? undefined,
        });
        onDone?.({ id: t.id, display_name: t.display_name, kind: t.kind });
        return;
      }
      // Descriptor-only malware path (URL / on-disk sample_path). Reachable
      // only if we ever surface a descriptor-mode row in MAL_KINDS.
      if (module === "malware") {
        const desc: Record<string, unknown> = {};
        for (const f of spec.descriptor) {
          const v = (descriptor[f.name] ?? "").trim();
          if (v !== "") desc[f.name] = v;
        }
        const t = await createMal.mutateAsync({
          workspace_id: workspaceId,
          display_name: displayName,
          kind: spec.key as MalwareTargetKind,
          descriptor: desc,
          tags,
        });
        setCreated({ id: t.id, display_name: t.display_name, kind: t.kind });
        onDone?.({ id: t.id, display_name: t.display_name, kind: t.kind });
      }
    } catch (err) {
      const msg =
        err && typeof err === "object" && "message" in err
          ? String((err as ApiError).message || "").slice(0, 400)
          : "unknown error";
      setError(msg);
    }
  }

  /* ---- render blocks --------------------------------------------------- */

  const kindGrid: ReactNode = (
    <div style={css("display:flex;flex-direction:column;gap:11px;")}>
      {groups.map(([g, gl]) => {
        const items = kinds.filter((k) => k.group === g);
        if (items.length === 0) return null;
        return (
          <div key={g}>
            <div
              style={css(
                "font-size:9px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-faint);margin-bottom:6px;",
              )}
            >
              {gl}
            </div>
            <div style={css("display:grid;grid-template-columns:repeat(3,1fr);gap:6px;")}>
              {items.map((k) => {
                const on = k.key === kindKey;
                return (
                  <button
                    key={k.key}
                    type="button"
                    onClick={(): void => onPickKind(k.key)}
                    style={css(
                      `padding:8px 9px;text-align:left;font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.04em;color:${
                        on ? "var(--accent)" : "var(--text-primary)"
                      };background:${
                        on ? "color-mix(in srgb,var(--accent) 10%,transparent)" : "var(--surface-card)"
                      };border:1px solid ${
                        on ? "var(--accent)" : "var(--border-soft)"
                      };border-radius:2px;cursor:pointer;`,
                    )}
                  >
                    {k.label}
                  </button>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );

  const wsRows = workspaces.data ?? [];
  const wsLoading = workspaces.isLoading;
  const wsError = workspaces.isError;

  const basicsBlock: ReactNode = (
    <div style={css("display:flex;flex-direction:column;gap:10px;")}>
      <label style={css("display:flex;flex-direction:column;gap:4px;")}>
        <span style={css("display:flex;align-items:center;gap:6px;")}>
          <span style={labelStyle}>workspace</span>
          <FieldHelp text="The workspace this target is filed under. Defaults to the first workspace on the account -- change it if a different team owns this target." />
        </span>
        {wsLoading ? (
          <span style={css("font-size:11px;color:var(--text-faint);")}>{"loading workspaces\u2026"}</span>
        ) : wsError ? (
          <span style={css("font-size:11px;color:var(--status-warn);")}>
            failed to load workspaces
          </span>
        ) : wsRows.length === 0 ? (
          <span style={css("font-size:11px;color:var(--text-faint);")}>
            no workspaces -- create one from {module} {"\u00b7"} workspaces first
          </span>
        ) : (
          <select
            value={workspaceId}
            onChange={(e: ChangeEvent<HTMLSelectElement>): void =>
              setWorkspaceId(e.target.value)
            }
            style={selectStyle}
          >
            {wsRows.map((w) => (
              <option key={w.id} value={w.id}>
                {w.name} {w.slug ? ` \u00b7 ${w.slug}` : ""}
              </option>
            ))}
          </select>
        )}
      </label>
      <label style={css("display:flex;flex-direction:column;gap:4px;")}>
        <span style={css("display:flex;align-items:center;gap:6px;")}>
          <span style={labelStyle}>display name</span>
          <FieldHelp text="How this target appears in target lists. Human-readable, no ids." />
        </span>
        <input
          value={displayName}
          onChange={(e): void => setDisplayName(e.target.value)}
          placeholder="how the row appears in lists"
          style={inputStyle}
        />
      </label>
      <label style={css("display:flex;flex-direction:column;gap:4px;")}>
        <span style={labelStyle}>tags (comma-separated, optional)</span>
        <input
          value={tagsRaw}
          onChange={(e): void => setTagsRaw(e.target.value)}
          placeholder="e.g. triage, batch-2026-q3"
          style={inputStyle}
        />
      </label>
    </div>
  );

  const fileBlock: ReactNode = wantsFile ? (
    <div style={css("display:flex;flex-direction:column;gap:6px;")}>
      <span style={css("display:flex;align-items:center;gap:6px;")}>
        <span style={labelStyle}>{spec.mode === "vr-apk" ? "apk file" : "binary / sample"}</span>
        <FieldHelp
          text={
            spec.mode === "vr-apk"
              ? "The APK to analyze. Uploaded in a single request and the server runs the APK_DECODE / JADX / STATIC_SUMMARY pipeline."
              : spec.mode === "vr-upload"
                ? "The binary the backend stores under this target. The target row is created first, then the file is uploaded to that id."
                : "The sample file. Uploaded in a single request to the malware ingest endpoint."
          }
        />
      </span>
      <input
        ref={fileInputRef}
        type="file"
        accept={spec.file?.accept ?? ""}
        onChange={(e): void => setFile(e.target.files?.[0] ?? null)}
        style={css(
          "background:var(--surface-sunk);border:1px solid var(--border-soft);padding:7px 9px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;border-radius:2px;",
        )}
      />
      <span style={css("font-size:10px;color:var(--text-faint);")}>
        {spec.file?.hint ?? ""}
        {file ? ` \u00b7 ${file.name} \u00b7 ${file.size.toLocaleString()} bytes` : ""}
      </span>
    </div>
  ) : null;

  const descriptorBlock: ReactNode = spec.descriptor.length > 0 ? (
    <div style={css("display:flex;flex-direction:column;gap:9px;")}>
      {spec.descriptor.map((f) => (
        <label key={f.name} style={css("display:flex;flex-direction:column;gap:4px;")}>
          <span style={labelStyle}>
            {f.label}
            {f.required ? " \u00b7 required" : ""}
          </span>
          <input
            value={descriptor[f.name] ?? ""}
            onChange={(e): void => setDescField(f.name, e.target.value)}
            placeholder={f.placeholder}
            style={inputStyle}
          />
        </label>
      ))}
    </div>
  ) : null;

  const doneStyle = css(
    "padding:11px 13px;border:1px solid var(--accent);background:color-mix(in srgb,var(--accent) 7%,transparent);border-radius:3px;display:flex;flex-direction:column;gap:6px;",
  );

  const kindLabel = spec.label;
  const title = `${module} \u00b7 upload target`;

  const statusStrip = (
    <>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          background: "var(--accent)",
          color: "var(--text-on-accent)",
          fontWeight: 700,
          letterSpacing: "0.14em",
        }}
      >
        {title}
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
        {spec.mode === "vr-apk"
          ? "single-shot POST /vr/targets/upload-apk"
          : spec.mode === "vr-upload"
            ? "POST /vr/targets \u2192 POST /vr/targets/{id}/upload"
            : spec.mode === "vr-descriptor"
              ? "POST /vr/targets (descriptor only)"
              : "single-shot POST /malware/targets/upload"}
      </span>
      <span style={{ flex: 1 }} />
    </>
  );

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={windowTitle}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
      footerExtras={statusStrip}
    >
      <WizardShell
        heading={title}
        steps={wizardSteps}
        current={0}
        issues={issues}
        onBack={onBack}
        onNext={(): void => {
          /* single-step wizard: primary is Finish, Next is never rendered */
        }}
        onFinish={(): void => void onSubmit()}
        backLabel={created ? "close" : "cancel"}
        finishLabel={spec.mode === "vr-descriptor" ? "create target" : "upload"}
        busy={busy}
        error={error}
        onRetry={(): void => void onSubmit()}
        showPrimary={!created}
      >
      <main style={{ flex: 1, minHeight: 0, display: "flex", gap: 10, padding: 12 }}>
        {/* LEFT: kind grid */}
        <div style={{ ...css(`flex:1 1 44%;${panelBox}`) }}>
          <div style={panelTitle}>
            <span style={dot} />
            <span style={css("color:var(--text-primary);")}>kind</span>
            <FieldHelp text="What shape of target this is. The kind picks the upload endpoint and which extra descriptor fields the form asks for." />
            <span style={css("flex:1;")} />
            <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>
              {module}
            </span>
          </div>
          <div style={css("flex:1;min-height:0;overflow:auto;padding:12px 14px;")}>
            {kindGrid}
          </div>
        </div>

        {/* RIGHT: basics + kind-specific inputs + submit */}
        <div style={{ ...css(`flex:1 1 56%;${panelBox}`) }}>
          <div style={panelTitle}>
            <span style={dot} />
            <span style={css("color:var(--text-primary);")}>
              {created ? "created" : "target"}
            </span>
            <span style={css("flex:1;")} />
            <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>
              {kindLabel}
            </span>
          </div>
          <div
            style={css(
              "flex:1;min-height:0;overflow:auto;padding:14px;display:flex;flex-direction:column;gap:14px;",
            )}
          >
            {basicsBlock}
            {fileBlock}
            {descriptorBlock}

            {created ? (
              <div style={doneStyle}>
                <div
                  style={css(
                    "font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--status-ok);",
                  )}
                >
                  {"target created \u00b7 ingestion enqueued"}
                </div>
                <div
                  style={css(
                    "display:grid;grid-template-columns:120px 1fr;gap:5px 10px;font-size:11px;",
                  )}
                >
                  <span style={css("color:var(--text-faint);")}>id</span>
                  <span style={css("color:var(--text-primary);word-break:break-all;")}>{created.id}</span>
                  <span style={css("color:var(--text-faint);")}>name</span>
                  <span style={css("color:var(--text-primary);")}>{created.display_name}</span>
                  <span style={css("color:var(--text-faint);")}>kind</span>
                  <span style={css("color:var(--text-primary);")}>{created.kind}</span>
                  {created.uploaded_filename ? (
                    <>
                      <span style={css("color:var(--text-faint);")}>uploaded</span>
                      <span style={css("color:var(--text-primary);word-break:break-all;")}>
                        {created.uploaded_filename}
                      </span>
                    </>
                  ) : null}
                  {created.sha256 ? (
                    <>
                      <span style={css("color:var(--text-faint);")}>sha256</span>
                      <span style={css("color:var(--text-primary);word-break:break-all;")}>
                        {created.sha256}
                      </span>
                    </>
                  ) : null}
                  {created.apk_path ? (
                    <>
                      <span style={css("color:var(--text-faint);")}>apk path</span>
                      <span style={css("color:var(--text-primary);word-break:break-all;")}>
                        {created.apk_path}
                      </span>
                    </>
                  ) : null}
                  {typeof created.bytes_written === "number" ? (
                    <>
                      <span style={css("color:var(--text-faint);")}>bytes</span>
                      <span style={css("color:var(--text-primary);")}>
                        {created.bytes_written.toLocaleString()}
                      </span>
                    </>
                  ) : null}
                  {created.enqueue_error ? (
                    <>
                      <span style={css("color:var(--status-warn);")}>enqueue error</span>
                      <span style={css("color:var(--status-warn);word-break:break-word;")}>
                        {created.enqueue_error}
                      </span>
                    </>
                  ) : null}
                </div>
              </div>
            ) : null}

          </div>
        </div>
      </main>
      </WizardShell>
    </ConsoleWindow>
  );
}
