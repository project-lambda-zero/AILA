/**
 * Boundary parser for the single-target detail payload shared by the VR and
 * Malware target pages. The payload is merged over the DataPage row snapshot
 * and parsed once here, so the pages render typed fields with no casts.
 */

import { asRecord, readNum, readStr, readStrArray } from "./parse";

export interface StageInfo {
  state: string | null;
  attempts: number | null;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
}

export interface TargetDetail {
  id: string;
  display_name: string | null;
  kind: string | null;
  status: string | null;
  analysis_state: string | null;
  analysis_state_message: string | null;
  analysis_started_at: string | null;
  analysis_completed_at: string | null;
  analysis_stages: Record<string, StageInfo>;
  capability_profile: Record<string, unknown> | null;
  descriptor: Record<string, unknown> | null;
  primary_language: string | null;
  secondary_languages: string[];
  uploaded_filename: string | null;
  android_package_name: string | null;
  apk_overview: Record<string, unknown> | null;
  workspace_name: string | null;
  workspace_id: string | null;
  tags: string[];
  created_at: string | null;
  updated_at: string | null;
}

function parseStage(v: unknown): StageInfo | null {
  const o = asRecord(v);
  if (!o) return null;
  return {
    state: readStr(o, "state"),
    attempts: readNum(o, "attempts"),
    started_at: readStr(o, "started_at"),
    completed_at: readStr(o, "completed_at"),
    error: readStr(o, "error"),
  };
}

function parseStages(v: unknown): Record<string, StageInfo> {
  const out: Record<string, StageInfo> = {};
  const o = asRecord(v);
  if (!o) return out;
  for (const [name, raw] of Object.entries(o)) {
    const stage = parseStage(raw);
    if (stage) out[name] = stage;
  }
  return out;
}

/** Tags arrive as bare strings or `{tag, source}` rows; keep the tag names. */
function parseTags(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const el of v) {
    if (typeof el === "string") {
      if (el) out.push(el);
      continue;
    }
    const rec = asRecord(el);
    const tag = rec ? readStr(rec, "tag") : null;
    if (tag) out.push(tag);
  }
  return out;
}

/** Parse a merged target record (DataPage row overlaid with the detail
 * payload) into a TargetDetail. Missing or mistyped fields become `null` or
 * empty collections, never `undefined`. */
export function parseTargetDetail(o: Record<string, unknown>): TargetDetail {
  return {
    id: readStr(o, "id") ?? "",
    display_name: readStr(o, "display_name"),
    kind: readStr(o, "kind"),
    status: readStr(o, "status"),
    analysis_state: readStr(o, "analysis_state"),
    analysis_state_message: readStr(o, "analysis_state_message"),
    analysis_started_at: readStr(o, "analysis_started_at"),
    analysis_completed_at: readStr(o, "analysis_completed_at"),
    analysis_stages: parseStages(o.analysis_stages),
    capability_profile: asRecord(o.capability_profile),
    descriptor: asRecord(o.descriptor),
    primary_language: readStr(o, "primary_language"),
    secondary_languages: readStrArray(o, "secondary_languages"),
    uploaded_filename: readStr(o, "uploaded_filename"),
    android_package_name: readStr(o, "android_package_name"),
    apk_overview: asRecord(o.apk_overview),
    workspace_name: readStr(o, "workspace_name"),
    workspace_id: readStr(o, "workspace_id"),
    tags: parseTags(o.tags),
    created_at: readStr(o, "created_at"),
    updated_at: readStr(o, "updated_at"),
  };
}
