/**
 * Recent entities -- a small, module-agnostic ring buffer of the last
 * entities/routes the operator opened. Distinct from `useRecentlyViewed`
 * which is a path-only recency list: this store carries entity metadata
 * (type + id) so the command palette can render a labelled "Recent"
 * group and offer entity-jump shortcuts.
 *
 * Storage: single `localStorage` key holding a JSON array, most-recent
 * first, de-duplicated by `path`, capped at MAX_ITEMS.
 *
 * A cross-tab `storage` listener syncs the in-memory copy so a jump in
 * one tab shows up in another tab's palette on next open.
 */
import { useCallback, useEffect, useState } from "react";
import { useLocation } from "react-router";

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

export interface RecentEntity {
  /** Entity type, e.g. "investigation", "task", "cve", or "route" for
   *  non-entity destinations the operator explicitly bookmarks. */
  type: string;
  /** Entity id or, for `type === "route"`, the route path. */
  id: string;
  /** Human-readable label shown in the palette. */
  title: string;
  /** Client-side path this entry navigates to. */
  path: string;
  /** ms epoch of the most recent visit. */
  at: number;
}

const STORAGE_KEY = "aila-recent-entities";
const MAX_ITEMS = 15;

// ---------------------------------------------------------------------------
// Detail-route patterns
//
// Ordered longest-first so nested routes (`/vr/investigations/:id/graph`)
// match before their parent (`/vr/investigations/:id`). Every pattern
// captures the id in group 1. `titlePrefix` is what we render when the
// only thing we know about the entity is its id.
// ---------------------------------------------------------------------------

interface DetailPattern {
  regex: RegExp;
  type: string;
  titlePrefix: string;
}

const DETAIL_PATTERNS: readonly DetailPattern[] = [
  // Sub-pages of a VR investigation -- record as the parent investigation
  // so the palette lands the operator back on the same case, not a
  // deep sub-tab.
  {
    regex: /^\/vr\/investigations\/([^/]+)(?:\/(?:graph|tree))?\/?$/,
    type: "investigation",
    titlePrefix: "VR Investigation",
  },
  {
    regex: /^\/malware\/investigations\/([^/]+)(?:\/(?:graph|tree))?\/?$/,
    type: "investigation",
    titlePrefix: "Malware Investigation",
  },
  {
    regex: /^\/forensics\/projects\/([^/]+)\/investigations\/([^/]+)\/?$/,
    type: "investigation",
    titlePrefix: "Forensics Investigation",
  },
  { regex: /^\/vr\/projects\/([^/]+)\/?$/, type: "project", titlePrefix: "VR Project" },
  { regex: /^\/vr\/targets\/([^/]+)\/?$/, type: "target", titlePrefix: "VR Target" },
  { regex: /^\/vr\/patterns\/([^/]+)\/?$/, type: "pattern", titlePrefix: "VR Pattern" },
  { regex: /^\/vr\/findings\/([^/]+)\/?$/, type: "finding", titlePrefix: "VR Finding" },
  { regex: /^\/vr\/disclosures\/([^/]+)\/?$/, type: "disclosure", titlePrefix: "Disclosure" },
  { regex: /^\/vr\/fuzz\/campaigns\/([^/]+)\/?$/, type: "campaign", titlePrefix: "Fuzz Campaign" },
  { regex: /^\/vr\/fuzz\/crashes\/([^/]+)\/?$/, type: "crash", titlePrefix: "Fuzz Crash" },
  { regex: /^\/malware\/workspaces\/([^/]+)\/?$/, type: "workspace", titlePrefix: "Workspace" },
  { regex: /^\/malware\/projects\/([^/]+)\/?$/, type: "project", titlePrefix: "Malware Project" },
  { regex: /^\/malware\/targets\/([^/]+)\/?$/, type: "target", titlePrefix: "Malware Target" },
  { regex: /^\/malware\/outcomes\/([^/]+)\/?$/, type: "outcome", titlePrefix: "Outcome" },
  { regex: /^\/malware\/patterns\/([^/]+)\/?$/, type: "pattern", titlePrefix: "Malware Pattern" },
  { regex: /^\/malware\/families\/([^/]+)\/?$/, type: "family", titlePrefix: "Family" },
  { regex: /^\/malware\/playbooks\/([^/]+)\/?$/, type: "playbook", titlePrefix: "Playbook" },
  { regex: /^\/forensics\/projects\/([^/]+)\/?$/, type: "project", titlePrefix: "Forensics Project" },
  { regex: /^\/vulnerability\/reports\/([^/]+)\/?$/, type: "report", titlePrefix: "Vuln Report" },
  { regex: /^\/vulnerability\/findings\/cve\/([^/]+)\/?$/, type: "cve", titlePrefix: "CVE" },
  { regex: /^\/systems\/([^/]+)\/?$/, type: "system", titlePrefix: "System" },
  { regex: /^\/tasks\/([^/]+)\/?$/, type: "task", titlePrefix: "Task" },
];

// ---------------------------------------------------------------------------
// Id helpers
// ---------------------------------------------------------------------------

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Hex/ULID-ish slug covering 8-32 char ids (ULIDs, short hashes, task ids).
// The `(?=.*[0-9])` lookahead REQUIRES at least one digit so ordinary search
// words (e.g. "dashboard", "investigations") are not mistaken for entity ids
// -- those would otherwise fire a bogus "Jump to" group AND suppress the real
// Navigate/Search results. Real ids in this platform (UUIDs, ULIDs, hashes,
// task ids) always carry digits; a `#` prefix stays available in
// `parseEntityJump` as the explicit escape hatch for a rare all-letter id.
const SLUG_REGEX = /^(?=.*[0-9])[0-9a-z]{8,32}$/i;

/** True when `value` looks like an entity id we could jump to. */
export function looksLikeEntityId(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (UUID_REGEX.test(trimmed)) return true;
  if (SLUG_REGEX.test(trimmed)) return true;
  return false;
}

/** Truncate an id for compact display in the palette. */
export function shortId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 8)}…`;
}

/**
 * Match `pathname` against the detail-route table. Returns the derived
 * entity if any pattern matches, else null.
 *
 * For multi-segment routes (forensics) the captured id is the last
 * `(...)`. For investigation sub-pages (`/graph`, `/tree`) the recorded
 * `path` normalises back to the investigation root so the palette lands
 * the operator on the main tab rather than the sub-tab.
 */
export function detectEntityFromPath(
  pathname: string,
): { type: string; id: string; title: string; path: string } | null {
  for (const pat of DETAIL_PATTERNS) {
    const match = pat.regex.exec(pathname);
    if (!match) continue;
    const id = match[match.length - 1];
    if (!id) continue;
    // Strip investigation /graph|/tree sub-pages so a Recent jump lands
    // on the main investigation page rather than a deep sub-tab.
    const path =
      pat.type === "investigation"
        ? pathname.replace(/\/(?:graph|tree)\/?$/, "").replace(/\/+$/, "")
        : pathname.replace(/\/+$/, "");
    return {
      type: pat.type,
      id,
      title: `${pat.titlePrefix} ${shortId(id)}`,
      path,
    };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

function loadItems(): RecentEntity[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    const out: RecentEntity[] = [];
    for (const entry of parsed) {
      if (
        entry &&
        typeof entry === "object" &&
        typeof (entry as RecentEntity).type === "string" &&
        typeof (entry as RecentEntity).id === "string" &&
        typeof (entry as RecentEntity).title === "string" &&
        typeof (entry as RecentEntity).path === "string" &&
        typeof (entry as RecentEntity).at === "number"
      ) {
        out.push(entry as RecentEntity);
      }
    }
    return out.slice(0, MAX_ITEMS);
  } catch {
    return [];
  }
}

function saveItems(items: RecentEntity[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
  } catch {
    // localStorage unavailable / quota exceeded -- silently ignore.
  }
}

/**
 * Add one entry, deduplicating by `path`. Callers may pass a richer
 * title than the auto-derived one; a later add() with a better title
 * replaces the earlier record.
 */
export function addRecentEntity(entry: Omit<RecentEntity, "at">): RecentEntity[] {
  const now = Date.now();
  const next: RecentEntity = { ...entry, at: now };
  const existing = loadItems();
  const filtered = existing.filter((item) => item.path !== next.path);
  const updated = [next, ...filtered].slice(0, MAX_ITEMS);
  saveItems(updated);
  // Manually dispatch a storage event so the in-tab hook re-renders.
  // (Native `storage` events fire in OTHER tabs only.)
  try {
    window.dispatchEvent(new CustomEvent("aila:recent-entities-updated"));
  } catch {
    // ignore
  }
  return updated;
}

/** Read the current list without subscribing. */
export function listRecentEntities(): RecentEntity[] {
  return loadItems();
}

/** Wipe the store. Used by the palette's "Clear" affordance. */
export function clearRecentEntities(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
  try {
    window.dispatchEvent(new CustomEvent("aila:recent-entities-updated"));
  } catch {
    // ignore
  }
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export interface UseRecentEntitiesReturn {
  items: RecentEntity[];
  add: (entry: Omit<RecentEntity, "at">) => void;
  clear: () => void;
}

/**
 * Subscribe to the recent-entities store. Re-renders on same-tab
 * updates (via the custom event dispatched by `addRecentEntity`) and
 * cross-tab updates (via the native `storage` event).
 */
export function useRecentEntities(): UseRecentEntitiesReturn {
  const [items, setItems] = useState<RecentEntity[]>(() => loadItems());

  useEffect(() => {
    function refresh() {
      setItems(loadItems());
    }
    function handleStorage(event: StorageEvent) {
      if (event.key === STORAGE_KEY || event.key === null) refresh();
    }
    window.addEventListener("aila:recent-entities-updated", refresh);
    window.addEventListener("storage", handleStorage);
    return () => {
      window.removeEventListener("aila:recent-entities-updated", refresh);
      window.removeEventListener("storage", handleStorage);
    };
  }, []);

  const add = useCallback((entry: Omit<RecentEntity, "at">) => {
    const updated = addRecentEntity(entry);
    setItems(updated);
  }, []);

  const clear = useCallback(() => {
    clearRecentEntities();
    setItems([]);
  }, []);

  return { items, add, clear };
}

/**
 * Location observer -- when the current pathname matches a known
 * detail route, records a visit. Cheap: only runs the regex table
 * once per pathname change, and only writes when the path is new
 * (or its `at` needs bumping).
 *
 * Mounted at exactly one place in the shell (the always-mounted
 * command palette). Mounting more than once wastes writes but is
 * otherwise harmless (dedup happens in the store).
 */
export function useRecordEntityVisit(): void {
  const location = useLocation();
  useEffect(() => {
    const detected = detectEntityFromPath(location.pathname);
    if (!detected) return;
    addRecentEntity(detected);
  }, [location.pathname]);
}

// ---------------------------------------------------------------------------
// Entity-jump target catalogue
//
// Used by the palette when the operator types an id (or `#<id>`). We
// don't know the entity type from the id alone, so we offer every
// unambiguous detail route. Module-scoped defaults (VR investigation)
// are called out in the label so the operator knows which module the
// jump targets.
// ---------------------------------------------------------------------------

export interface EntityJumpTarget {
  type: string;
  label: string;
  build: (id: string) => string;
}

export const ENTITY_JUMP_TARGETS: readonly EntityJumpTarget[] = [
  { type: "task", label: "Task", build: (id) => `/tasks/${encodeURIComponent(id)}` },
  { type: "system", label: "System", build: (id) => `/systems/${encodeURIComponent(id)}` },
  {
    type: "cve",
    label: "CVE",
    build: (id) => `/vulnerability/findings/cve/${encodeURIComponent(id)}`,
  },
  {
    type: "vr-investigation",
    label: "VR Investigation",
    build: (id) => `/vr/investigations/${encodeURIComponent(id)}`,
  },
  {
    type: "vr-finding",
    label: "VR Finding",
    build: (id) => `/vr/findings/${encodeURIComponent(id)}`,
  },
  {
    type: "malware-investigation",
    label: "Malware Investigation",
    build: (id) => `/malware/investigations/${encodeURIComponent(id)}`,
  },
  {
    type: "malware-target",
    label: "Malware Target",
    build: (id) => `/malware/targets/${encodeURIComponent(id)}`,
  },
];

/**
 * Parse an entity-jump query. Accepts:
 *   - `#<id>`               -> { id, typeHint: null }
 *   - `#<type> <id>`        -> { id, typeHint: "<type>" }
 *   - bare id-looking token -> { id, typeHint: null }
 *
 * Returns null if the input is neither a `#`-prefixed jump nor an
 * id-looking bare token.
 */
export function parseEntityJump(
  query: string,
): { id: string; typeHint: string | null } | null {
  const trimmed = query.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith("#")) {
    const rest = trimmed.slice(1).trim();
    if (!rest) return null;
    const parts = rest.split(/\s+/);
    if (parts.length === 1) return { id: parts[0], typeHint: null };
    const [maybeType, ...idParts] = parts;
    return { id: idParts.join(" "), typeHint: maybeType.toLowerCase() };
  }
  if (looksLikeEntityId(trimmed)) {
    return { id: trimmed, typeHint: null };
  }
  return null;
}

/**
 * Resolve a jump query into the set of target routes to offer. When
 * `typeHint` is set we return only matching targets (fuzzy contains
 * match on the target label + type); otherwise every target is
 * returned so the operator can pick.
 */
export function resolveEntityJumpTargets(
  jump: { id: string; typeHint: string | null },
): EntityJumpTarget[] {
  if (!jump.typeHint) return [...ENTITY_JUMP_TARGETS];
  const hint = jump.typeHint;
  const matches = ENTITY_JUMP_TARGETS.filter(
    (target) =>
      target.type.toLowerCase().includes(hint) ||
      target.label.toLowerCase().includes(hint),
  );
  return matches.length > 0 ? matches : [...ENTITY_JUMP_TARGETS];
}
