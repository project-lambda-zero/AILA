/** LeftRail data source for the forensics module.
 *
 * The rail's bottom list is one row per project (GET /forensics/projects,
 * paginated envelope keyed under `items`). Rows are mapped to the small
 * `RailRow` shape LeftRail consumes (id, title, status, is_favorite, plus a
 * synthetic activity weight the rail uses to sort data-rich projects first).
 * Clicking a row opens ForensicsProjectPage for that project id.
 */
import { useQuery } from "@tanstack/react-query";
import type { UseQueryResult } from "@tanstack/react-query";

import { apiFetch } from "./client";

/** Minimum row shape the LeftRail's investigation list consumes. Kept
 * structurally compatible with `Investigation` and `MalwareInvestigation`
 * so a single rendering path works across all module data sources. */
export interface RailRow {
  id: string;
  title: string;
  status?: string;
  is_favorite?: boolean;
  /** Fed into the rail's sort weight; forensics projects have no branch/
   * message counts so we synthesise from activity counts. */
  branch_count?: number;
  message_count?: number;
}

/** Subset of the /forensics/projects response fields we consume for the
 * rail (mirrors ProjectSummary in the forensics page module). */
interface ProjectRow {
  id: string;
  name: string;
  status: string;
  evidence_count: number;
  artifact_count: number;
  lead_count: number;
  investigation_count: number;
}

interface ProjectListEnvelope {
  items: ProjectRow[];
  total?: number;
}

function mapProject(p: ProjectRow): RailRow {
  return {
    id: p.id,
    title: p.name,
    status: p.status,
    is_favorite: false,
    // Weight investigations heaviest (they mirror VR branches), then leads,
    // then evidence -- so a project the analyst has actually driven surfaces
    // above a freshly-created shell.
    branch_count: p.investigation_count ?? 0,
    message_count:
      (p.lead_count ?? 0) * 10 + (p.evidence_count ?? 0) + (p.artifact_count ?? 0),
  };
}

export function useForensicsProjects(): UseQueryResult<RailRow[]> {
  return useQuery({
    queryKey: ["forensics", "projects", "rail"],
    queryFn: () =>
      apiFetch<ProjectListEnvelope>("/forensics/projects?page_size=100"),
    select: (env) => (env.items ?? []).map(mapProject),
    staleTime: 15_000,
  });
}
