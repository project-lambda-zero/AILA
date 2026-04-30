/**
 * types.ts — Local TypeScript types for the Radar feature (Phase 144).
 * Maps 1:1 to TopologyNode/TopologyEdge shapes from GET /topology.
 */

export type ColorByMode = "vulnerabilities" | "services" | "distro" | "connectivity";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface PortInfo {
  port: number;
  protocol: string;
  local_address: string;
  process_name: string | null;
}

export interface ServiceInfo {
  service_name: string;
  state: string;
  sub_state: string;
}

export interface SystemMetadata {
  gateway_ip: string | null;
  gateway_interface: string | null;
  external_ip: string | null;
  os_name: string | null;
  os_pretty_name: string | null;
  kernel: string | null;
  cpu_cores: number | null;
  memory_mb: number | null;
  disk_gb: number | null;
  uptime_seconds: number | null;
  last_collected: string | null;
  is_stale: boolean;
}

export interface TopologyNode {
  id: number;
  name: string;
  host: string;
  distro: string;
  subnet: string | null;
  group_tags: string[];
  ports: PortInfo[];
  services: ServiceInfo[];
  severity_counts: SeverityCounts | null;
  last_collected: string | null;
  is_stale: boolean;
  metadata?: SystemMetadata | null;
}

export interface TopologyEdge {
  source_system_id: number;
  dest_system_id: number;
  dest_port: number;
  protocol: string;
  state: string;
  is_stale: boolean;
}

export interface SubnetGroup {
  subnet_prefix: string;
  system_ids: number[];
}

export interface TopologyResponse {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  subnets: SubnetGroup[];
}

export interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

export interface RadarFilter {
  search: string;
  severities: string[]; // e.g. ["critical","high"] — empty means all
}
