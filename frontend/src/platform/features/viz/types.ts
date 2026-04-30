/**
 * types.ts — Local types for the Viz feature (Phase 144, Plan 02).
 */

export interface SeverityFacets {
  CRITICAL?: number;
  HIGH?: number;
  MEDIUM?: number;
  LOW?: number;
  [key: string]: number | undefined;
}

export interface TrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface SystemHeatmapCell {
  systemId: number;
  systemName: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}
