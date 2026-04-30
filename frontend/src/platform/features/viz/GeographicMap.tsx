/**
 * GeographicMap — VIZ-04.
 *
 * Leaflet map showing topology nodes as CircleMarkers.
 * Nodes are placed using lat/lng extracted from group_tags.
 * Tag format: "lat:52.5200" or "lng:13.4050" (case-insensitive).
 *
 * Skips nodes where lat/lng cannot be parsed or are out of range.
 * Graceful empty state when no geo-tagged nodes are found.
 *
 * Data source: useTopology() — no extra API call.
 * Circle color derived from dominant severity.
 */
import * as React from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useTopology } from "@platform/features/radar/useTopology";
import type { TopologyNode } from "@platform/features/radar/types";
import { dominantSeverity } from "@platform/features/radar/topologyUtils";

// ---------------------------------------------------------------------------
// Severity → inline hex color (CSS vars not resolved by Leaflet canvas)
// ---------------------------------------------------------------------------

const SEVERITY_HEX: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#9ca3af",
  none: "#6b7280",
};

function markerColor(node: TopologyNode): string {
  const sev = dominantSeverity(node.severity_counts);
  return SEVERITY_HEX[sev] ?? SEVERITY_HEX.none;
}

// ---------------------------------------------------------------------------
// Geo coordinate parsing
// ---------------------------------------------------------------------------

interface GeoCoords {
  lat: number;
  lng: number;
}

/**
 * Parse lat/lng from group_tags strings.
 * Accepts formats: "lat:52.5200", "lng:13.4050", "lat=52.5200", "lng=13.4050"
 * Returns null if either coordinate is missing, NaN, or out of range.
 */
function parseGeoCoords(tags: string[]): GeoCoords | null {
  let lat: number | null = null;
  let lng: number | null = null;

  for (const tag of tags) {
    const latMatch = tag.match(/lat[=:]([-\d.]+)/i);
    const lngMatch = tag.match(/lng[=:]([-\d.]+)/i);

    if (latMatch) {
      const v = parseFloat(latMatch[1]);
      if (!isNaN(v) && v >= -90 && v <= 90) {
        lat = v;
      }
    }
    if (lngMatch) {
      const v = parseFloat(lngMatch[1]);
      if (!isNaN(v) && v >= -180 && v <= 180) {
        lng = v;
      }
    }
  }

  if (lat !== null && lng !== null) return { lat, lng };
  return null;
}

// ---------------------------------------------------------------------------
// Mapped node type
// ---------------------------------------------------------------------------

interface GeoNode {
  node: TopologyNode;
  lat: number;
  lng: number;
  color: string;
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface GeographicMapProps {
  className?: string;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function GeographicMap({ className }: GeographicMapProps) {
  const { data: topology, isLoading } = useTopology();

  if (isLoading) {
    return (
      <AilaCard className={className}>
        <div className="p-4 flex flex-col gap-2">
          <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">
            System Geographic Map
          </p>
          <LoadingSkeleton size="xl" width="full" />
        </div>
      </AilaCard>
    );
  }

  const nodes = topology?.nodes ?? [];

  // Extract nodes with valid geo coordinates
  const geoNodes: GeoNode[] = [];
  for (const node of nodes) {
    const coords = parseGeoCoords(node.group_tags);
    if (coords) {
      geoNodes.push({
        node,
        lat: coords.lat,
        lng: coords.lng,
        color: markerColor(node),
      });
    }
  }

  return (
    <AilaCard className={className}>
      <div className="p-4">
        <div className="flex items-center justify-between mb-3">
          <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">
            System Geographic Map
          </p>
        </div>

        {geoNodes.length === 0 ? (
          <div className="py-6 text-center">
            <p className="font-mono text-xs text-muted-foreground">
              No geographic data available.
            </p>
            <p className="font-mono text-[10px] text-muted-foreground/70 mt-1">
              Add lat/lng tags to systems using format: lat:52.5200 lng:13.4050
            </p>
          </div>
        ) : (
          <MapContainer
            center={[20, 0]}
            zoom={2}
            className="h-[400px] w-full rounded"
            scrollWheelZoom={false}
          >
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            {geoNodes.map((item) => (
              <CircleMarker
                key={item.node.id}
                center={[item.lat, item.lng]}
                radius={8}
                pathOptions={{
                  fillColor: item.color,
                  fillOpacity: 0.8,
                  color: item.color,
                  weight: 2,
                }}
              >
                <Popup>
                  <strong>{item.node.name}</strong>
                  <br />
                  {item.node.host}
                  <br />
                  {item.node.distro}
                  {item.node.is_stale && (
                    <>
                      <br />
                      <span style={{ color: "#9ca3af", fontSize: "10px" }}>[stale]</span>
                    </>
                  )}
                </Popup>
              </CircleMarker>
            ))}
          </MapContainer>
        )}
      </div>
    </AilaCard>
  );
}
