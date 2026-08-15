/**
 * GeographicMap -- VIZ-04 (mock rebuild).
 *
 * Leaflet map inside a WindowPanel. Marker colors driven by
 * useThemeChartColors so severity fills track the active theme
 * (Leaflet renders to canvas / SVG that cannot resolve CSS vars).
 */
import * as React from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { MonoBadge } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { useTopology } from "@platform/features/radar/useTopology";
import type { TopologyNode } from "@platform/features/radar/types";
import { dominantSeverity } from "@platform/features/radar/topologyUtils";
import { useThemeChartColors } from "./chartColors";

interface GeoCoords {
  lat: number;
  lng: number;
}

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

interface GeoNode {
  node: TopologyNode;
  lat: number;
  lng: number;
  color: string;
}

interface GeographicMapProps {
  className?: string;
}

export function GeographicMap({ className }: GeographicMapProps) {
  const { data: topology, isLoading } = useTopology();
  const colors = useThemeChartColors();

  const severityHex: Record<string, string> = {
    critical: colors.critical,
    high: colors.high,
    medium: colors.medium,
    low: colors.low,
    none: colors.textMuted,
  };

  if (isLoading) {
    return (
      <WindowPanel title="system geographic map" tone="muted" status="LOADING" className={className}>
        <LoadingSkeleton size="xl" width="full" />
      </WindowPanel>
    );
  }

  const nodes = topology?.nodes ?? [];
  const geoNodes: GeoNode[] = [];
  for (const node of nodes) {
    const coords = parseGeoCoords(node.group_tags);
    if (coords) {
      const sev = dominantSeverity(node.severity_counts);
      geoNodes.push({
        node,
        lat: coords.lat,
        lng: coords.lng,
        color: severityHex[sev] ?? severityHex.none,
      });
    }
  }

  return (
    <WindowPanel title="system geographic map" className={className}>
      <div className="flex flex-col" style={{ gap: 10 }}>
        {geoNodes.length === 0 ? (
          <div
            className="flex flex-col items-center font-mono text-center"
            style={{ padding: "18px 0", gap: 6, color: "var(--text-muted)" }}
          >
            <span style={{ fontSize: 11 }}>no geographic data available.</span>
            <span style={{ fontSize: 10, color: "var(--text-faint)" }}>
              add lat/lng tags to systems using format: lat:52.5200 lng:13.4050
            </span>
          </div>
        ) : (
          <>
            <div
              style={{
                height: 400,
                width: "100%",
                borderRadius: 3,
                overflow: "hidden",
                border: "1px solid var(--border-faint)",
              }}
            >
              <MapContainer
                center={[20, 0]}
                zoom={2}
                style={{ height: "100%", width: "100%" }}
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
                      fillOpacity: 0.85,
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
                          <span style={{ color: "var(--text-faint)", fontSize: 10 }}>[stale]</span>
                        </>
                      )}
                    </Popup>
                  </CircleMarker>
                ))}
              </MapContainer>
            </div>
            {/* Legend */}
            <div className="flex items-center flex-wrap" style={{ gap: 6 }}>
              <MonoBadge tone="critical">CRITICAL</MonoBadge>
              <MonoBadge tone="high">HIGH</MonoBadge>
              <MonoBadge tone="medium">MEDIUM</MonoBadge>
              <MonoBadge tone="low">LOW</MonoBadge>
            </div>
          </>
        )}
      </div>
    </WindowPanel>
  );
}
