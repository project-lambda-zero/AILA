import { useQuery } from "@tanstack/react-query";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { WindowPanel } from "@/components/aila/WindowPanel";

import { fetchHelloWorldStatus } from "./api";

export default function HelloWorldPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["hello_world", "status"],
    queryFn: fetchHelloWorldStatus,
  });

  const footer = isLoading
    ? "status ; polling module"
    : error
      ? "status ; unreachable"
      : data
        ? `module ; ${data.module}`
        : "status ; idle";

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-4">
      <WindowPanel
        title="module status"
        tone={error ? "warn" : data ? "ok" : "accent"}
        status={footer}
      >
        <div className="flex flex-col gap-4">
          <div
            className="font-mono uppercase text-muted-foreground"
            style={{ fontSize: "10.5px", letterSpacing: "0.14em" }}
          >
            reference module &middot; contract proof
          </div>

          {isLoading && (
            <p className="font-mono text-sm text-muted-foreground">Loading...</p>
          )}

          {error && (
            <p className="font-mono text-sm" style={{ color: "var(--color-critical)" }}>
              Failed to load status
            </p>
          )}

          {data && (
            <div className="flex flex-wrap items-center gap-3">
              <PixelIcon name="ok" size={16} style={{ color: "var(--color-mint)" }} />
              <AilaBadge status="completed">Active</AilaBadge>
              <span className="text-sm text-foreground">
                {data.module} reports status:{" "}
                <span className="font-mono" style={{ color: "var(--color-mint)" }}>
                  {data.status}
                </span>
              </span>
            </div>
          )}
        </div>
      </WindowPanel>
    </div>
  );
}
