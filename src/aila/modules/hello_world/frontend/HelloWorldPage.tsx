import { useQuery } from "@tanstack/react-query";

import { MonoBadge, SectionHeader } from "@/components/aila/mock";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { WindowPanel } from "@/components/aila/WindowPanel";

import { fetchHelloWorldStatus } from "./api";

export default function HelloWorldPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["hello_world", "status"],
    queryFn: fetchHelloWorldStatus,
  });

  const footer = isLoading
    ? "status \u00b7 polling module"
    : error
      ? "status \u00b7 unreachable"
      : data
        ? `module \u00b7 ${data.module}`
        : "status \u00b7 idle";

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col" style={{ gap: 16 }}>
      <SectionHeader
        icon={<PixelIcon name="terminal" size={16} />}
        title="hello world \u00b7 reference module"
      />

      <WindowPanel
        title="module status"
        tone={error ? "warn" : data ? "ok" : "accent"}
        status={footer}
      >
        <div className="flex flex-col" style={{ gap: 14 }}>
          <div
            className="font-mono uppercase"
            style={{ fontSize: 10.5, letterSpacing: "0.14em", color: "var(--text-muted)" }}
          >
            reference module &middot; contract proof
          </div>

          {isLoading && (
            <p
              className="font-mono"
              style={{ fontSize: 12, margin: 0, color: "var(--text-muted)" }}
            >
              loading&hellip;
            </p>
          )}

          {error && (
            <p
              className="font-mono"
              style={{ fontSize: 12, margin: 0, color: "var(--accent)" }}
            >
              failed to load status
            </p>
          )}

          {data && (
            <div className="flex flex-wrap items-center" style={{ gap: 12 }}>
              <PixelIcon name="ok" size={16} style={{ color: "var(--status-ok)" }} />
              <MonoBadge tone="ok">active</MonoBadge>
              <span
                className="font-mono"
                style={{ fontSize: 12, color: "var(--text-primary)" }}
              >
                {data.module} reports status:{" "}
                <span style={{ color: "var(--status-ok)" }}>{data.status}</span>
              </span>
            </div>
          )}
        </div>
      </WindowPanel>
    </div>
  );
}
