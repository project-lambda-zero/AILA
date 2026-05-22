import { useQuery } from "@tanstack/react-query";

import { PageFrame } from "@app/layout/PageFrame";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";

import { fetchHelloWorldStatus } from "./api";

export default function HelloWorldPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["hello_world", "status"],
    queryFn: fetchHelloWorldStatus,
  });

  return (
    <PageFrame title="Hello World">
      <AilaCard  techBorder glow><div className="space-y-4">
        <h2 className="text-lg font-semibold text-text">Module Status</h2>
        {isLoading && <p className="text-text-muted">Loading...</p>}
        {error && <p className="text-critical">Failed to load status</p>}
        {data && (
          <div className="flex items-center gap-2">
            <AilaBadge status="completed">Active</AilaBadge>
            <span className="text-text-muted">
              {data.module} reports status: {data.status}
            </span>
          </div>
        )}
      </div></AilaCard>
    </PageFrame>
  );
}
