import { lazy } from "react";

// Monaco is heavy; load it only when a code block is actually rendered. One
// lazy wrapper for the whole X-Ray tree so every consumer shares the chunk.
export const LazyCodeBlock = lazy(() => import("../CodeBlock"));
