/**
 * SchemaEditorScreen — lazy-loadable re-export for routes.tsx (Plan 03).
 *
 * Usage in routes.tsx:
 *   const SchemaEditorScreen = React.lazy(() => import("./screens/SchemaEditorScreen"));
 */
export { SchemaEditorPage as SchemaEditorScreen } from "../editor/SchemaEditorPage";

// Default export for React.lazy compatibility
export { SchemaEditorPage as default } from "../editor/SchemaEditorPage";
