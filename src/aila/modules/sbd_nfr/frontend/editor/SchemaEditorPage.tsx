import { useMemo, useState } from "react";

import { Eye, CloudArrowUp, Warning } from "@phosphor-icons/react";

import { EmptyState } from "@/components/aila/EmptyState";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import { useSchemaTree, useSchemaVersion } from "./api";
import { BlueprintCanvas } from "./BlueprintCanvas";
import { QuestionEditorDrawer } from "./QuestionEditorDrawer";
import { SubtaskMappingEditor } from "./SubtaskMappingEditor";
import { ConditionalLogicVisualizer } from "./ConditionalLogicVisualizer";
import { PublishVersionDialog } from "./PublishVersionDialog";
import { LivePreviewDrawer } from "./LivePreviewDrawer";
import { collectEditorQuestions, toEditorSections } from "./treeModel";

interface DrawerState {
  open: boolean;
  questionId: string | null;
  subgroupId: string;
}

const CLOSED_DRAWER: DrawerState = {
  open: false,
  questionId: null,
  subgroupId: "",
};

export function SchemaEditorPage() {
  const schemaTreeQuery = useSchemaTree();
  const versionQuery = useSchemaVersion();

  const [drawerState, setDrawerState] = useState<DrawerState>(CLOSED_DRAWER);
  const [publishOpen, setPublishOpen] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<"editor" | "mappings" | "logic">("editor");

  const sections = useMemo(() => toEditorSections(schemaTreeQuery.data), [schemaTreeQuery.data]);
  const allQuestions = useMemo(() => collectEditorQuestions(schemaTreeQuery.data), [schemaTreeQuery.data]);
  const activeQuestion = drawerState.questionId
    ? (allQuestions.find((question) => question.id === drawerState.questionId) ?? null)
    : null;

  function openEditDrawer(questionId: string, subgroupId: string) {
    setDrawerState({ open: true, questionId, subgroupId });
  }

  function openAddDrawer(subgroupId: string) {
    setDrawerState({ open: true, questionId: null, subgroupId });
  }

  function closeDrawer() {
    setDrawerState(CLOSED_DRAWER);
  }

  const version = versionQuery.data?.version;
  const subgroupCount = sections.reduce((total, section) => total + section.subgroups.length, 0);
  const conditionalCount = sections.reduce(
    (total, section) => total + (section.depends_on_question_id || section.condition_expr_json ? 1 : 0),
    0,
  ) + allQuestions.reduce(
    (total, question) => total + (question.depends_on_question_id || question.condition_expr_json ? 1 : 0),
    0,
  );
  return (
    <div className="flex flex-col gap-6 min-h-screen bg-base p-4 lg:p-6">
      <AilaCard variant="elevated" padding="lg" className="bg-elevated border-border" techBorder glow><div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
        <div className="space-y-3">
          <p className="font-mono text-xs uppercase tracking-[0.3em] text-text-muted">Blueprint Schema Studio</p>
          <div className="flex flex-wrap items-center gap-2">
            {version !== undefined && <AilaBadge severity="medium" size="sm">Schema v{version}</AilaBadge>}
            {versionQuery.data?.published_at === null && <AilaBadge severity="high" size="sm">Draft</AilaBadge>}
            <AilaBadge severity="info" size="sm">{sections.length} sections</AilaBadge>
            <AilaBadge severity="info" size="sm">{subgroupCount} subgroups</AilaBadge>
            <AilaBadge severity="info" size="sm">{allQuestions.length} questions</AilaBadge>
            <AilaBadge severity={conditionalCount > 0 ? "medium" : "neutral"} size="sm">{conditionalCount} logic links</AilaBadge>
          </div>
        </div>
      
        <div className="flex flex-col gap-3 xl:items-end">
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => setPreviewOpen(true)}
              className="font-mono text-xs"
            >
              <Eye className="mr-1.5 h-4 w-4" />
              Preview Wizard
            </Button>
            <Button
              type="button"
              disabled={version === undefined}
              onClick={() => setPublishOpen(true)}
              className="font-mono text-xs"
            >
              <CloudArrowUp className="mr-1.5 h-4 w-4" />
              {version !== undefined ? `Publish v${version + 1}` : "Publish"}
            </Button>
          </div>
          <p className="font-mono text-[11px] text-text-muted">
            {versionQuery.data?.published_at
              ? `Published ${new Date(versionQuery.data.published_at).toLocaleDateString()}`
              : "Draft changes are local until you publish a new schema version."}
          </p>
        </div>
      </div></AilaCard>

      <div className="flex-1">
        <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as "editor" | "mappings" | "logic")} className="flex flex-col gap-4">
          <TabsList className="w-fit border border-border bg-surface">
            <TabsTrigger value="editor" className="font-mono text-xs">
              Editor
            </TabsTrigger>
            <TabsTrigger value="mappings" className="font-mono text-xs">
              Mappings
            </TabsTrigger>
            <TabsTrigger value="logic" className="font-mono text-xs">
              Logic
            </TabsTrigger>
          </TabsList>
          <TabsContent value="editor" className="mt-0">
            {schemaTreeQuery.isPending && (
              <div className="flex h-[400px] items-center justify-center rounded-[6px] border border-border bg-base">
                <p className="animate-pulse font-mono text-sm text-text-muted">Loading blueprint canvas…</p>
              </div>
            )}
            {schemaTreeQuery.isError && (
              <EmptyState
                icon={<Warning className="h-10 w-10 text-accent" />}
                title="Failed to load schema"
                description={schemaTreeQuery.error instanceof Error ? schemaTreeQuery.error.message : "Unknown error"}
              />
            )}
            {!schemaTreeQuery.isPending && !schemaTreeQuery.isError && (
              <BlueprintCanvas
                sections={sections}
                onEditQuestion={openEditDrawer}
                onAddQuestion={openAddDrawer}
              />
            )}
          </TabsContent>
          <TabsContent value="mappings" className="mt-0">
            <SubtaskMappingEditor />
          </TabsContent>
          <TabsContent value="logic" className="mt-0">
            <ConditionalLogicVisualizer />
          </TabsContent>
        </Tabs>
      </div>

      <QuestionEditorDrawer
        question={activeQuestion}
        subgroupId={drawerState.subgroupId}
        open={drawerState.open}
        onClose={closeDrawer}
      />

      {version !== undefined && (
        <PublishVersionDialog
          open={publishOpen}
          onClose={() => setPublishOpen(false)}
          currentVersion={version}
        />
      )}

      <LivePreviewDrawer open={previewOpen} onClose={() => setPreviewOpen(false)} />
    </div>
  );
}
