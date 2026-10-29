import { Suspense, useEffect, useState, type JSX } from "react";

import { useDraftPoc, useVrFinding } from "../../../../api/hooks";
import { readStr } from "../../../../api/parse";
import type { Investigation, Message } from "../../../../api/types";
import { css } from "../../../css";
import { toast } from "../../../toast";
import { ActButton, actionRow, fieldStyle, formLabel } from "../actions";
import { LazyCodeBlock } from "../LazyCode";
import { H, emptyNote } from "../theme";

// The draft runs on the VR worker; stop polling once it has had this long.
const DRAFT_POLL_LIMIT_MS = 180_000;

interface PendingDraft {
  findingId: string;
  baseline: string | null;
  startedAt: number;
}

// PROOF OF CONCEPT pane body: the linked finding's stored PoC (falling back
// to the transcript's PoC turn) and an operator "draft PoC" action that
// queues an LLM draft and polls the finding until its PoC code changes.
export function PocPanelBody({ inv, pocMsg }: { inv: Investigation | undefined; pocMsg: Message | undefined }): JSX.Element {
  const findingIds = inv?.linked_finding_ids ?? [];
  const [picked, setPicked] = useState("");
  const findingId = findingIds.includes(picked) ? picked : (findingIds[0] ?? null);
  const [pending, setPending] = useState<PendingDraft | null>(null);
  const polling = pending !== null && pending.findingId === findingId;
  const finding = useVrFinding(findingId, polling);
  const draft = useDraftPoc();

  const storedCode = finding.data?.poc?.code ?? null;
  useEffect(() => {
    if (!pending || pending.findingId !== findingId) return;

    if (storedCode !== pending.baseline) {
      toast.success("PoC draft ready");
      setPending(null);
    } else if (Date.now() - pending.startedAt > DRAFT_POLL_LIMIT_MS) {
      toast.info("PoC draft still running; reopen this view later to see it");
      setPending(null);
    }
  }, [pending, findingId, storedCode, finding.dataUpdatedAt]);

  const startDraft = (): void => {
    if (!findingId) return;
    draft.mutate(findingId, {
      onSuccess: () => {
        toast.info("PoC draft queued");
        setPending({ findingId, baseline: storedCode, startedAt: Date.now() });
      },
      onError: (err) => toast.fail("draft PoC", err),
    });
  };

  const poc = finding.data?.poc ?? null;

  const transcriptCode = pocMsg
    ? (readStr(pocMsg.payload, "script_content") ?? readStr(pocMsg.payload, "code") ?? readStr(pocMsg.payload, "pseudocode") ?? "")
    : "";

  const code = poc?.code ?? transcriptCode;
  const language = poc?.language ?? (pocMsg ? readStr(pocMsg.payload, "language") : null) ?? "python";

  return (
    <div style={css("padding:8px;display:flex;flex-direction:column;gap:8px;")}>
      <div style={actionRow}>
        {findingIds.length > 1 ? (
          <>
            <span style={formLabel}>finding</span>
            <select value={findingId ?? ""} onChange={(e) => setPicked(e.target.value)} aria-label="finding" style={fieldStyle}>
              {findingIds.map((id) => <option key={id} value={id}>{id.slice(0, 8)}</option>)}
            </select>
          </>
        ) : findingId ? (
          <span style={formLabel}>finding {findingId.slice(0, 8)}</span>
        ) : (
          <span style={formLabel}>no linked finding; drafting needs a dispatched finding</span>
        )}
        <span style={css("flex:1;")} />
        {poc ? (
          <span style={css(`font-size:11px;color:${poc.crashes_patched === 0 && poc.crashes_vulnerable > 0 ? H.mint : "var(--text-muted)"};`)}>
            {`vuln ${poc.crashes_vulnerable}/5 · patched ${poc.crashes_patched}/1`}
          </span>
        ) : null}
        <ActButton
          label={code ? "redraft PoC" : "draft PoC"}
          pendingLabel="queueing…"
          tone="accent"
          disabled={!findingId || !finding.isSuccess || polling}
          pending={draft.isPending}
          onClick={startDraft}
        />
      </div>
      {polling ? <div style={css(`font-size:11px;color:${H.amber};`)}>drafting on the VR worker; polling the finding…</div> : null}
      {code ? (
        <Suspense fallback={<div style={emptyNote}>loading editor…</div>}>
          <LazyCodeBlock code={code} language={language} />
        </Suspense>
      ) : (
        <div style={emptyNote}>no proof-of-concept drafted yet.</div>
      )}
    </div>
  );
}
