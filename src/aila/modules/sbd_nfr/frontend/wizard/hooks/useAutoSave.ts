import { useCallback, useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { requestJson } from "@platform/api/http";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";

import type { AnswerInput } from "../../types";

const DEBOUNCE_MS = 1500;

export interface AutoSaveResult {
  recordAnswer: (answer: AnswerInput) => void;
  flushNow: () => void;
}

/**
 * Debounced 1.5s auto-save hook for wizard answers (D-08, Pattern 4).
 *
 * pendingRef accumulates AnswerInput objects, merging by question_id so the
 * last value wins.  On timer expiry the accumulated answers are sent as a
 * single PATCH to the section answers endpoint.
 *
 * flushNow() cancels the timer and fires the save immediately — callers must
 * invoke it before section navigation (Pitfall 4).
 *
 * Security (T-137-04): 1.5s debounce prevents rapid-fire PATCH flooding.
 */
export function useAutoSave(sessionId: string, sectionKey: string): AutoSaveResult {
  const queryClient = useQueryClient();

  // Map from question_id -> AnswerInput; last-write wins on duplicate question_id
  const pendingRef = useRef<Map<string, AnswerInput>>(new Map());
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const flush = useCallback(async () => {
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    const pending = pendingRef.current;
    if (pending.size === 0) {
      return;
    }
    const answers = Array.from(pending.values());
    // Clear before the async call so a concurrent recordAnswer doesn't get
    // swallowed by the clear after the response arrives.
    pendingRef.current = new Map();

    const token = await getAuthTokenStandalone();
    await requestJson(
      `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/sections/${encodeURIComponent(sectionKey)}/answers`,
      {
        method: "PATCH",
        body: { answers },
        token,
      },
    );
    void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "session", sessionId] });
  }, [queryClient, sectionKey, sessionId]);

  const recordAnswer = useCallback(
    (answer: AnswerInput) => {
      // Merge by question_id — last value wins
      pendingRef.current.set(answer.question_id, answer);

      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
      }
      timerRef.current = setTimeout(() => {
        timerRef.current = null;
        void flush();
      }, DEBOUNCE_MS);
    },
    [flush],
  );

  // Flush on sectionKey change (before unmount / navigation)
  useEffect(() => {
    return () => {
      void flush();
    };
    // flush is stable; this effect depends only on sectionKey to re-run on section change
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sectionKey]);

  return { recordAnswer, flushNow: flush };
}
