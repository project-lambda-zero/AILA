import { create } from "zustand";

/**
 * Shared publisher for the live chat session and the operator-acted message
 * ids. ChatConsole is the sole writer (mirrors its local `chatSessionId` and
 * `acted` Set into this store); widgets read it. The widget subsystem uses
 * this to render pending dante proposals in a floater without owning the
 * chat's confirm/dismiss logic -- the operator acts in the chat, ChatConsole
 * updates `acted`, and the widget observes the same state.
 */
interface ChatSessionState {
  sessionId: string | null;
  actedMessageIds: string[];
  setSessionId: (id: string | null) => void;
  setActedMessageIds: (ids: string[]) => void;
}

export const useChatSession = create<ChatSessionState>((set) => ({
  sessionId: null,
  actedMessageIds: [],
  setSessionId: (id) => set({ sessionId: id }),
  setActedMessageIds: (ids) => set({ actedMessageIds: ids }),
}));
