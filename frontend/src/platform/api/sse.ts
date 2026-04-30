import { buildApiError, buildApiUrl } from "@platform/api/http";

export interface JsonSseEvent<TData> {
  event: string | null;
  id: string | null;
  data: TData;
}

interface StreamJsonEventsOptions<TData> {
  token: string;
  signal?: AbortSignal;
  onEvent: (event: JsonSseEvent<TData>) => void;
}

function emitEvent<TData>(
  eventName: string | null,
  eventId: string | null,
  dataLines: string[],
  onEvent: (event: JsonSseEvent<TData>) => void,
): void {
  if (dataLines.length === 0) {
    return;
  }
  const payloadText = dataLines.join("\n");
  onEvent({
    event: eventName,
    id: eventId,
    data: JSON.parse(payloadText) as TData,
  });
}

export async function streamJsonEvents<TData>(
  pathname: string,
  options: StreamJsonEventsOptions<TData>,
): Promise<void> {
  const response = await fetch(buildApiUrl(pathname), {
    headers: {
      Accept: "text/event-stream",
      Authorization: `Bearer ${options.token}`,
    },
    signal: options.signal,
  });

  if (!response.ok) {
    throw await buildApiError(response);
  }

  if (!response.body) {
    throw new Error("The server did not provide an event stream body.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let currentEvent: string | null = null;
  let currentId: string | null = null;
  let currentData: string[] = [];

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split(/\r?\n/);
    buffer = lines.pop() ?? "";

    for (const line of lines) {
      if (line === "") {
        emitEvent(currentEvent, currentId, currentData, options.onEvent);
        currentEvent = null;
        currentId = null;
        currentData = [];
        continue;
      }
      if (line.startsWith(":")) {
        continue;
      }
      if (line.startsWith("event:")) {
        currentEvent = line.slice(6).trim();
        continue;
      }
      if (line.startsWith("id:")) {
        currentId = line.slice(3).trim();
        continue;
      }
      if (line.startsWith("data:")) {
        currentData.push(line.slice(5).trimStart());
      }
    }
  }

  if (buffer.trim() || currentData.length > 0) {
    if (buffer.trim().startsWith("data:")) {
      currentData.push(buffer.trim().slice(5).trimStart());
    }
    emitEvent(currentEvent, currentId, currentData, options.onEvent);
  }
}
