# SSE Integration Guide

How to consume Server-Sent Events from AILA's three SSE endpoints.

---

## Overview

AILA exposes four SSE surfaces:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/scans/{run_id}/events` | GET | Scan progress (stage, percent, message) |
| `/tasks/{task_id}/events` | GET | Task progress (stage, percent, message) |
| `/forensics/projects/{project_id}/investigations/{investigation_id}/events` | GET | Forensic investigation agent progress |
| `/sessions/{session_id}/messages` | POST | Chat token streaming |

All require a valid JWT Bearer token. SSE responses use `Content-Type: text/event-stream` with `Cache-Control: no-cache` and `X-Accel-Buffering: no`.

---

## 1. Scan Progress SSE

### Endpoint

```
GET /scans/{run_id}/events?last_id=0
```

### Authentication

Bearer JWT token (reader+ role).

### Query Parameters

| Param | Default | Description |
|-------|---------|-------------|
| `last_id` | `0` | Redis Stream ID to start from. `0` = replay all events. |

### Event Format

Each `data:` line contains JSON:

```json
{"stage": "inventory", "message": "Collecting packages from arch-vm", "percent": "25", "timestamp": "2026-04-05T08:00:00Z"}
```

Fields:
- `stage` (str) -- workflow stage name (e.g., `inventory`, `advisory`, `scoring`, `reporting`)
- `message` (str) -- human-readable progress message
- `percent` (str) -- completion percentage 0-100
- `timestamp` (str) -- ISO-8601 UTC timestamp

Keepalive pings are sent every 30 seconds when no events arrive:

```json
{"type": "ping"}
```

### curl Example

```bash
# Get a JWT token first
TOKEN=$(curl -s -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "aila_sk_..."}' | jq -r .access_token)

# Submit a scan
RUN_ID=$(curl -s -X POST http://localhost:8000/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query_text": "scan all systems"}' | jq -r .run_id)

# Stream progress events
curl -N -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/scans/$RUN_ID/events?last_id=0"
```

### Late-Connect Replay

If you connect after events have been emitted, all past events are replayed via Redis XRANGE before live streaming begins. This is the late-connect replay pattern (D-17/TASK-09). Pass `last_id=0` to get all events from the beginning.

### No-Redis Fallback

If Redis is not configured, the endpoint returns a single informational event and closes:

```
data: {"message": "Redis not configured \u2014 no progress stream available"}
```

---

## 2. Task Progress SSE

### Endpoint

```
GET /tasks/{task_id}/events?last_id=0
```

Identical event format and behavior to scan progress. Uses the same `ProgressStream` infrastructure backed by Redis Streams.

### curl Example

```bash
# Submit a freeform task
TASK_ID=$(curl -s -X POST http://localhost:8000/task \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query_text": "explain top CVEs"}' | jq -r .run_id)

# Stream task progress
curl -N -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/tasks/$TASK_ID/events?last_id=0"
```

### Access Control

Task events are scoped by group_id. Admin role sees all tasks; other roles only see tasks belonging to their group.

---

## 3. Chat Streaming SSE

### Endpoint

```
POST /sessions/{session_id}/messages
```

### Content Negotiation

Send `Accept: text/event-stream` to receive streaming tokens. Without this header, the endpoint returns a single JSON response.

### Request Body

```json
{"content": "What are the most critical CVEs?"}
```

### Event Format (Token Stream)

Each `data:` line during streaming:

```json
{"token": "The", "type": "token"}
{"token": " most", "type": "token"}
{"token": " critical", "type": "token"}
```

Final event on completion:

```json
{"type": "done", "run_id": "uuid-if-scan-triggered"}
```

The `done` sentinel is emitted OUTSIDE the finally block -- only on normal completion, never on client disconnect.

### curl Example

```bash
# Create a session
SESSION_ID=$(curl -s -X POST http://localhost:8000/sessions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "My session"}' | jq -r .session_id)

# Stream chat response
curl -N -X POST "http://localhost:8000/sessions/$SESSION_ID/messages" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  -d '{"content": "What are the most exploitable CVEs?"}'
```

### Persistence

The complete assistant message is persisted to the database in the `finally` block after streaming completes. This ensures the full response is always saved regardless of how the stream ends.

### Client Disconnect

If the client disconnects mid-stream, `asyncio.CancelledError` is caught, the background task is cancelled, and the queue is discarded. The partial response is still persisted.

---

## 4. Forensics Investigation SSE

### Endpoint

```
GET /forensics/projects/{project_id}/investigations/{investigation_id}/events?last_id=0
```

### Authentication

Bearer JWT token (reader+ role). Team-scoped — you must own the project.

### Event Format

Identical to scan/task progress:

```json
{"stage": "reasoning", "message": "Checking prefetch artifacts for lateral movement", "percent": null}
{"stage": "script_exec", "message": "Running vol3 -f memory.dmp windows.pslist", "percent": null}
{"stage": "completed", "message": "Investigation complete", "percent": 100}
```

Terminal `event: done` is emitted when investigation status reaches `completed` or `failed`:

```
event: done
data: {"status": "completed"}
```

### No-stream Fallback

If Redis is unavailable or the investigation has no `task_id` yet (race between submit and SSE open):

```
data: {"message": "No progress stream available — Redis not configured or task not yet queued"}
```

### Frontend Hook

```typescript
import { useInvestigationEventFeed } from "@forensics/queries";

const { events, feedStatus } = useInvestigationEventFeed(projectId, investigationId);
// feedStatus: "idle" | "connecting" | "live" | "unavailable" | "closed" | "error"
// events: InvestigationEvent[]  — {stage, message, percent, timestamp}
```

Only open the feed when the investigation status is running (`queued | running | analyzing`). Pass empty strings to disable.

---

## Module SSE Standard

**Any AILA module that emits async progress MUST follow this pattern.**

### Backend Checklist

- [ ] Worker emits events via `ProgressStream.emit(task_id, {"stage": ..., "message": ..., "percent": ...})`
- [ ] Router exposes `GET /{resource}/{id}/events?last_id=0` returning `StreamingResponse`
- [ ] Endpoint does ownership check before opening the stream
- [ ] No-Redis guard: return single informational event and close
- [ ] Catchup via `stream.catchup(task_id, last_id)` on connect (late-join support)
- [ ] Live stream via `stream.stream_events(task_id, "$")` after catchup
- [ ] On each `ping` event: check DB for terminal status, emit `event: done` and return if terminal
- [ ] Terminal `event: done` emitted when resource reaches its terminal state
- [ ] `Cache-Control: no-cache` + `X-Accel-Buffering: no` response headers

### Frontend Checklist

- [ ] Hook uses `streamJsonEvents()` from `@platform/api/sse` (NOT `EventSource` — needs auth header)
- [ ] Hook uses `getAuthTokenStandalone()` to inject Bearer token
- [ ] `AbortController` for cleanup on unmount
- [ ] Only open feed when resource is in a running state (pass empty string to disable)
- [ ] Handle `"unavailable"` status gracefully (no Redis / not yet queued)
- [ ] Handle `event: done` by triggering a React Query cache invalidation

### asyncio Rules

- **NEVER** wrap `await task_queue.submit()` in `asyncio.to_thread()` — `submit` is `async def`
- **NEVER** call sync `session_scope()` directly inside `async def` — use `UnitOfWork` (async) or wrap in `asyncio.to_thread()`
- `ProgressStream.catchup()` and `stream_events()` are `async` — `await` / `async for` them directly

---

## JavaScript EventSource Example

For scan and task progress (GET endpoints):

```javascript
const token = 'your-jwt-token';
const runId = 'scan-run-id';

const eventSource = new EventSource(
  `http://localhost:8000/scans/${runId}/events?last_id=0`,
  { headers: { 'Authorization': `Bearer ${token}` } }
);

eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'ping') return; // keepalive
  console.log(`[${data.stage}] ${data.percent}% - ${data.message}`);
};

eventSource.onerror = () => {
  eventSource.close();
};
```

Note: The standard `EventSource` API does not support custom headers. Use a library like `eventsource` (Node.js) or `fetch` with `ReadableStream` for browser clients that need auth headers.

### Fetch-based SSE (Browser)

```javascript
async function streamSSE(url, token) {
  const response = await fetch(url, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const text = decoder.decode(value);
    for (const line of text.split('\n')) {
      if (line.startsWith('data: ')) {
        const data = JSON.parse(line.slice(6));
        console.log(data);
      }
    }
  }
}
```

---

## Redis Streams Architecture

SSE progress is backed by Redis Streams, not pub/sub.

- Key format: `task:{task_id}:progress`
- MAXLEN: 1000 events per stream (configurable via `AILA_PLATFORM_PROGRESS_STREAM_MAXLEN`)
- XADD for emit, XRANGE for catchup, XREAD (block=30s) for live streaming
- Late-connect clients replay the full event history from their `last_id`

### Tuning

| Config | Default | Env Var |
|--------|---------|---------|
| Stream max events | 1000 | `AILA_PLATFORM_PROGRESS_STREAM_MAXLEN` |
| XREAD block timeout | 30000ms | derived from heartbeat interval |
| Heartbeat interval | 30s | `AILA_PLATFORM_HEARTBEAT_INTERVAL_S` |

---

*Last updated: 2026-04-05 (v1.7)*
