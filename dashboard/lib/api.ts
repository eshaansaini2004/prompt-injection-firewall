const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const API_KEY = process.env.NEXT_PUBLIC_DASHBOARD_API_KEY;

function authHeaders(): Record<string, string> {
  return API_KEY ? { Authorization: `Bearer ${API_KEY}` } : {};
}

// Response shapes, mirroring the Pydantic models in src/pif/models.py. These are
// asserted, not validated — if the backend changes a field, TypeScript won't notice.
// Keep them in step with models.py.
export type Stats = {
  total_requests: number;
  blocked_total: number;
  blocked_today: number;
  block_rate: number;
  avg_latency_ms: number;
};

export type TimelineBucket = { hour: string; total: number; blocked: number };

export type AttackTypeCount = { attack_type: string; count: number };

export type AttackEvent = {
  id: string;
  timestamp: string;
  model: string | null;
  attack_type: string;
  confidence: number;
  blocked: boolean;
  payload_hash: string;
  payload_preview: string | null;
  layer_triggered: number;
  latency_ms: number;
};

async function apiFetch<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: "no-store", headers: authHeaders() });
  if (!res.ok) {
    throw new Error(`API error ${res.status}: ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export async function fetchStats() {
  return apiFetch<Stats>(`${BASE}/api/stats`);
}

// /api/events returns a page wrapper, not a bare array. It also caps limit at
// 200 server-side — ask for more and the request is rejected outright.
export const EVENTS_PAGE_MAX = 200;

export type EventsPage = { events: AttackEvent[]; limit: number; offset: number };

export async function fetchEvents(params?: {
  limit?: number;
  offset?: number;
  blocked_only?: boolean;
  attack_type?: string;
}) {
  const q = new URLSearchParams();
  if (params?.limit) q.set("limit", String(Math.min(params.limit, EVENTS_PAGE_MAX)));
  if (params?.offset) q.set("offset", String(params.offset));
  if (params?.blocked_only) q.set("blocked_only", "true");
  if (params?.attack_type) q.set("attack_type", params.attack_type);
  return apiFetch<EventsPage>(`${BASE}/api/events?${q}`);
}

/** Page through /api/events for the export. Stops on a short page or at `max`. */
export async function fetchAllEvents(max = 1000): Promise<AttackEvent[]> {
  const all: AttackEvent[] = [];
  while (all.length < max) {
    const limit = Math.min(EVENTS_PAGE_MAX, max - all.length);
    const page = await fetchEvents({ limit, offset: all.length });
    all.push(...page.events);
    if (page.events.length < limit) break;
  }
  return all;
}

export async function fetchTimeline(hours = 24) {
  return apiFetch<TimelineBucket[]>(`${BASE}/api/timeline?hours=${hours}`);
}

export async function fetchEvent(event_id: string) {
  return apiFetch<AttackEvent>(`${BASE}/api/events/${event_id}`);
}

export async function fetchAttackTypes() {
  return apiFetch<AttackTypeCount[]>(`${BASE}/api/attack-types`);
}

export function createEventSocket(onEvent: (event: unknown) => void): { close: () => void } {
  const wsUrl = BASE.replace(/^http/, "ws");
  let ws: WebSocket | null = null;
  let closed = false;
  let retryTimeout: ReturnType<typeof setTimeout> | null = null;

  function connect() {
    if (closed) return;
    ws = new WebSocket(`${wsUrl}/ws/events`);

    ws.onopen = () => {
      if (API_KEY) ws!.send(JSON.stringify({ token: API_KEY }));
    };

    ws.onmessage = (e) => {
      try {
        onEvent(JSON.parse(e.data));
      } catch {
        // ignore malformed frames
      }
    };

    ws.onclose = () => {
      if (!closed) {
        // Reconnect after 3 seconds
        retryTimeout = setTimeout(connect, 3000);
      }
    };

    ws.onerror = () => {
      ws?.close();
    };
  }

  connect();

  return {
    close() {
      closed = true;
      if (retryTimeout) clearTimeout(retryTimeout);
      ws?.close();
    },
  };
}
