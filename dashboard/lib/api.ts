const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const API_KEY = process.env.NEXT_PUBLIC_DASHBOARD_API_KEY;

function authHeaders(): Record<string, string> {
  return API_KEY ? { Authorization: `Bearer ${API_KEY}` } : {};
}

async function apiFetch(url: string): Promise<unknown> {
  const res = await fetch(url, { cache: "no-store", headers: authHeaders() });
  if (!res.ok) {
    throw new Error(`API error ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchStats() {
  return apiFetch(`${BASE}/api/stats`);
}

export async function fetchEvents(params?: {
  limit?: number;
  offset?: number;
  blocked_only?: boolean;
  attack_type?: string;
}) {
  const q = new URLSearchParams();
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  if (params?.blocked_only) q.set("blocked_only", "true");
  if (params?.attack_type) q.set("attack_type", params.attack_type);
  return apiFetch(`${BASE}/api/events?${q}`);
}

export async function fetchTimeline(hours = 24) {
  return apiFetch(`${BASE}/api/timeline?hours=${hours}`);
}

export async function fetchEvent(event_id: string) {
  return apiFetch(`${BASE}/api/events/${event_id}`);
}

export async function fetchAttackTypes() {
  return apiFetch(`${BASE}/api/attack-types`);
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
