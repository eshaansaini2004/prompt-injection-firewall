const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const API_KEY = process.env.NEXT_PUBLIC_DASHBOARD_API_KEY;

function authHeaders(): Record<string, string> {
  return API_KEY ? { Authorization: `Bearer ${API_KEY}` } : {};
}

export async function fetchStats() {
  const res = await fetch(`${BASE}/api/stats`, {
    cache: "no-store",
    headers: authHeaders(),
  });
  return res.json();
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
  const res = await fetch(`${BASE}/api/events?${q}`, {
    cache: "no-store",
    headers: authHeaders(),
  });
  return res.json();
}

export async function fetchTimeline(hours = 24) {
  const res = await fetch(`${BASE}/api/timeline?hours=${hours}`, {
    cache: "no-store",
    headers: authHeaders(),
  });
  return res.json();
}

export async function fetchAttackTypes() {
  const res = await fetch(`${BASE}/api/attack-types`, {
    cache: "no-store",
    headers: authHeaders(),
  });
  return res.json();
}

export function createEventSocket(onEvent: (event: unknown) => void): WebSocket {
  const wsUrl = BASE.replace(/^http/, "ws");
  const url = API_KEY
    ? `${wsUrl}/ws/events?token=${API_KEY}`
    : `${wsUrl}/ws/events`;
  const ws = new WebSocket(url);
  ws.onmessage = (e) => {
    try {
      onEvent(JSON.parse(e.data));
    } catch {
      // ignore malformed frames
    }
  };
  return ws;
}
