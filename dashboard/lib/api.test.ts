import { afterEach, describe, expect, it, vi } from "vitest";

import { createEventSocket, fetchAllEvents, fetchEvents, fetchStats } from "./api";

const BASE = "http://localhost:8000";

function mockFetch(response: Partial<Response>) {
  const fn = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}), ...response });
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("apiFetch", () => {
  it("throws on a non-2xx response instead of returning junk", async () => {
    mockFetch({ ok: false, status: 503, statusText: "Service Unavailable" });
    await expect(fetchStats()).rejects.toThrow("API error 503");
  });

  it("does not cache — the dashboard polls for new events", async () => {
    const fetchMock = mockFetch({ json: async () => ({}) });
    await fetchStats();
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ cache: "no-store" });
  });
});

describe("fetchEvents query building", () => {
  it("omits absent filters", async () => {
    const fetchMock = mockFetch({ json: async () => [] });
    await fetchEvents();
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/api/events?`);
  });

  it("passes through the filters it was given", async () => {
    const fetchMock = mockFetch({ json: async () => [] });
    await fetchEvents({ limit: 50, offset: 100, blocked_only: true, attack_type: "obfuscation" });
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      limit: "50",
      offset: "100",
      blocked_only: "true",
      attack_type: "obfuscation",
    });
  });

  it("clamps limit to the server's page cap — 1000 was a 422", async () => {
    const fetchMock = mockFetch({ json: async () => ({ events: [], limit: 200, offset: 0 }) });
    await fetchEvents({ limit: 1000 });
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.get("limit")).toBe("200");
  });

  it("drops offset=0 — a falsy number is not a filter worth sending", async () => {
    const fetchMock = mockFetch({ json: async () => [] });
    await fetchEvents({ offset: 0 });
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/api/events?`);
  });
});

class FakeSocket {
  static instances: FakeSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;

  constructor(public url: string) {
    FakeSocket.instances.push(this);
  }

  send() {}

  close() {
    this.closed = true;
    this.onclose?.();
  }
}

describe("createEventSocket", () => {
  function withFakeSocket() {
    FakeSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeSocket);
    return FakeSocket;
  }

  it("connects over ws, not http", () => {
    withFakeSocket();
    const socket = createEventSocket(() => {});
    expect(FakeSocket.instances[0].url).toBe("ws://localhost:8000/ws/events");
    socket.close();
  });

  it("hands parsed frames to the callback and swallows malformed ones", () => {
    withFakeSocket();
    const seen: unknown[] = [];
    const socket = createEventSocket((e) => seen.push(e));
    const ws = FakeSocket.instances[0];

    ws.onmessage!({ data: JSON.stringify({ id: "abc" }) });
    expect(() => ws.onmessage!({ data: "not json" })).not.toThrow();

    expect(seen).toEqual([{ id: "abc" }]);
    socket.close();
  });

  it("reconnects when the server drops the connection", () => {
    vi.useFakeTimers();
    withFakeSocket();
    const socket = createEventSocket(() => {});

    FakeSocket.instances[0].onclose!();
    vi.advanceTimersByTime(3000);

    expect(FakeSocket.instances).toHaveLength(2);
    socket.close();
  });

  it("stays closed after close() — no reconnect storm on unmount", () => {
    vi.useFakeTimers();
    withFakeSocket();
    const socket = createEventSocket(() => {});

    socket.close();
    vi.advanceTimersByTime(30_000);

    expect(FakeSocket.instances).toHaveLength(1);
  });
});

describe("fetchAllEvents", () => {
  function page(count: number, offset: number) {
    return {
      events: Array.from({ length: count }, (_, i) => ({ id: `e${offset + i}` })),
      limit: 200,
      offset,
    };
  }

  it("pages until a short page comes back", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => page(200, 0) })
      .mockResolvedValueOnce({ ok: true, json: async () => page(37, 200) });
    vi.stubGlobal("fetch", fetchMock);

    const events = await fetchAllEvents();

    expect(events).toHaveLength(237);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(new URL(fetchMock.mock.calls[1][0]).searchParams.get("offset")).toBe("200");
  });

  it("stops at max instead of draining the whole table", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => page(200, 0) });
    vi.stubGlobal("fetch", fetchMock);

    const events = await fetchAllEvents(400);

    expect(events).toHaveLength(400);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
