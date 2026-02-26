# PIF Dashboard

Next.js 15 dashboard for the Prompt Injection Firewall. Reads from the PIF backend via REST and WebSocket.

## Setup

```bash
npm install
```

Create `.env.local`:
```
NEXT_PUBLIC_API_URL=http://localhost:8000
```

```bash
npm run dev   # http://localhost:3001
```

## What's in it

- 4 stat cards (total requests, blocked, block rate, avg detection latency)
- 24h line chart — total vs blocked requests per hour
- Attack type donut chart
- Live event feed over WebSocket (`/ws/events`)

All backend calls go through `lib/api.ts`.
