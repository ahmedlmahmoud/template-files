# Floppy egress door (dumb tunnel)

A stateless WebSocket→TCP relay. It holds **no seat credentials**.

## How it works
Warbo opens a WebSocket to `/ws?h=<host>&p=<port>` and streams raw bytes to
the target. Each request's `Proxy-Authorization` (the seat) travels **inside**
the tunnel as bytes — the door never reads, stores, or needs any seat. Seats
stay fully dynamic and per-request on the Warbo side.

## Env
- `PORT` — injected by the platform. The server binds `0.0.0.0:$PORT`.
- Nothing else. No `SEAT_USER` / `SEAT_PASS` needed.

## Endpoints
- `GET /ws?h=<host>&p=<port>` — RFC6455 binary tunnel (the door path). Defaults to Floppy `170.23.130.191:10080`.
- `GET /health` — `ok <egress-ip>` (shows this host's egress IP).
- `GET /hs?c=<host>&p=<port>` — one-shot dial, returns the first status line (no auth).

## Deploy
Any platform that builds a Dockerfile, or detects Python. Just point it at this
folder/repo. No env to set.
