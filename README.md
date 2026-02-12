# Request Filter Proxy (Fixed Window + Redis + Cosmos DB)

A FastAPI-based reverse proxy that filters and rate-limits requests using a fixed-window counter in Redis, blocks abusive request fingerprints, and persists logs and block history in Azure Cosmos DB.

## What this service does

- Proxies incoming HTTP requests to a configurable backend.
- Computes a deterministic fingerprint per request.
- Enforces a fixed-window threshold per fingerprint.
- Temporarily blocks abusive patterns with Redis TTLs.
- Stores application logs and block history in Cosmos DB.
- Exposes admin endpoints for monitoring and configuration.

## Architecture

- **FastAPI**: HTTP server and middleware pipeline.
- **Redis**: In-memory counters and block TTLs.
- **Azure Cosmos DB**: Durable logs and block history.
- **httpx**: Upstream proxy client.

### Architecture diagram

```mermaid
config:
   theme: forest
   look: neo
---
flowchart LR

      Client[Client]
      Proxy["Request Filter Proxy (FastAPI)"]
      Admin["Admin Endpoints - __admin"]
      Redis[(Redis - Rate Limits TTL Counters)]
      Cosmos[(Azure Cosmos DB - Logs and Block History)]
      Backend["Upstream Backend API"]

      Client -->|HTTP Request| Proxy

      Proxy -->|Admin API| Admin
      Proxy -->|INCR EXPIRE Block Checks| Redis
      Proxy -->|Logs and History| Cosmos
      Proxy -->|Forward Valid Request| Backend

      Backend -->|Response| Proxy
      Proxy -->|HTTP Response| Client
```

## Configuration

All configuration is via environment variables in [main.py](main.py):

| Variable | Default | Description |
|---|---|---|
| `BACKEND_URL` | `http://backend.filter.svc.cluster.local:90` | Default upstream backend URL |
| `LISTEN_PORT` | `8080` | Port to expose the proxy |
| `WINDOW_SECONDS` | `10` | Fixed window duration in seconds |
| `THRESHOLD` | `10` | Max requests per fingerprint per window |
| `BLOCK_DURATION` | `300` | Block duration in seconds |
| `TRUST_XFF` | `true` | Trust `X-Forwarded-For` for client IP |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `LOG_LEVEL` | `INFO` | Log level |
| `COSMOS_URI` | *(required)* | Cosmos DB endpoint |
| `COSMOS_KEY` | *(required)* | Cosmos DB key |
| `COSMOS_DATABASE` | `logs-db` | Cosmos DB database |
| `COSMOS_CONTAINER_LOGS` | `application-logs` | Logs container name |
| `COSMOS_CONTAINER_BLOCKS` | `blocked-patterns` | Blocks container name |

## Request fingerprinting

Each request is fingerprinted using:

- HTTP method
- URL path
- Source IP (optionally from `X-Forwarded-For`)
- Selected headers: `user-agent`, `content-type`, `accept`, `authorization`, `cookie`
- Body signature (small bodies in full, large bodies as SHA-256)

This fingerprint is used to rate-limit and block abusive traffic.

## Workflow

1. **Receive request** at the proxy.
2. **Skip admin routes** under `/__admin/*`.
3. **Read body** and **extract client IP**.
4. **Build fingerprint** from method, path, IP, headers, and body signature.
5. **Check block list** in Redis:
   - If blocked, return `403` with `X-Blocked` headers.
6. **Increment fixed-window counter** in Redis (`INCR` + `EXPIRE`).
7. **Threshold exceeded**:
   - Create a Redis block entry with TTL.
   - Persist block metadata to Cosmos DB (async).
   - Return `403` with block details.
8. **Forward request** to backend via `httpx`.
9. **Return upstream response** to client.

## Redis keys

- `cnt:{fingerprint}:{window_start}`: Fixed-window counter.
- `blk:{fingerprint}`: Block flag with TTL.
- `blkmeta:{fingerprint}`: Block metadata hash with TTL.
- `config:backend_url`: Dynamic backend override.

## Admin endpoints

- `GET /__admin/blocked`: Active blocked fingerprints (Redis).
- `GET /__admin/blocked/history`: Block history (Cosmos DB).
- `GET /__admin/stats`: Current window counters and top offenders.
- `GET /__admin/config/backend`: Current backend URL config.
- `POST /__admin/config/backend`: Update backend URL.
- `GET /__admin/logs`: Recent logs (Cosmos DB).

## Health check

- `GET /health`: Returns proxy status and Cosmos/Redis connectivity.

## Running locally

1. Ensure Redis is running.
2. Set Cosmos DB credentials in environment variables.
3. Start the app (example):
   - `python main.py` (or via your process manager)
4. Send requests to `http://localhost:${LISTEN_PORT}`.

## Notes

- Backend URL can be updated at runtime via `POST /__admin/config/backend` and is stored in Redis.
- Requests to `/__admin/*` are not proxied and bypass rate limiting.
- Cosmos DB writes are asynchronous and do not block request handling.
