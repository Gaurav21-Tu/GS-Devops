# app_fixed_window_redis.py
import os
import time
import hashlib
import logging
from typing import Dict, Tuple, List
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
import httpx
import asyncio
import redis.asyncio as redis

# ----------- Config -------------
DEFAULT_BACKEND_URL = os.getenv("BACKEND_URL", "http://backend.filter.svc.cluster.local:90")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "10"))        # fixed window length
THRESHOLD = int(os.getenv("THRESHOLD", "10"))                  # how many in one window to block
BLOCK_DURATION = int(os.getenv("BLOCK_DURATION", "300"))       # seconds to block
TRUST_XFF = os.getenv("TRUST_XFF", "true").lower() in ("1", "true", "yes")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Redis key for dynamic backend URL
BACKEND_URL_KEY = "config:backend_url"

# ----------- Logging ------------
import sqlite3
from datetime import datetime

class SQLiteHandler(logging.Handler):
    def __init__(self, db_path):
        super().__init__()
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                level TEXT,
                message TEXT,
                module TEXT,
                funcName TEXT,
                lineno INTEGER
            )
        """)
        conn.commit()
        conn.close()

    def emit(self, record):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO logs (timestamp, level, message, module, funcName, lineno)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                datetime.fromtimestamp(record.created).isoformat(),
                record.levelname,
                self.format(record),
                record.module,
                record.funcName,
                record.lineno
            ))
            conn.commit()
            conn.close()
        except Exception:
            self.handleError(record)

SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "/app/logs/request_filter.db")

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger("request-filter")
console_handler = logging.StreamHandler()
console_handler.setLevel(LOG_LEVEL)

# Add SQLite handler
sqlite_handler = SQLiteHandler(SQLITE_DB_PATH)
sqlite_handler.setLevel(LOG_LEVEL)

logger.addHandler(console_handler)
logger.addHandler(sqlite_handler)

# Test log
logger.info("This is a test log before writing to SQLite.")
logger.warning("Testing warning log.")
logger.error("Something went wrong!")

# ----------- FastAPI & clients ----
app = FastAPI(title="Request Filter Proxy (Fixed Window + Redis)")
client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)

# ----------- Redis client -------
redis_client = redis.from_url(
    REDIS_URL, 
    decode_responses=True,
    retry_on_timeout=True,
    socket_keepalive=True,
    socket_connect_timeout=5,
    socket_timeout=5,
    health_check_interval=30
)

# Key patterns used:
# - Counter key per window: "cnt:{fingerprint}:{window_start}"
# - Block key: "blk:{fingerprint}"  (value: "1", TTL = BLOCK_DURATION)
# - Block metadata (hash): "blkmeta:{fingerprint}" (HSET fields)
# We purposely keep the design simple for fixed-window behavior (atomic INCR).

# ----------- Helpers ------------
async def get_backend_url() -> str:
    """Get current backend URL from Redis, fallback to default."""
    try:
        url = await redis_client.get(BACKEND_URL_KEY)
        if url:
            return url
    except Exception as e:
        logger.error(f"Failed to get backend URL from Redis: {e}")
    return DEFAULT_BACKEND_URL

async def set_backend_url(url: str) -> bool:
    """Set backend URL in Redis."""
    try:
        await redis_client.set(BACKEND_URL_KEY, url)
        logger.info(f"Backend URL updated to: {url}")
        return True
    except Exception as e:
        logger.error(f"Failed to set backend URL in Redis: {e}")
        return False

def get_client_ip(request: Request) -> str:
    """Extract client IP; respect X-Forwarded-For if configured (only enable behind trusted proxy)."""
    if TRUST_XFF:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"

def fingerprint_request(method: str, path: str, headers: Dict[str, str], body_bytes: bytes, source_ip: str) -> str:
    """
    Create deterministic fingerprint for request.
    We include method, path, source_ip, selected headers and a short body signature.
    """
    interesting = []
    for k in ("user-agent", "content-type", "accept", "authorization", "cookie"):
        v = headers.get(k, "")
        if v:
            interesting.append(f"{k}:{v[:200]}")
    if not body_bytes:
        body_sig = ""
    elif len(body_bytes) <= 512:
        body_sig = body_bytes.decode(errors="replace")
    else:
        body_sig = hashlib.sha256(body_bytes).hexdigest()
    base = "|".join([method.upper(), path, source_ip, ",".join(interesting), body_sig])
    return hashlib.sha256(base.encode()).hexdigest()

def current_window_start(now: float) -> int:
    """Return the integer timestamp representing the start of the fixed window containing 'now'."""
    return int(now) - (int(now) % WINDOW_SECONDS)

async def is_blocked_redis(fingerprint: str) -> Tuple[bool, int]:
    """
    Check if fingerprint is currently blocked.
    Returns (blocked_bool, seconds_remaining).
    """
    blk_key = f"blk:{fingerprint}"
    ttl = await redis_client.ttl(blk_key)
    if ttl is None or ttl < 0:
        return False, 0
    return ttl > 0, max(0, int(ttl))

async def mark_and_check_fixed_window(fingerprint: str, meta: Dict) -> Tuple[bool, int]:
    """
    Fixed-window implementation using atomic INCR + EXPIRE.
    Steps:
      1) Determine the counter key for this fingerprint and window.
      2) INCR it atomically. If value >= THRESHOLD -> create block key with TTL and store metadata.
    """
    now = time.time()
    window_start = current_window_start(now)
    cnt_key = f"cnt:{fingerprint}:{window_start}"
    # Increase counter atomically
    try:
        count = await redis_client.incr(cnt_key)
    except Exception as e:
        logger.exception("Redis INCR failed: %s", e)
        # As fallback, allow request (deny only on clear evidence)
        return False, 0

    # Ensure TTL exists on the counter key (so it expires after some time)
    await redis_client.expire(cnt_key, WINDOW_SECONDS * 2)

    if count >= THRESHOLD:
        # create block key (value can be simple "1")
        blk_key = f"blk:{fingerprint}"
        blk_meta_key = f"blkmeta:{fingerprint}"

        # store minimal metadata about the block in a HASH for admin UI / future Azure export
        meta_payload = {
            "fingerprint": fingerprint,
            "source_ip": meta.get("source_ip", ""),
            "method": meta.get("method", ""),
            "path": meta.get("path", ""),
            "user_agent": meta.get("user_agent", "")[:1024],
            "content_type": meta.get("content_type", ""),
            "body_hash": meta.get("body_hash", ""),
            "first_seen": str(int(meta.get("first_seen", now))),
            "blocked_at": str(int(now)),
            "count_in_window": str(count)
        }

        # Use pipeline to set both keys atomically-ish (MULTI/EXEC)
        pipeline = redis_client.pipeline()
        pipeline.set(blk_key, "1", ex=BLOCK_DURATION)
        pipeline.hset(blk_meta_key, mapping=meta_payload)
        pipeline.expire(blk_meta_key, BLOCK_DURATION)
        try:
            await pipeline.execute()
        except Exception:
            # Even if metadata storing fails, ensure block key exists
            try:
                await redis_client.set(blk_key, "1", ex=BLOCK_DURATION)
            except Exception:
                logger.exception("Failed to set block key in Redis.")

        # Optionally remove the counter key to free space
        try:
            await redis_client.delete(cnt_key)
        except Exception:
            pass

        logger.warning("Fingerprint blocked (fixed window): %s %s %s", fingerprint, meta.get("method"), meta.get("path"))

        # ---------- FUTURE AZURE EXPORT POINT ----------
        # Here you can push `meta_payload` (and additional context) to your Azure ingest:
        # - send to Azure Blob / File Share as newline-delimited JSON
        # - send to Azure Event Hubs / Service Bus for async processing
        # - store to Cosmos DB / Table Storage
        #
        # Example (future): azure_upload(json.dumps(meta_payload))
        # Include fields: fingerprint, source_ip, method, path, user_agent, content_type, body_hash,
        # first_seen, blocked_at, block_expires_at (now+BLOCK_DURATION), count_in_window
        #
        # This is the place you will later integrate the API that pushes attack logs & fingerprint metadata
        # to Azure for your UI to consume.
        # -----------------------------------------------

        return True, BLOCK_DURATION

    return False, 0

async def forward_request_to_backend(request: Request, body: bytes) -> httpx.Response:
    """
    Forward request to backend preserving headers and body.
    Remove hop-by-hop headers and set host to backend host.
    """
    backend_url = await get_backend_url()
    path = request.url.path
    query = request.url.query
    url = backend_url.rstrip("/") + path
    if query:
        url += "?" + query

    headers = dict(request.headers)
    for h in ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"]:
        headers.pop(h, None)

    # set host header for backend
    try:
        headers["host"] = httpx.URL(backend_url).host or headers.get("host", "")
    except Exception:
        headers["host"] = headers.get("host", "")

    return await client.request(
        method=request.method,
        url=url,
        content=body,
        headers=headers,
        timeout=30.0
    )

# ----------- Middleware -----------
@app.middleware("http")
async def inspect_and_proxy(request: Request, call_next):
    # allow admin endpoints to pass through
    if request.url.path.startswith("/__admin/"):
        return await call_next(request)

    try:
        body = await request.body()
    except Exception:
        body = b""

    source_ip = get_client_ip(request)
    headers_lower = {k.lower(): v for k, v in request.headers.items()}
    body_hash = hashlib.sha256(body).hexdigest() if body else ""

    fingerprint = fingerprint_request(
        method=request.method,
        path=request.url.path,
        headers=headers_lower,
        body_bytes=body,
        source_ip=source_ip
    )

    meta = {
        "source_ip": source_ip,
        "method": request.method,
        "path": request.url.path,
        "user_agent": headers_lower.get("user-agent", "")[:1024],
        "content_type": headers_lower.get("content-type", ""),
        "body_hash": body_hash,
        "first_seen": time.time()
    }

    # Fast path: check if blocked
    try:
        blocked, remaining = await is_blocked_redis(fingerprint)
    except Exception:
        logger.exception("Redis TTL check failed")
        blocked, remaining = False, 0

    if blocked:
        # Text-only JSON blocked response (no image)
        headers = {
            "X-Blocked": "true",
            "X-Block-Reason": "pattern_matched",
            "X-Block-Seconds-Remaining": str(remaining)
        }
        content = {
            "GshieldSecurity": "Unauthorised Request",
            "blocked": True,
            "reason": "pattern_matched",
            "block_seconds_remaining": remaining,
            "fingerprint": fingerprint
        }
        return JSONResponse(status_code=403, content=content, headers=headers)

    # Not currently blocked -> do the fixed-window increment & decide
    try:
        is_blocked, remaining = await mark_and_check_fixed_window(fingerprint, meta)
    except Exception as e:
        logger.exception("mark_and_check failed: %s", e)
        is_blocked, remaining = False, 0

    if is_blocked:
        headers = {
            "X-Blocked": "true",
            "X-Block-Reason": "threshold_exceeded",
            "X-Block-Seconds-Remaining": str(remaining)
        }
        content = {
            "GshieldSecurity": "Unauthorised Request",
            "blocked": True,
            "reason": "threshold_exceeded",
            "block_seconds_remaining": remaining,
            "fingerprint": fingerprint
        }
        return JSONResponse(status_code=403, content=content, headers=headers)

    # Allowed: forward to backend
    try:
        upstream_resp = await forward_request_to_backend(request, body)
    except httpx.RequestError as e:
        logger.exception("Error forwarding to backend: %s", e)
        raise HTTPException(status_code=502, detail="Backend unreachable")

    # return response preserving upstream headers (but avoid hop-by-hop)
    response_headers = {k: v for k, v in upstream_resp.headers.items() if k.lower() not in (
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade")}
    return Response(content=upstream_resp.content, status_code=upstream_resp.status_code, headers=response_headers)

# ----------- Admin endpoints ------------
@app.get("/__admin/blocked")
async def list_blocked():
    """
    Return active blocked fingerprints and metadata from Redis.
    WARNING: Uses SCAN -- ok for moderate keyspaces; for very large Redis, adapt storage strategy.
    """
    cursor = "0"
    results = []
    # Use async SCAN
    async for key in redis_client.scan_iter(match="blkmeta:*"):
        # key example: blkmeta:{fingerprint}
        fingerprint = key.split("blkmeta:", 1)[-1]
        meta = await redis_client.hgetall(key)
        ttl = await redis_client.ttl(f"blk:{fingerprint}")
        meta["block_seconds_remaining"] = int(ttl) if ttl and ttl > 0 else 0
        results.append(meta)
    return results

@app.get("/__admin/stats")
async def stats():
    """
    Show current counters for the active window.
    Scans cnt:* keys for the current window to gather counts.
    """
    now = time.time()
    window_start = current_window_start(now)
    pattern = f"cnt:*:{window_start}"
    stats_list = []
    async for key in redis_client.scan_iter(match=pattern):
        # key format: cnt:{fingerprint}:{window_start}
        try:
            parts = key.split(":")
            fingerprint = parts[1]
            count = int(await redis_client.get(key) or 0)
            stats_list.append((fingerprint, count))
        except Exception:
            continue
    top = sorted(stats_list, key=lambda x: x[1], reverse=True)[:50]
    return {
        "now": int(now),
        "window_seconds": WINDOW_SECONDS,
        "threshold": THRESHOLD,
        "block_duration": BLOCK_DURATION,
        "top_patterns": top
    }

@app.get("/__admin/config/backend")
async def get_config_backend():
    """Get current backend URL configuration."""
    backend_url = await get_backend_url()
    return {
        "backend_url": backend_url,
        "default_backend_url": DEFAULT_BACKEND_URL,
        "is_custom": backend_url != DEFAULT_BACKEND_URL
    }

@app.post("/__admin/config/backend")
async def update_config_backend(request: Request):
    """Update backend URL configuration."""
    try:
        data = await request.json()
        new_url = data.get("backend_url", "").strip()
        
        if not new_url:
            raise HTTPException(status_code=400, detail="backend_url is required")
        
        # Basic URL validation
        if not (new_url.startswith("http://") or new_url.startswith("https://")):
            raise HTTPException(status_code=400, detail="backend_url must start with http:// or https://")
        
        success = await set_backend_url(new_url)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update backend URL")
        
        return {
            "success": True,
            "backend_url": new_url,
            "message": "Backend URL updated successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to update backend URL")
        raise HTTPException(status_code=500, detail=f"Error updating backend URL: {str(e)}")

@app.get("/__admin/logs")
async def get_logs(limit: int = 100):
    """Get recent logs from SQLite database."""
    try:
        conn = sqlite3.connect(SQLITE_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, level, message, module, funcName, lineno
            FROM logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        logs = []
        for row in rows:
            logs.append({
                "id": row[0],
                "timestamp": row[1],
                "level": row[2],
                "message": row[3],
                "module": row[4],
                "funcName": row[5],
                "lineno": row[6]
            })
        
        return {"logs": logs, "count": len(logs)}
    except Exception as e:
        logger.exception("Failed to retrieve logs")
        raise HTTPException(status_code=500, detail=f"Error retrieving logs: {str(e)}")

# ----------- Run instructions (uvicorn) ------------
# Start with: uvicorn app_fixed_window_redis:app --host 0.0.0.0 --port 8080






































# import os
# import time
# import hashlib
# import logging
# from typing import Dict, Tuple
# from fastapi import FastAPI, Request, Response, HTTPException
# from fastapi.responses import FileResponse
# import httpx
# import asyncio

# # ----------- Configuration -------------
# BACKEND_URL = os.getenv("BACKEND_URL", "http://backend.default.svc.cluster.local:80")
# LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
# WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "10"))           # How long is the detection window
# THRESHOLD = int(os.getenv("THRESHOLD", "10"))                     # How many times a pattern can occur before block
# BLOCK_DURATION = int(os.getenv("BLOCK_DURATION", "300"))         # How long to block matching pattern (in seconds)
# TRUST_XFF = os.getenv("TRUST_XFF", "true").lower() in ("1", "true", "yes")
# LOG_LEVEL = os.getenv("LOG_LEVEL", "info").upper()

# # ----------- Logging -------------------
# logging.basicConfig(level=LOG_LEVEL)
# logger = logging.getLogger("request-filter")

# # ----------- FastAPI -------------------
# app = FastAPI(title="Request Filter Proxy")

# # ----------- State ---------------------
# counts: Dict[str, list] = {}  # Fingerprint → list of timestamps (for detection window)
# blocked_patterns: Dict[str, Dict] = {}  # Fingerprint → metadata for blocked patterns
# _counts_lock = asyncio.Lock()  # For thread-safe access to counts
# client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)

# # ----------- Helper Functions ----------

# def get_client_ip(request: Request) -> str:
#     """Extract client IP, respecting X-Forwarded-For if configured."""
#     if TRUST_XFF:
#         xff = request.headers.get("x-forwarded-for")
#         if xff:
#             return xff.split(",")[0].strip()
#     if request.client:
#         return request.client.host
#     return "unknown"

# def fingerprint_request(method: str, path: str, headers: Dict[str, str], body_bytes: bytes, source_ip: str) -> str:
#     """
#     Create a hash (fingerprint) of key request properties to detect patterns.
#     Includes method, path, selected headers, body signature, and source IP.
#     """
#     interesting = []
#     for k in ["user-agent", "content-type", "accept", "authorization", "cookie"]:
#         v = headers.get(k, "")
#         if v:
#             interesting.append(f"{k}:{v[:200]}")
#     if not body_bytes:
#         body_sig = ""
#     elif len(body_bytes) <= 512:
#         body_sig = body_bytes.decode(errors="replace")
#     else:
#         body_sig = hashlib.sha256(body_bytes).hexdigest()
#     base = "|".join([method.upper(), path, source_ip, ",".join(interesting), body_sig])
#     return hashlib.sha256(base.encode()).hexdigest()

# async def mark_and_check(fingerprint: str, meta: Dict) -> Tuple[bool, int]:
#     """
#     Track a fingerprint occurrence, and decide if it should be blocked.
#     If blocked, return True and remaining block duration.
#     """
#     now = time.time()

#     # Remove expired blocked patterns
#     expired = [fp for fp, data in blocked_patterns.items() if data["block_expires_at"] <= now]
#     for fp in expired:
#         blocked_patterns.pop(fp)

#     # Already blocked?
#     if fingerprint in blocked_patterns:
#         remaining = int(blocked_patterns[fingerprint]["block_expires_at"] - now)
#         return True, remaining

#     async with _counts_lock:
#         lst = counts.setdefault(fingerprint, [])
#         lst.append(now)

#         # Remove old timestamps (outside the sliding window)
#         cutoff = now - WINDOW_SECONDS
#         while lst and lst[0] < cutoff:
#             lst.pop(0)

#         count = len(lst)
#         if count >= THRESHOLD:
#             # Block pattern and store metadata
#             block_expires_at = now + BLOCK_DURATION
#             blocked_patterns[fingerprint] = {
#                 "fingerprint": fingerprint,
#                 "source_ip": meta.get("source_ip", ""),
#                 "method": meta.get("method", ""),
#                 "path": meta.get("path", ""),
#                 "user_agent": meta.get("user_agent", ""),
#                 "content_type": meta.get("content_type", ""),
#                 "body_hash": meta.get("body_hash", ""),
#                 "first_seen": meta.get("first_seen", now),
#                 "blocked_at": now,
#                 "block_expires_at": block_expires_at,
#                 "count_in_window": count
#             }
#             logger.warning("Pattern blocked: %s (%s %s from %s)", fingerprint, meta["method"], meta["path"], meta["source_ip"])
#             counts.pop(fingerprint, None)
#             return True, BLOCK_DURATION

#         return False, 0

# async def forward_request_to_backend(request: Request, body: bytes) -> httpx.Response:
#     """
#     Forwards the request to the actual backend while preserving most headers and content.
#     """
#     path = request.url.path
#     query = request.url.query
#     url = BACKEND_URL.rstrip("/") + path
#     if query:
#         url += "?" + query

#     headers = dict(request.headers)
#     # Remove hop-by-hop headers
#     for h in ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"]:
#         headers.pop(h, None)

#     headers["host"] = httpx.URL(BACKEND_URL).host or headers.get("host", "")

#     return await client.request(
#         method=request.method,
#         url=url,
#         content=body,
#         headers=headers,
#         timeout=30.0
#     )

# # ----------- Middleware ----------------

# @app.middleware("http")
# async def inspect_and_proxy(request: Request, call_next):
#     """Intercept every HTTP request to inspect, block, or forward."""
#     # Skip middleware for admin endpoints - let FastAPI handle them directly
#     if request.url.path.startswith("/__admin/"):
#         return await call_next(request)
    
#     try:
#         body = await request.body()
#     except Exception:
#         body = b""

#     source_ip = get_client_ip(request)
#     headers_lower = {k.lower(): v for k, v in request.headers.items()}
#     body_hash = hashlib.sha256(body).hexdigest() if body else ""

#     fingerprint = fingerprint_request(
#         method=request.method,
#         path=request.url.path,
#         headers=headers_lower,
#         body_bytes=body,
#         source_ip=source_ip
#     )

#     meta = {
#         "source_ip": source_ip,
#         "method": request.method,
#         "path": request.url.path,
#         "user_agent": headers_lower.get("user-agent", ""),
#         "content_type": headers_lower.get("content-type", ""),
#         "body_hash": body_hash,
#         "first_seen": time.time()
#     }

#     is_blocked, remaining = await mark_and_check(fingerprint, meta)

#     if is_blocked:
#         # Serve the blocked image instead of JSON response
#         image_path = "/app/image/Image (1).jpg"
#         if os.path.exists(image_path):
#             return FileResponse(
#                 path=image_path,
#                 media_type="image/jpeg",
#                 headers={
#                     "X-Blocked": "true",
#                     "X-Block-Reason": "pattern_matched",
#                     "X-Block-Seconds-Remaining": str(remaining)
#                 }
#             )
#         else:
#             # Fallback to JSON if image not found
#             return Response(
#                 content=f'{{"GshieldSecurity":"Unauthorised Request","blocked":true,"reason":"pattern_matched","block_seconds_remaining":{remaining}}}',
#                 status_code=403,
#                 media_type="application/json"
#             )

#     try:
#         upstream_resp = await forward_request_to_backend(request, body)
#     except httpx.RequestError as e:
#         logger.exception("Error forwarding to backend: %s", e)
#         raise HTTPException(status_code=502, detail="Backend unreachable")

#     return Response(
#         content=upstream_resp.content,
#         status_code=upstream_resp.status_code,
#         headers={k: v for k, v in upstream_resp.headers.items()}
#     )

# # ----------- Admin API -----------------

# @app.get("/__admin/blocked")
# async def list_blocked():
#     """List currently blocked request patterns with metadata."""
#     now = time.time()
#     results = []
#     for data in blocked_patterns.values():
#         results.append({
#             "fingerprint": data["fingerprint"],
#             "source_ip": data["source_ip"],
#             "method": data["method"],
#             "path": data["path"],
#             "user_agent": data["user_agent"],
#             "content_type": data["content_type"],
#             "body_hash": data["body_hash"],
#             "first_seen": int(data["first_seen"]),
#             "blocked_at": int(data["blocked_at"]),
#             "block_expires_at": int(data["block_expires_at"]),
#             "block_seconds_remaining": int(data["block_expires_at"] - now),
#             "count_in_window": data["count_in_window"]
#         })
#     return results

# @app.get("/__admin/stats")
# async def stats():
#     """Show top fingerprints by count in the sliding window."""
#     now = time.time()
#     summary = {
#         k: len([ts for ts in v if ts >= now - WINDOW_SECONDS])
#         for k, v in counts.items()
#     }
#     top = sorted(summary.items(), key=lambda x: x[1], reverse=True)[:20]
#     return {
#         "now": int(now),
#         "window_seconds": WINDOW_SECONDS,
#         "threshold": THRESHOLD,
#         "block_duration": BLOCK_DURATION,
#         "top_patterns": top
#     }
