# app_fixed_window_redis_cosmosdb.py
import os
import time
import hashlib
import logging
import uuid
from typing import Dict, Tuple, List
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import asyncio
import redis.asyncio as redis
from datetime import datetime
from azure.cosmos.aio import CosmosClient
from azure.cosmos import exceptions, PartitionKey

# ----------- Config -------------
DEFAULT_BACKEND_URL = os.getenv("BACKEND_URL", "http://backend.filter.svc.cluster.local:90")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "10"))
THRESHOLD = int(os.getenv("THRESHOLD", "10"))
BLOCK_DURATION = int(os.getenv("BLOCK_DURATION", "300"))
TRUST_XFF = os.getenv("TRUST_XFF", "true").lower() in ("1", "true", "yes")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Azure Cosmos DB Configuration
COSMOS_URI = os.getenv("COSMOS_URI", "https://gaurav.documents.azure.com:443/")
COSMOS_KEY = os.getenv("COSMOS_KEY", "AFMd1khv72EchA1bQPyFtDjmswyyM6CM7cuOI86JkIkKyAWB12ewQ5dVIkYefy2T5nZoMOelkfdkACDbuqXK9g==")
COSMOS_DATABASE = os.getenv("COSMOS_DATABASE", "logs-db")
COSMOS_CONTAINER_LOGS = os.getenv("COSMOS_CONTAINER_LOGS", "application-logs")
COSMOS_CONTAINER_BLOCKS = os.getenv("COSMOS_CONTAINER_BLOCKS", "blocked-patterns")

# Redis key for dynamic backend URL
BACKEND_URL_KEY = "config:backend_url"

# ----------- Logging with Cosmos DB ------------
class CosmosDBHandler(logging.Handler):
    """Custom logging handler that writes logs to Azure Cosmos DB"""
    def __init__(self, cosmos_client, database_name: str, container_name: str):
        super().__init__()
        self.cosmos_client = cosmos_client
        self.database_name = database_name
        self.container_name = container_name
        self.container = None
        self._init_task = None

    async def init_container(self):
        """Initialize the Cosmos DB container asynchronously"""
        try:
            database = self.cosmos_client.get_database_client(self.database_name)
            
            # Create container if it doesn't exist
            try:
                self.container = database.get_container_client(self.container_name)
                await self.container.read()
            except exceptions.CosmosResourceNotFoundError:
                # Container doesn't exist, create it
                self.container = await database.create_container(
                    id=self.container_name,
                    partition_key=PartitionKey(path="/level")
                )
        except Exception as e:
            print(f"Failed to initialize Cosmos DB container: {e}")

    def emit(self, record):
        """Emit a log record to Cosmos DB"""
        if self.container is None:
            return
        
        try:
            log_document = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                "level": record.levelname,
                "message": self.format(record),
                "module": record.module,
                "funcName": record.funcName,
                "lineno": record.lineno,
                "created": record.created
            }
            
            # Schedule async operation
            asyncio.create_task(self._write_log(log_document))
        except Exception:
            self.handleError(record)

    async def _write_log(self, log_document):
        """Write log document to Cosmos DB"""
        try:
            await self.container.create_item(body=log_document)
        except Exception as e:
            print(f"Failed to write log to Cosmos DB: {e}")

# Initialize Cosmos DB client
cosmos_client = CosmosClient(COSMOS_URI, credential=COSMOS_KEY)

# ----------- Logging Setup ------------
logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger("request-filter")
console_handler = logging.StreamHandler()
console_handler.setLevel(LOG_LEVEL)

# Add Cosmos DB handler
cosmos_handler = CosmosDBHandler(cosmos_client, COSMOS_DATABASE, COSMOS_CONTAINER_LOGS)
cosmos_handler.setLevel(LOG_LEVEL)

logger.addHandler(console_handler)
logger.addHandler(cosmos_handler)

# ----------- FastAPI & clients ----
app = FastAPI(title="Request Filter Proxy (Fixed Window + Redis + Cosmos DB)")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

# Cosmos DB containers
logs_container = None
blocks_container = None

@app.on_event("startup")
async def startup_event():
    """Initialize Cosmos DB containers on startup"""
    global logs_container, blocks_container
    
    try:
        # Initialize logging container
        await cosmos_handler.init_container()
        
        # Initialize database client
        database = cosmos_client.get_database_client(COSMOS_DATABASE)
        
        # Initialize logs container
        try:
            logs_container = database.get_container_client(COSMOS_CONTAINER_LOGS)
            await logs_container.read()
        except exceptions.CosmosResourceNotFoundError:
            logs_container = await database.create_container(
                id=COSMOS_CONTAINER_LOGS,
                partition_key=PartitionKey(path="/level")
            )
        
        # Initialize blocks container
        try:
            blocks_container = database.get_container_client(COSMOS_CONTAINER_BLOCKS)
            await blocks_container.read()
        except exceptions.CosmosResourceNotFoundError:
            blocks_container = await database.create_container(
                id=COSMOS_CONTAINER_BLOCKS,
                partition_key=PartitionKey(path="/fingerprint")
            )
        
        logger.info("Cosmos DB containers initialized successfully")
        logger.info("Application startup complete with Azure Cosmos DB integration")
        
    except Exception as e:
        logger.error(f"Failed to initialize Cosmos DB: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    await cosmos_client.close()
    await client.aclose()

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
    """Extract client IP; respect X-Forwarded-For if configured."""
    if TRUST_XFF:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"

def fingerprint_request(method: str, path: str, headers: Dict[str, str], body_bytes: bytes, source_ip: str) -> str:
    """Create deterministic fingerprint for request."""
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
    """Return the integer timestamp representing the start of the fixed window."""
    return int(now) - (int(now) % WINDOW_SECONDS)

async def is_blocked_redis(fingerprint: str) -> Tuple[bool, int]:
    """Check if fingerprint is currently blocked."""
    blk_key = f"blk:{fingerprint}"
    ttl = await redis_client.ttl(blk_key)
    if ttl is None or ttl < 0:
        return False, 0
    return ttl > 0, max(0, int(ttl))

async def store_block_to_cosmos(meta_payload: Dict):
    """Store blocked pattern metadata to Cosmos DB for persistence"""
    if blocks_container is None:
        return
    
    try:
        document = {
            "id": str(uuid.uuid4()),
            "fingerprint": meta_payload["fingerprint"],
            "source_ip": meta_payload["source_ip"],
            "method": meta_payload["method"],
            "path": meta_payload["path"],
            "user_agent": meta_payload["user_agent"],
            "content_type": meta_payload["content_type"],
            "body_hash": meta_payload["body_hash"],
            "first_seen": meta_payload["first_seen"],
            "blocked_at": meta_payload["blocked_at"],
            "count_in_window": meta_payload["count_in_window"],
            "block_duration": BLOCK_DURATION,
            "timestamp": datetime.utcnow().isoformat()
        }
        await blocks_container.create_item(body=document)
        logger.info(f"Stored block metadata to Cosmos DB for fingerprint: {meta_payload['fingerprint']}")
    except Exception as e:
        logger.error(f"Failed to store block to Cosmos DB: {e}")

async def mark_and_check_fixed_window(fingerprint: str, meta: Dict) -> Tuple[bool, int]:
    """Fixed-window implementation using atomic INCR + EXPIRE."""
    now = time.time()
    window_start = current_window_start(now)
    cnt_key = f"cnt:{fingerprint}:{window_start}"
    
    try:
        count = await redis_client.incr(cnt_key)
    except Exception as e:
        logger.exception("Redis INCR failed: %s", e)
        return False, 0

    await redis_client.expire(cnt_key, WINDOW_SECONDS * 2)

    if count >= THRESHOLD:
        blk_key = f"blk:{fingerprint}"
        blk_meta_key = f"blkmeta:{fingerprint}"

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

        # Store in Redis
        pipeline = redis_client.pipeline()
        pipeline.set(blk_key, "1", ex=BLOCK_DURATION)
        pipeline.hset(blk_meta_key, mapping=meta_payload)
        pipeline.expire(blk_meta_key, BLOCK_DURATION)
        try:
            await pipeline.execute()
        except Exception:
            try:
                await redis_client.set(blk_key, "1", ex=BLOCK_DURATION)
            except Exception:
                logger.exception("Failed to set block key in Redis.")

        try:
            await redis_client.delete(cnt_key)
        except Exception:
            pass

        logger.warning("Fingerprint blocked (fixed window): %s %s %s", fingerprint, meta.get("method"), meta.get("path"))

        # Store in Cosmos DB for persistence and analytics
        asyncio.create_task(store_block_to_cosmos(meta_payload))

        return True, BLOCK_DURATION

    return False, 0

async def forward_request_to_backend(request: Request, body: bytes) -> httpx.Response:
    """Forward request to backend preserving headers and body."""
    backend_url = await get_backend_url()
    path = request.url.path
    query = request.url.query
    url = backend_url.rstrip("/") + path
    if query:
        url += "?" + query

    headers = dict(request.headers)
    for h in ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"]:
        headers.pop(h, None)

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

    try:
        blocked, remaining = await is_blocked_redis(fingerprint)
    except Exception:
        logger.exception("Redis TTL check failed")
        blocked, remaining = False, 0

    if blocked:
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

    try:
        upstream_resp = await forward_request_to_backend(request, body)
    except httpx.RequestError as e:
        logger.exception("Error forwarding to backend: %s", e)
        raise HTTPException(status_code=502, detail="Backend unreachable")

    response_headers = {k: v for k, v in upstream_resp.headers.items() if k.lower() not in (
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade")}
    return Response(content=upstream_resp.content, status_code=upstream_resp.status_code, headers=response_headers)

# ----------- Admin endpoints ------------
@app.get("/__admin/blocked")
async def list_blocked():
    """Return active blocked fingerprints and metadata from Redis."""
    results = []
    async for key in redis_client.scan_iter(match="blkmeta:*"):
        fingerprint = key.split("blkmeta:", 1)[-1]
        meta = await redis_client.hgetall(key)
        ttl = await redis_client.ttl(f"blk:{fingerprint}")
        meta["block_seconds_remaining"] = int(ttl) if ttl and ttl > 0 else 0
        results.append(meta)
    return results

@app.get("/__admin/stats")
async def stats():
    """Show current counters for the active window."""
    now = time.time()
    window_start = current_window_start(now)
    pattern = f"cnt:*:{window_start}"
    stats_list = []
    async for key in redis_client.scan_iter(match=pattern):
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
    """Get recent logs from Cosmos DB."""
    if logs_container is None:
        raise HTTPException(status_code=503, detail="Cosmos DB not initialized")
    
    try:
        query = f"SELECT * FROM c ORDER BY c.created DESC OFFSET 0 LIMIT {limit}"
        items = []
        async for item in logs_container.query_items(query=query, enable_cross_partition_query=True):
            items.append({
                "id": item.get("id"),
                "timestamp": item.get("timestamp"),
                "level": item.get("level"),
                "message": item.get("message"),
                "module": item.get("module"),
                "funcName": item.get("funcName"),
                "lineno": item.get("lineno")
            })
        
        return {"logs": items, "count": len(items)}
    except Exception as e:
        logger.exception("Failed to retrieve logs from Cosmos DB")
        raise HTTPException(status_code=500, detail=f"Error retrieving logs: {str(e)}")

@app.get("/__admin/blocked/history")
async def get_blocked_history(limit: int = 100):
    """Get historical blocked patterns from Cosmos DB."""
    if blocks_container is None:
        raise HTTPException(status_code=503, detail="Cosmos DB not initialized")
    
    try:
        query = f"SELECT * FROM c ORDER BY c.blocked_at DESC OFFSET 0 LIMIT {limit}"
        items = []
        async for item in blocks_container.query_items(query=query, enable_cross_partition_query=True):
            items.append(item)
        
        return {"blocks": items, "count": len(items)}
    except Exception as e:
        logger.exception("Failed to retrieve block history from Cosmos DB")
        raise HTTPException(status_code=500, detail=f"Error retrieving block history: {str(e)}")

# ----------- Health check ------------
@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "cosmos_db": "connected" if logs_container and blocks_container else "disconnected",
        "redis": "connected"
    }
