import os
import redis

# Read Redis URL from environment variable
redis_url = os.getenv("REDIS_URL", "redis://:yourpassword@redissvc.filter.svc.cluster.local:6379/0")

# Create Redis client directly from URL
r = redis.from_url(redis_url, decode_responses=True)

# Test connection
try:
    if r.ping():
        print("✅ Connected to Redis!")
    else:
        print("❌ Failed to connect to Redis")
except Exception as e:
    print("❌ Error connecting to Redis:", e)

# Example: Set and get a key
r.set("test_key", "Hello Redis")
value = r.get("test_key")
print("test_key =", value)
