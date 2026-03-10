"""
Redis connection and storage configuration.

Reads REDIS_URL env var. If Redis is unavailable or unset,
falls back gracefully so the app still starts (in-memory mode).
"""

from __future__ import annotations

import logging
import os
from typing import Optional

import redis

logger = logging.getLogger(__name__)

REDIS_URL: str = os.environ.get("REDIS_URL", "")

_redis_client: Optional[redis.Redis] = None
_redis_available: bool = False


def get_redis() -> Optional[redis.Redis]:
    """Return a Redis client, or None if Redis is unavailable."""
    global _redis_client, _redis_available

    if _redis_client is not None:
        return _redis_client if _redis_available else None

    if not REDIS_URL:
        logger.warning("REDIS_URL not set — using in-memory fallback for rate limiting and token store")
        _redis_available = False
        return None

    try:
        client = redis.from_url(REDIS_URL, socket_connect_timeout=2, decode_responses=True)
        client.ping()
        _redis_client = client
        _redis_available = True
        logger.info("Redis connected: %s", REDIS_URL)
    except Exception as exc:
        logger.warning("Redis unavailable (%s) — falling back to in-memory mode", exc)
        _redis_client = None
        _redis_available = False

    return _redis_client if _redis_available else None


def is_redis_available() -> bool:
    """Return True if Redis is reachable."""
    return get_redis() is not None
