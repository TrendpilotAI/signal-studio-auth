"""
Structured JSON logging configuration for signal-studio-auth.

Provides a JSON formatter that outputs structured log entries with:
- timestamp, level, logger, message
- Extra fields (user_id, action, ip, etc.) merged into the top-level object

Usage:
    from config.logging_config import setup_structured_logging
    setup_structured_logging()  # Call once at startup

    # In route handlers:
    from config.logging_config import auth_log
    auth_log("login_success", user_id="abc-123", ip="1.2.3.4")
"""

from __future__ import annotations

import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any


class StructuredJSONFormatter(logging.Formatter):
    """Format log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge any extra fields passed via `extra=` kwarg
        for key in ("action", "user_id", "ip", "email", "method", "path",
                     "status_code", "duration_ms", "detail", "token_family"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val
        # Also include exc_info if present
        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def setup_structured_logging(level: int = logging.INFO) -> None:
    """
    Configure the root logger (and our app loggers) to emit structured JSON.

    Safe to call multiple times — clears existing handlers first.
    """
    root = logging.getLogger()
    # Only add our handler once
    if any(getattr(h, "_structured_json", False) for h in root.handlers):
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJSONFormatter())
    handler._structured_json = True  # type: ignore[attr-defined]

    root.addHandler(handler)
    root.setLevel(level)

    # Ensure our app loggers inherit
    for name in ("routes.auth_routes", "middleware.supabase_auth_middleware",
                 "middleware.rbac", "config"):
        logging.getLogger(name).setLevel(level)


# ---------------------------------------------------------------------------
# Convenience helper for auth-specific structured logs
# ---------------------------------------------------------------------------

_auth_logger = logging.getLogger("auth.events")


def auth_log(action: str, *, level: int = logging.INFO, **kwargs: Any) -> None:
    """
    Emit a structured auth event log.

    Example:
        auth_log("login_success", user_id="abc", ip="1.2.3.4", email="x@y.com")
    """
    _auth_logger.log(level, action, extra={"action": action, **kwargs})
