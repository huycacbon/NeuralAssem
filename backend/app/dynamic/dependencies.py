"""FastAPI dependency wiring for the dynamic analysis module - web transport.

The desktop build wires its own `SessionStore` inside
`app.desktop_bridge.DesktopApi.__init__`, constructed with its own
repository instance rather than this module's singleton - see that file for
why (the desktop build's analyses live in a repository private to that
window, not the web deployment's shared one).
"""

from __future__ import annotations

from functools import lru_cache

from app.dependencies import get_repository
from app.dynamic.config import dynamic_settings
from app.dynamic.session_store import SessionStore


@lru_cache(maxsize=1)
def get_session_store() -> SessionStore:
    return SessionStore(
        repository=get_repository(),
        capacity=dynamic_settings.max_concurrent_sessions,
        idle_timeout_seconds=dynamic_settings.session_idle_timeout_seconds,
        reaper_interval_seconds=dynamic_settings.reaper_interval_seconds,
    )
