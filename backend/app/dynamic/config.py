"""Runtime configuration for the dynamic analysis module.

Kept separate from ``app.config.Settings`` on purpose (own env prefix, own
module): the spec requires this package to stay fully decoupled from the
static analyzer, and settings are part of that surface.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class DynamicSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BGA_DYN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    #: How long to wait for the initial TCP connect + attach to ``dbgsrv``
    #: before giving up and reporting DYNAMIC_CONNECT_FAILED.
    connect_timeout_seconds: float = 10.0

    #: How long a single "continue" call may block waiting for a breakpoint
    #: (or the process exiting) before returning DYNAMIC_TIMEOUT. The caller
    #: can always issue another "continue" afterwards - this is a per-call
    #: cap, not a session cap.
    continue_timeout_seconds: float = 120.0

    #: A session with no user-initiated activity (step/breakpoint/continue/
    #: state read) for this long is disconnected and evicted automatically.
    #: Per the user's own answer to the spec's question #4.
    session_idle_timeout_seconds: int = 1800

    #: Bound on live debug sessions held in memory at once, mirroring
    #: ``Settings.max_stored_analyses``'s role for the static side.
    max_concurrent_sessions: int = 4

    #: How often the background reaper thread checks for idle sessions.
    reaper_interval_seconds: float = 30.0


dynamic_settings = DynamicSettings()
