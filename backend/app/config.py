"""Runtime configuration. All values are overridable via ``BGA_*`` env vars."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BGA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    #: Bind address. Loopback by default - the tool is not meant to be exposed.
    host: str = "127.0.0.1"
    port: int = 8000

    #: In production mode the structured error envelope omits ``details`` so no
    #: stack trace or internal path reaches the browser.
    environment: str = "development"

    max_upload_mb: int = 100
    #: Wall-clock cap for one angr run. Exceeding it returns ANALYSIS_TIMEOUT.
    analysis_timeout_seconds: int = 300

    #: CORS: local Vite dev servers only.
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:4173",
            "http://127.0.0.1:4173",
        ]
    )

    max_stored_analyses: int = 16
    default_graph_depth: int = 2
    default_max_nodes: int = 500

    upload_dir: Path = Field(
        default_factory=lambda: Path(tempfile.gettempdir()) / "binary-graph-analyzer"
    )

    #: Explicit path to the built frontend (`frontend/dist`). Set by the
    #: desktop launcher so the packaged app finds its bundled UI regardless of
    #: where it was unpacked; left unset in normal dev, where `main.py` finds
    #: the repo-relative `frontend/dist` on its own if it has been built.
    frontend_dist_dir: Path | None = None

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        # Allow BGA_CORS_ORIGINS="http://a,http://b" from the environment.
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


settings = Settings()
