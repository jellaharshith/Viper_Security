"""Application settings, loaded from environment variables / a git-ignored .env file.

Rule: secrets are ``SecretStr`` and are never hardcoded, logged, or committed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed configuration. Env vars use the ``VIPER_`` prefix (e.g. VIPER_LOG_LEVEL)."""

    model_config = SettingsConfigDict(
        env_prefix="VIPER_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_env: str = "dev"
    log_level: str = "INFO"

    # --- Local plane: inference + embedded vector store ---
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = ""  # set once a model is chosen/pulled (M1)
    qdrant_path: Path = Path("data/qdrant")  # embedded mode, no server/Docker

    # --- Execution plane: cloud Kali VM (empty until provisioned) ---
    exec_api_url: str = ""
    exec_api_token: SecretStr = SecretStr("")

    # --- Safety: active testing is OFF unless explicitly enabled ---
    allow_active_testing: bool = False

    def redacted(self) -> dict[str, Any]:
        """Settings as a dict that is safe to print/log (secrets masked)."""
        out: dict[str, Any] = {}
        for name, value in self.model_dump(mode="json").items():
            out[name] = "***" if isinstance(getattr(self, name), SecretStr) else value
        return out


def get_settings() -> Settings:
    return Settings()
