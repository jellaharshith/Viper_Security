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
    embed_model: str = "nomic-embed-text"
    embed_query_prefix: str = "search_query: "  # nomic-embed-text task prefix
    embed_doc_prefix: str = "search_document: "
    kb_version: str = "v2p"  # index version = collection suffix (v2p: nomic task prefixes)
    retrieval_top_k: int = 4
    min_score: float = 0.65  # below this, no sources are attached (calibrated in M2)

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
