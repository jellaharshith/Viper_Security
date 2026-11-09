"""Application settings, loaded from environment variables / a git-ignored .env file.

Rule: secrets are ``SecretStr`` and are never hardcoded, logged, or committed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed configuration. Env vars use the ``VIPER_`` prefix (e.g. VIPER_LOG_LEVEL)."""

    model_config = SettingsConfigDict(
        env_prefix="VIPER_", env_file=".env", env_file_encoding="utf-8", extra="ignore",
        populate_by_name=True,
    )

    app_env: str = "dev"
    log_level: str = "INFO"

    # --- Local plane: inference + embedded vector store ---
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = ""  # set once a model is chosen/pulled (M1)
    qdrant_path: Path = Path("data/qdrant")  # embedded mode, no server/Docker
    store: Literal["qdrant", "pgvector", "supabase"] = "qdrant"
    # Supabase over its HTTPS API: read under the exact names used in .env (no VIPER_ prefix).
    supabase_url: str = Field(default="", validation_alias="SUPABASE_URL")
    supabase_secret_key: SecretStr = Field(default=SecretStr(""), validation_alias="SUPABASE_SECRET_KEY")
    database_url: SecretStr = SecretStr("")
    embed_model: str = "nomic-embed-text"
    embed_query_prefix: str = "search_query: "  # nomic-embed-text task prefix
    embed_doc_prefix: str = "search_document: "
    kb_version: str = "v2p"  # index version = collection suffix (v2p: nomic task prefixes)
    kb_registry_path: Path = Path("data/kb_registry.json")
    kb_min_recall_at_4: float = 0.95  # promotion gate: absolute floor on the frozen retrieval set
    kb_max_shrink: float = 0.10  # reject an update that drops more than this fraction of records
    retrieval_top_k: int = 4
    min_score: float = 0.70  # below this, no sources are attached (recalibrated in M3e, ADR 0007)

    # --- Execution plane: cloud Kali VM (empty until provisioned) ---
    exec_api_url: str = ""
    exec_api_token: SecretStr = SecretStr("")
    exec_api_ca_cert: Path | None = None  # PEM the orchestrator trusts for the VM's TLS cert
    exec_egress_allowlist: str = ""  # comma-separated hosts the exec client may target

    # --- Safety: active testing is OFF unless explicitly enabled ---
    allow_active_testing: bool = False
    audit_dir: Path = Path("data/audit")
    checkpoint_db: Path = Path("data/checkpoints.db")  # SQLite checkpoints for paused agent runs
    report_dir: Path = Path("data/reports")  # M7: one Markdown report per finished thread
    # v1.1: real audit anchoring via an RFC-3161 timestamp authority (network use is opt-in per command)
    anchor_tsa_url: str = "http://timestamp.digicert.com"
    anchor_tsa_ca: Path | None = None  # None = verify against the certifi trust store

    def egress_hosts(self) -> list[str]:
        """Allowlisted target hosts, lowercased. Empty means no target is permitted."""
        return [h.strip().lower() for h in self.exec_egress_allowlist.split(",") if h.strip()]

    def redacted(self) -> dict[str, Any]:
        """Settings as a dict that is safe to print/log (secrets masked)."""
        out: dict[str, Any] = {}
        for name, value in self.model_dump(mode="json").items():
            out[name] = "***" if isinstance(getattr(self, name), SecretStr) else value
        return out


def get_settings() -> Settings:
    return Settings()
