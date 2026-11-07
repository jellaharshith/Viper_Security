"""Policy data model: scope, actions, decisions. No I/O; everything here is pure data."""

from __future__ import annotations

import hashlib
import json
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(IntEnum):
    READ = 0  # knowledge-base lookup, local scope queries
    PASSIVE = 1  # dry-run planning against in-scope targets
    ACTIVE = 2  # anything that would send traffic to a target
    INTRUSIVE = 3  # exploitation, credential attacks: always denied in M5


class DecisionType(StrEnum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class ToolInfo(BaseModel):
    """Registry-owned facts about a tool. Only ``viper.tools.registry`` may create these."""

    model_config = ConfigDict(frozen=True)

    name: str
    risk: RiskLevel
    dry_run_only: bool = True  # M5 stubs never touch a target


class Action(BaseModel):
    """A model-proposed action. It carries no risk level and no permissions on purpose."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str
    tool_name: str
    args: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_id: str
    type: DecisionType
    reason: str
    risk: RiskLevel | None = None


class Scope(BaseModel):
    """Authoritative engagement scope, loaded from a validated file, never from model text."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    project_id: str
    program_url: str = ""
    evidence_ref: str = ""  # where the permission to test is documented
    in_scope: tuple[str, ...] = ()  # hosts, "*.domain" wildcards, or CIDR ranges
    exclusions: tuple[str, ...] = ()  # always win over in_scope
    forbidden_techniques: tuple[str, ...] = ()

    @property
    def revision(self) -> str:
        """SHA-256 of the canonical JSON form; changes whenever scope changes."""
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()
