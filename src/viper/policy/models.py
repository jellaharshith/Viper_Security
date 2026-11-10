"""Policy data model: scope, actions, decisions. No I/O; everything here is pure data."""

from __future__ import annotations

import hashlib
import json
import re
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskLevel(IntEnum):
    READ = 0  # knowledge-base lookup, local scope queries
    PASSIVE = 1  # dry-run planning against in-scope targets
    ACTIVE = 2  # anything that would send traffic to a target
    INTRUSIVE = 3  # exploitation, credential attacks: always denied in M5


class DecisionType(StrEnum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


KNOWN_TECHNIQUES = frozenset({
    "port-scan", "service-detection", "web-scan", "template-scan", "passive-scan", "spider",
    "brute-force", "dos", "exploit",
})
_SLUG = re.compile(r"[a-z0-9-]{1,64}")
MAX_PERMITTED_TECHNIQUES = 20


def normalize_technique(text: str) -> str:
    """Lowercase slug of free text (runs of anything but a-z0-9 become one dash)."""
    return re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-")


class ToolInfo(BaseModel):
    """Registry-owned facts about a tool. Only ``viper.tools.registry`` may create these."""

    model_config = ConfigDict(frozen=True)

    name: str
    risk: RiskLevel
    dry_run_only: bool = True  # M5 stubs never touch a target
    techniques: frozenset[str] = frozenset()  # registry-owned technique tags (F3)
    default_rate_rps: int | None = None  # request rate when the action omits ``rate_limit``


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
    # Free text for humans; the engine enforces only entries that normalise to a KNOWN technique
    # slug (see KNOWN_TECHNIQUES), so old entries such as "INTRUSIVE" stay readable but inert.
    forbidden_techniques: tuple[str, ...] = ()
    # v1.1 limits (additive: old scope files keep loading with these defaults)
    # HTTP request-rate cap (nuclei). Tools with no rate argument (nmap) are NOT bounded by it; see ADR 0012.
    max_rate_rps: int | None = Field(default=None, ge=1, le=1000, strict=True)
    automation_allowed: bool = Field(default=True, strict=True)
    permitted_techniques: tuple[str, ...] = ()  # empty = no restriction; else only these slugs

    @field_validator("permitted_techniques")
    @classmethod
    def _slugs_only(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_PERMITTED_TECHNIQUES or any(not _SLUG.fullmatch(t) for t in value):
            raise ValueError("permitted_techniques must be a short list of lowercase [a-z0-9-] slugs")
        return value

    @property
    def revision(self) -> str:
        """SHA-256 of the canonical JSON form; changes whenever scope changes."""
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()
