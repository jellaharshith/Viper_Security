"""Finding schema v1 (frozen contract shared with viper.report).

``confidence="confirmed"`` is reserved for deterministic parser evidence (an open port in
nmap output, a template match in nuclei output). LLM text must never produce it.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["confirmed", "hypothesis"]
SourceTool = Literal["nmap", "nuclei"]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    affected_asset: str  # in-scope target
    source_tool: SourceTool
    source_action_id: str
    evidence: str  # raw tool-output excerpt, never LLM prose
    severity: Severity
    severity_rationale: str
    confidence: Confidence
    reproducibility: str
    remediation: str
    references: list[str]
    audit_refs: list[str]  # audit event hashes
