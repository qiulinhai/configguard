"""Pydantic models for ConfigGuard."""
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


class RuleMatch(BaseModel):
    type: str = Field(description="match type: regex, exact, contains")
    pattern: str
    scope: Optional[str] = Field(default=None, description="block type scope")


class Finding(BaseModel):
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    status: FindingStatus
    evidence: str
    block_type: Optional[str] = None
    block_name: Optional[str] = None
    remediation: Optional[str] = None
    evidence_summary: Optional[dict] = None  # Human-readable evidence from EvidenceBuilder


class Block(BaseModel):
    type: str
    name: str
    commands: list[str] = Field(default_factory=list)


class ConfigIR(BaseModel):
    raw_lines: list[str] = Field(default_factory=list)
    blocks: list[Block] = Field(default_factory=list)
    normalized: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)


class AuditReport(BaseModel):
    version: str = "0.1.0"
    summary: dict
    findings: list[Finding]
    metadata: dict


from dataclasses import dataclass

@dataclass
class Signal:
    type: str           # e.g., "transport_input"
    value: str          # e.g., "telnet"
    context: str        # e.g., "vty 0 4"
    block_type: str     # e.g., "line"
    raw: str            # original config line
    severity_hint: str | None = None  # optional: "high", "medium", "low"

    def __hash__(self):
        return hash((self.type, self.context))


@dataclass
class CanonicalResource:
    """Vendor-neutral semantic model of a security-relevant configuration resource.

    This is the core IR v1 datatype - represents WHAT the config IS (semantics),
    not HOW it is configured (syntax).
    """
    id: str                           # Globally unique: {domain}:{type}:{name}:{scope_hash}
    resource_type: str                 # Semantic type: "auth.remote_access", "network.snmp"
    name: str                          # Logical name: "ssh", "vty0-4", "GigabitEthernet0/1"
    attributes: dict                  # Vendor-neutral semantic facts
    scope: str                         # "global", "endpoint", "resource"
    source: dict                       # Provenance: {vendor, parser, line, ...}
    relationships: list[str] = None    # Links to other CanonicalResource IDs
    tags: list[str] = None             # Classification hints: ["security-critical", "mgmt-plane"]

    def __post_init__(self):
        if self.relationships is None:
            self.relationships = []
        if self.tags is None:
            self.tags = []