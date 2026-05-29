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