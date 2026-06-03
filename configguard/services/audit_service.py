"""Audit service: load → parse → evaluate → score → return.

Pure function used by both `configguard audit` and `configguard fleet audit`.
Does not write files or print to stdout — callers handle I/O and presentation.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from configguard.engine import RuleEngine
from configguard.evidence import EvidenceBuilder
from configguard.models import Finding
from configguard.parser import CiscoIOSParser
from configguard.risk.engine import RiskEngine, RiskEngineResult
from configguard.signals import SignalExtractor
from configguard.context import ContextBuilder
from configguard.registry import create_signal_registry_with_defaults

# Ensure the signal registry is populated so ContextBuilder uses the
# proper category-based keys (e.g., "snmp" instead of "snmp_community").
# The CLI does this at import time as a side effect; we replicate it here
# so the service works in isolation.
create_signal_registry_with_defaults()


@dataclass
class AuditResult:
    """Result of auditing a single config file.

    `error` is non-null iff `status == "ERROR"`. When ERROR, `findings` is
    empty and `risk_result` is None. The caller is responsible for mapping
    this to a Snapshot `DeviceSnapshot` (or any other representation).
    """
    config_name: str
    config_path: str
    config_hash: str
    findings: list[Finding] = field(default_factory=list)
    risk_result: Optional[RiskEngineResult] = None
    error: Optional[str] = None

    @property
    def is_error(self) -> bool:
        return self.error is not None


def run_audit(
    config_path: Path,
    config_name: str,
    rules_dir: Path,
    use_context: bool = True,
) -> AuditResult:
    """Audit a single config file. Returns an AuditResult (no I/O)."""
    # 1. Read file (compute hash from raw bytes)
    try:
        config_bytes = config_path.read_bytes()
    except OSError as exc:
        return AuditResult(
            config_name=config_name,
            config_path=str(config_path),
            config_hash="",
            error=f"Failed to read {config_path}: {exc}",
        )

    config_hash = hashlib.sha256(config_bytes).hexdigest()
    config_text = config_bytes.decode("utf-8", errors="replace")

    # 2. Parse
    try:
        ir = CiscoIOSParser(config_text).parse()
    except Exception as exc:
        return AuditResult(
            config_name=config_name,
            config_path=str(config_path),
            config_hash=config_hash,
            error=f"Failed to parse {config_path}: {exc}",
        )

    # The parser is tolerant of garbage input. A config that yields no
    # raw_lines is treated as a parse error (only comments / whitespace).
    if not ir.raw_lines and not ir.blocks:
        return AuditResult(
            config_name=config_name,
            config_path=str(config_path),
            config_hash=config_hash,
            error=f"Failed to parse {config_path}: no parseable content",
        )

    # 3. Evaluate
    engine = RuleEngine(str(rules_dir))
    try:
        if use_context:
            extractor = SignalExtractor()
            signals = extractor.extract(ir)
            builder = ContextBuilder()
            contexts = builder.build_contexts(signals)
            if not engine._category_index:
                findings = engine.evaluate(ir)
            else:
                findings = engine.evaluate_with_contexts(contexts, engine.rules)
            # Attach evidence summaries
            evidence_builder = EvidenceBuilder()
            context_by_key = {ctx.context_key: ctx for ctx in contexts}
            for f in findings:
                if f.block_name and f.block_name in context_by_key:
                    context = context_by_key[f.block_name]
                    evidence_builder.attach_evidence_summary(f, context)
        else:
            findings = engine.evaluate(ir)
    except Exception as exc:
        return AuditResult(
            config_name=config_name,
            config_path=str(config_path),
            config_hash=config_hash,
            error=f"Failed to evaluate {config_path}: {exc}",
        )

    # 4. Score
    risk_result = RiskEngine().evaluate(findings)

    return AuditResult(
        config_name=config_name,
        config_path=str(config_path),
        config_hash=config_hash,
        findings=findings,
        risk_result=risk_result,
    )
