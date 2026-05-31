"""IR Validation Framework — shared pytest fixtures."""
import json
from pathlib import Path
from typing import NamedTuple

import pytest

from configguard.models import CanonicalResource


class IRTestCase(NamedTuple):
    """A test case with config input and expected golden IR."""
    case_id: str
    description: str
    config: str
    golden_ir_path: Path


# Resolve fixtures directory relative to this file
FIXTURES_DIR = Path(__file__).parent / "fixtures"
GOLDEN_IR_DIR = FIXTURES_DIR / "golden_ir"


@pytest.fixture
def sample_ir() -> list[CanonicalResource]:
    """A minimal sample IR for unit testing."""
    return [
        CanonicalResource(
            id="auth.remote_access:vty0-4:endpoint:a1b2c3",
            resource_type="auth.remote_access",
            name="vty0-4",
            attributes={
                "methods": ["telnet", "ssh"],
                "insecure_methods": ["telnet"],
                "secure_methods": ["ssh"],
            },
            scope="endpoint",
            source={"vendor": "cisco_ios", "line": "transport input telnet ssh"},
            relationships=[],
            tags=["mgmt-plane"],
        ),
        CanonicalResource(
            id="network.snmp:default:resource:b2c3d4",
            resource_type="network.snmp",
            name="default",
            attributes={
                "enabled": True,
                "version": "v2c",
                "communities": ["public", "private"],
                "access_level": ["RO", "RW"],
            },
            scope="resource",
            source={"vendor": "cisco_ios", "line": "snmp-server community public RO"},
            relationships=[],
            tags=["mgmt-plane"],
        ),
    ]


@pytest.fixture
def case_001_config() -> str:
    """Case 001: Telnet enabled (security risk)."""
    return """
!
line vty 0 4
 transport input telnet ssh
!
"""


@pytest.fixture
def case_002_config() -> str:
    """Case 002: SNMP v2c with public community."""
    return """
snmp-server community public RO
snmp-server community private RW
!
"""


@pytest.fixture
def case_003_config() -> str:
    """Case 003: AAA new-model disabled."""
    return """
no aaa new-model
!
"""


@pytest.fixture
def case_004_config() -> str:
    """Case 004: HTTP server enabled (insecure)."""
    return """
ip http server
!
"""


@pytest.fixture
def case_005_config() -> str:
    """Case 005: Multiple findings combined."""
    return """
aaa new-model
!
line vty 0 4
 transport input telnet ssh
!
snmp-server community public RO
!
ip http server
!
logging host 10.1.1.1
!
ntp server 10.1.1.2
!
interface GigabitEthernet0/1
 shutdown
!
"""


def load_golden_ir(case_id: str) -> list[dict]:
    """Load golden IR JSON for a given case_id."""
    golden_path = GOLDEN_IR_DIR / f"{case_id}_golden_ir.json"
    if not golden_path.exists():
        return []
    return json.loads(golden_path.read_text())


def normalize_ir(ir: list[CanonicalResource]) -> list[dict]:
    """Normalize IR for deterministic comparison."""
    return sorted([
        {
            "id": r.id,
            "type": r.resource_type,
            "name": r.name,
            "attrs": sorted(r.attributes.items()),
            "scope": r.scope,
        }
        for r in ir
    ], key=lambda x: x["id"])
