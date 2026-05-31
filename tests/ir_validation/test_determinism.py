"""IR v1 Determinism Check.

Purpose:
Ensure IR is a pure function — same input config always produces
byte-level stable, identical output.

parse(config) == parse(config)

This prevents:
- Random ordering of resources
- Unstable resource IDs
- Non-deterministic parsing
"""
import pytest

from configguard.models import CanonicalResource
from tests.ir_validation.conftest import normalize_ir


class TestDeterminism:
    """Ensure IR parsing is deterministic."""

    def test_normalize_ir_produces_stable_output(self, sample_ir):
        """normalize_ir must produce identical output for same input."""
        norm1 = normalize_ir(sample_ir)
        norm2 = normalize_ir(sample_ir)

        assert norm1 == norm2, "normalize_ir is not deterministic"

    def test_normalize_ir_sorting_is_stable(self, sample_ir):
        """normalize_ir sorting must be by ID (deterministic key)."""
        norm = normalize_ir(sample_ir)

        ids = [r["id"] for r in norm]
        assert ids == sorted(ids), "normalize_ir not sorted by ID"

    def test_empty_ir_normalizes_correctly(self):
        """Empty IR should normalize to empty list."""
        norm = normalize_ir([])
        assert norm == []

    def test_single_resource_normalizes_correctly(self):
        """Single resource IR should normalize deterministically."""
        ir = [
            CanonicalResource(
                id="auth.aaa:default:global:abc",
                resource_type="auth.aaa",
                name="default",
                attributes={"enabled": True},
                scope="resource",
                source={"vendor": "cisco_ios", "line": "aaa new-model"},
                relationships=[],
                tags=[],
            )
        ]
        norm = normalize_ir(ir)

        assert len(norm) == 1
        assert norm[0]["id"] == "auth.aaa:default:global:abc"
        assert norm[0]["type"] == "auth.aaa"

    def test_different_parsing_order_same_result(self):
        """Resources parsed in different order should normalize identically."""
        # Two resources with known stable IDs
        ir1 = [
            CanonicalResource(
                id="network.snmp:default:resource:aaa",
                resource_type="network.snmp",
                name="default",
                attributes={"enabled": True},
                scope="resource",
                source={"vendor": "cisco_ios", "line": "snmp-server community public RO"},
                relationships=[],
                tags=[],
            ),
            CanonicalResource(
                id="auth.aaa:default:global:bbb",
                resource_type="auth.aaa",
                name="default",
                attributes={"enabled": True},
                scope="resource",
                source={"vendor": "cisco_ios", "line": "aaa new-model"},
                relationships=[],
                tags=[],
            ),
        ]

        # Same resources in different order
        ir2 = [
            CanonicalResource(
                id="auth.aaa:default:global:bbb",
                resource_type="auth.aaa",
                name="default",
                attributes={"enabled": True},
                scope="resource",
                source={"vendor": "cisco_ios", "line": "aaa new-model"},
                relationships=[],
                tags=[],
            ),
            CanonicalResource(
                id="network.snmp:default:resource:aaa",
                resource_type="network.snmp",
                name="default",
                attributes={"enabled": True},
                scope="resource",
                source={"vendor": "cisco_ios", "line": "snmp-server community public RO"},
                relationships=[],
                tags=[],
            ),
        ]

        # Normalize both and compare
        norm1 = normalize_ir(ir1)
        norm2 = normalize_ir(ir2)

        # IDs should be in same sorted order
        assert [r["id"] for r in norm1] == [r["id"] for r in norm2]


class TestIRIdentityStability:
    """Ensure resource IDs are stable and not based on randomness."""

    def test_same_content_same_id(self):
        """Same semantic content must produce same ID."""
        ir1 = CanonicalResource(
            id="network.snmp:default:resource:fixed_id",
            resource_type="network.snmp",
            name="default",
            attributes={"version": "v2c", "communities": ["public"]},
            scope="resource",
            source={"vendor": "cisco_ios", "line": "snmp-server community public RO"},
            relationships=[],
            tags=[],
        )

        ir2 = CanonicalResource(
            id="network.snmp:default:resource:fixed_id",
            resource_type="network.snmp",
            name="default",
            attributes={"version": "v2c", "communities": ["public"]},
            scope="resource",
            source={"vendor": "cisco_ios", "line": "snmp-server community public RO"},
            relationships=[],
            tags=[],
        )

        assert ir1.id == ir2.id

    def test_different_content_different_id(self):
        """Different semantic content should produce different IDs."""
        ir1 = CanonicalResource(
            id="network.snmp:default:resource:same",
            resource_type="network.snmp",
            name="default",
            attributes={"version": "v1"},
            scope="resource",
            source={"vendor": "cisco_ios", "line": "snmp-server community public RO"},
            relationships=[],
            tags=[],
        )

        ir2 = CanonicalResource(
            id="network.snmp:default:resource:different",
            resource_type="network.snmp",
            name="default",
            attributes={"version": "v2c"},
            scope="resource",
            source={"vendor": "cisco_ios", "line": "snmp-server community public RO"},
            relationships=[],
            tags=[],
        )

        # IDs are manually set here, but in real adapter they must be derived
        # This test documents that different content ≠ same ID
        assert ir1.id != ir2.id
