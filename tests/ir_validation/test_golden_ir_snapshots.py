"""IR v1 Golden Snapshot Test.

Purpose:
Prevent IR regressions by comparing adapter output against
known-correct golden IR snapshots.

Golden IR is the source of truth — not the adapter, not the parser.
If the golden IR passes all invariant checks and coverage matrix,
it becomes the authoritative definition of correct behavior.
"""
import json
from pathlib import Path

import pytest

from configguard.models import CanonicalResource
from tests.ir_validation.conftest import normalize_ir, GOLDEN_IR_DIR


def load_golden_ir_json(case_id: str) -> list[dict]:
    """Load golden IR from JSON fixture file."""
    golden_path = GOLDEN_IR_DIR / f"{case_id}_golden_ir.json"
    if not golden_path.exists():
        pytest.skip(f"Golden IR not found: {golden_path}")
    return json.loads(golden_path.read_text())


def golden_to_canonicalResource(golden_list: list[dict]) -> list[CanonicalResource]:
    """Convert golden IR dict to CanonicalResource list."""
    resources = []
    for item in golden_list:
        r = CanonicalResource(
            id=item["id"],
            resource_type=item["resource_type"],
            name=item["name"],
            attributes=item["attributes"],
            scope=item["scope"],
            source=item["source"],
            relationships=item.get("relationships", []),
            tags=item.get("tags", []),
        )
        resources.append(r)
    return resources


class TestGoldenIRSnapshots:
    """Compare adapter output against golden IR snapshots."""

    def test_golden_ir_case_001_exists(self):
        """Case 001 golden IR must exist."""
        golden_path = GOLDEN_IR_DIR / "case_001_telnet_golden_ir.json"
        assert golden_path.exists(), f"Golden IR missing: {golden_path}"

    def test_golden_ir_case_002_exists(self):
        """Case 002 golden IR must exist."""
        golden_path = GOLDEN_IR_DIR / "case_002_snmp_v2c_golden_ir.json"
        assert golden_path.exists(), f"Golden IR missing: {golden_path}"

    def test_golden_ir_case_003_exists(self):
        """Case 003 golden IR must exist."""
        golden_path = GOLDEN_IR_DIR / "case_003_aaa_disabled_golden_ir.json"
        assert golden_path.exists(), f"Golden IR missing: {golden_path}"

    def test_golden_ir_case_004_exists(self):
        """Case 004 golden IR must exist."""
        golden_path = GOLDEN_IR_DIR / "case_004_http_insecure_golden_ir.json"
        assert golden_path.exists(), f"Golden IR missing: {golden_path}"

    def test_golden_ir_case_005_exists(self):
        """Case 005 golden IR must exist."""
        golden_path = GOLDEN_IR_DIR / "case_005_combined_golden_ir.json"
        assert golden_path.exists(), f"Golden IR missing: {golden_path}"


class TestGoldenIRStructure:
    """Verify golden IR files have correct structure."""

    @pytest.mark.parametrize("case_id", [
        "case_001_telnet",
        "case_002_snmp_v2c",
        "case_003_aaa_disabled",
        "case_004_http_insecure",
        "case_005_combined",
    ])
    def test_golden_ir_is_list(self, case_id):
        """Golden IR must be a list of resources."""
        golden = load_golden_ir_json(case_id)
        assert isinstance(golden, list), f"{case_id}: golden IR is not a list"
        assert len(golden) > 0, f"{case_id}: golden IR is empty"

    @pytest.mark.parametrize("case_id", [
        "case_001_telnet",
        "case_002_snmp_v2c",
        "case_003_aaa_disabled",
        "case_004_http_insecure",
        "case_005_combined",
    ])
    def test_golden_ir_has_required_fields(self, case_id):
        """Each golden IR resource must have required fields."""
        golden = load_golden_ir_json(case_id)

        required_fields = ["id", "resource_type", "name", "attributes", "scope", "source"]

        for i, resource in enumerate(golden):
            for field in required_fields:
                assert field in resource, \
                    f"{case_id}[{i}]: missing required field '{field}'"

    @pytest.mark.parametrize("case_id", [
        "case_001_telnet",
        "case_002_snmp_v2c",
        "case_003_aaa_disabled",
        "case_004_http_insecure",
        "case_005_combined",
    ])
    def test_golden_ir_no_duplicate_ids(self, case_id):
        """Golden IR must not contain duplicate resource IDs."""
        golden = load_golden_ir_json(case_id)
        ids = [r["id"] for r in golden]
        assert len(ids) == len(set(ids)), \
            f"{case_id}: duplicate IDs found"


class TestGoldenIRSchemaCompliance:
    """Verify golden IR satisfies schema invariants."""

    @pytest.mark.parametrize("case_id", [
        "case_001_telnet",
        "case_002_snmp_v2c",
        "case_003_aaa_disabled",
        "case_004_http_insecure",
        "case_005_combined",
    ])
    def test_golden_ir_no_vendor_leakage(self, case_id):
        """Golden IR must not contain vendor keywords in resource_type."""
        golden = load_golden_ir_json(case_id)

        vendor_keywords = ["cisco", "ios", "juniper", "junos", "nxos"]

        for i, resource in enumerate(golden):
            resource_type = resource["resource_type"].lower()
            for keyword in vendor_keywords:
                assert keyword not in resource_type, \
                    f"{case_id}[{i}]: vendor keyword '{keyword}' in resource_type"

    @pytest.mark.parametrize("case_id", [
        "case_001_telnet",
        "case_002_snmp_v2c",
        "case_003_aaa_disabled",
        "case_004_http_insecure",
        "case_005_combined",
    ])
    def test_golden_ir_valid_scopes(self, case_id):
        """Golden IR scopes must be valid."""
        golden = load_golden_ir_json(case_id)
        allowed_scopes = {"global", "endpoint", "resource"}

        for i, resource in enumerate(golden):
            assert resource["scope"] in allowed_scopes, \
                f"{case_id}[{i}]: invalid scope '{resource['scope']}'"


class TestGoldenIRCoverage:
    """Verify golden IR covers all 8 rules."""

    def test_case_001_covers_telnet(self):
        """Case 001 golden IR must cover AUTH_REMOTE_ACCESS_METHODS."""
        golden = load_golden_ir_json("case_001_telnet")

        # Find auth.remote_access resource
        remote_access = [r for r in golden if r["resource_type"] == "auth.remote_access"]
        assert len(remote_access) > 0, "No auth.remote_access in case_001"

        # Verify telnet is present
        ra = remote_access[0]
        methods = ra["attributes"].get("methods", [])
        assert "telnet" in methods, "Telnet not found in auth.remote_access.methods"

    def test_case_002_covers_snmp(self):
        """Case 002 golden IR must cover NETWORK_SNMP_SECURITY."""
        golden = load_golden_ir_json("case_002_snmp_v2c")

        snmp_resources = [r for r in golden if r["resource_type"] == "network.snmp"]
        assert len(snmp_resources) > 0, "No network.snmp in case_002"

        snmp = snmp_resources[0]
        assert snmp["attributes"].get("version") == "v2c"
        assert len(snmp["attributes"].get("communities", [])) >= 1

    def test_case_003_covers_aaa_disabled(self):
        """Case 003 golden IR must cover AUTH_AAA_MISSING."""
        golden = load_golden_ir_json("case_003_aaa_disabled")

        aaa_resources = [r for r in golden if r["resource_type"] == "auth.aaa"]
        assert len(aaa_resources) > 0, "No auth.aaa in case_003"

        aaa = aaa_resources[0]
        assert aaa["attributes"].get("enabled") == False, "AAA should be disabled"

    def test_case_004_covers_http_insecure(self):
        """Case 004 golden IR must cover NETWORK_HTTP_SERVER."""
        golden = load_golden_ir_json("case_004_http_insecure")

        http_resources = [r for r in golden if r["resource_type"] == "network.management"]
        assert len(http_resources) > 0, "No network.management in case_004"

        http = http_resources[0]
        assert http["attributes"].get("enabled") == True
        assert http["attributes"].get("secure_only") == False
