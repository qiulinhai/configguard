"""IR v1 Schema Invariant Check.

Purpose:
Ensure Canonical IR is structurally valid, vendor-neutral,
deterministic-safe, and semantically complete.

Canonical assertions for every IR resource.
"""
import pytest

from configguard.models import CanonicalResource


class TestIRSchemaInvariants:
    """Schema-level invariants that ALL CanonicalResource must satisfy."""

    def test_id_must_be_non_empty(self, sample_ir):
        """Every resource must have a non-empty, stable ID."""
        for r in sample_ir:
            assert isinstance(r.id, str)
            assert len(r.id) > 0, f"Resource {r.name} has empty id"

    def test_resource_type_must_be_valid(self, sample_ir):
        """resource_type must be a non-empty string with no vendor keywords."""
        for r in sample_ir:
            assert isinstance(r.resource_type, str)
            assert len(r.resource_type) > 0, f"Resource {r.name} has empty resource_type"

            # Critical: no vendor leakage in resource_type
            vendor_keywords = ["cisco", "ios", "juniper", "junos", "nxos", "linux"]
            for keyword in vendor_keywords:
                assert keyword not in r.resource_type.lower(), \
                    f"Vendor leakage: '{keyword}' in resource_type '{r.resource_type}'"

    def test_attributes_must_be_dict(self, sample_ir):
        """attributes must be a dict with string keys."""
        for r in sample_ir:
            assert isinstance(r.attributes, dict), f"{r.id} attributes is not a dict"
            for k, v in r.attributes.items():
                assert isinstance(k, str), f"{r.id} attribute key is not str: {k}"

    def test_scope_must_be_valid(self, sample_ir):
        """scope must be one of the allowed values."""
        allowed_scopes = {"global", "endpoint", "resource"}
        for r in sample_ir:
            assert r.scope in allowed_scopes, \
                f"Invalid scope '{r.scope}' for resource {r.id}"

    def test_source_must_be_traceable(self, sample_ir):
        """source must contain vendor and line provenance."""
        for r in sample_ir:
            assert isinstance(r.source, dict), f"{r.id} source is not a dict"
            assert "vendor" in r.source, f"{r.id} source missing 'vendor'"
            assert "line" in r.source, f"{r.id} source missing 'line'"

    def test_relationships_and_tags_are_lists(self, sample_ir):
        """relationships and tags must be lists (may be empty)."""
        for r in sample_ir:
            assert isinstance(r.relationships, list), f"{r.id} relationships is not a list"
            assert isinstance(r.tags, list), f"{r.id} tags is not a list"

    def test_id_uniqueness(self, sample_ir):
        """All resource IDs must be unique within the IR."""
        ids = [r.id for r in sample_ir]
        assert len(ids) == len(set(ids)), f"Duplicate IDs found: {[i for i in ids if ids.count(i) > 1]}"

    def test_no_vendor_keywords_in_attributes(self, sample_ir):
        """attributes must not contain vendor-specific keywords."""
        vendor_keywords = ["cisco", "ios", "juniper", "junos", "nxos"]

        for r in sample_ir:
            for key, value in r.attributes.items():
                key_str = str(key).lower()
                value_str = str(value).lower()

                for keyword in vendor_keywords:
                    assert keyword not in key_str, \
                        f"Vendor keyword '{keyword}' in attribute key '{key}'"
                    assert keyword not in value_str, \
                        f"Vendor keyword '{keyword}' in attribute value '{value}'"
