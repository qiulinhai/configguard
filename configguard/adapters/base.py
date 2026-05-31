"""ConfigGuard Vendor Adapter Interface — v0.3 IR Contract.

This module defines the VendorAdapter contract that ALL vendor adapters
must satisfy. Adapters are pure translation layers: CLI → Canonical IR.

Responsibilities:
    ✓ CLI syntax → semantic mapping
    ✓ Grouping raw lines → resources
    ✓ Extracting attributes

Forbidden:
    ✗ No rule evaluation
    ✗ No signal generation
    ✗ No deduplication logic
    ✗ No context logic
"""
from abc import ABC, abstractmethod
from configguard.models import CanonicalResource


class VendorAdapter(ABC):
    """Converts vendor-specific configuration into Canonical IR v1."""

    @abstractmethod
    def parse(self, raw_config: str, metadata: dict | None = None) -> list[CanonicalResource]:
        """Convert vendor config into canonical IR.

        Args:
            raw_config: Raw configuration text from device
            metadata: Optional metadata (vendor, file, etc.)

        Returns:
            List of CanonicalResource objects

        Invariants:
            1. Same input config → same IR output (deterministic)
            2. No vendor keywords in output (vendor-neutral)
            3. All security-relevant facts preserved (lossless)
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def vendor_id(self) -> str:
        """Unique vendor identifier (e.g., 'cisco_ios', 'juniper_junos')."""
        raise NotImplementedError

    @property
    def mapping_spec(self) -> dict:
        """Declarative mapping spec — defines CLI → IR translation rules.

        Subclasses override this to define their vendor's mapping.
        Format:
            resource_type -> {
                "match": [line patterns],
                "attributes": {
                    attr_name -> { "extract": extraction_method }
                }
            }
        """
        return {}
