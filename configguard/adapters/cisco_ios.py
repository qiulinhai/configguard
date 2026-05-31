"""Cisco IOS → Canonical IR Adapter — v0.3 Naive Implementation.

This adapter interprets a declarative mapping spec to translate Cisco IOS
configuration into vendor-neutral Canonical IR v1.

Architecture:
    Cisco CLI
        ↓
    Tokenizer (syntax only)
        ↓
    Block Grouper (structure only)
        ↓
    Spec Interpreter (semantic mapping)
        ↓
    Canonical IR
        ↓
    IR Validation Suite ← (already built, is the contract)

The adapter does NOT contain hardcoded if/else logic. Instead, it
interprets CISCO_TO_IR_MAPPING spec to determine resource types and
attributes.
"""
import re
import hashlib
from typing import Any

from configguard.adapters.base import VendorAdapter
from configguard.models import CanonicalResource


# ---------------------------------------------------------------------------
# Declarative Mapping Spec — Cisco IOS → Canonical IR v1
# ---------------------------------------------------------------------------
# This spec is the KEY ASSET. It defines the translation rules declaratively.
# The adapter interprets this spec — it does not contain hardcoded logic.
#
# Format per resource_type:
#   "resource_type": {
#       "description": str,
#       "scope": "global" | "endpoint" | "resource",
#       "match": [line patterns to detect this resource],
#       "attributes": {
#           attr_name: {
#               "extract": extraction_method,
#               "regex": optional regex for extraction
#           }
#       },
#       "block_type": "global" | "interface" | "line" (optional)
#   }
# ---------------------------------------------------------------------------
CISCO_TO_IR_MAPPING = {
    "auth.aaa": {
        "description": "AAA authentication configuration",
        "scope": "resource",
        "match": [
            r"^\s*aaa new-model",
            r"^\s*no aaa new-model",
        ],
        "attributes": {
            "enabled": {
                "extract": "enabled_flag",
                "pattern": r"aaa new-model",
                "value_map": {True: True, False: False},
            },
            "model_type": {
                "extract": "model_type",
            },
        },
    },
    "auth.remote_access": {
        "description": "Remote access (VTY/Console) configuration",
        "scope": "endpoint",
        "block_type": "line",
        "match": [
            r"^\s*line vty",
        ],
        "attributes": {
            "methods": {
                "extract": "transport_input",
                "required": False,
            },
            "authentication_required": {
                "extract": "auth_required",
                "default": True,
            },
        },
        "sub_attributes": {
            "transport input": "methods",
        },
    },
    "network.snmp": {
        "description": "SNMP configuration",
        "scope": "resource",
        "match": [
            r"^\s*snmp-server community",
        ],
        "attributes": {
            "enabled": {
                "extract": "enabled_flag",
                "value_map": {True: True},
            },
            "communities": {
                "extract": "snmp_communities",
            },
            "version": {
                "extract": "snmp_version",
            },
            "access_level": {
                "extract": "snmp_access_level",
            },
        },
    },
    "network.management": {
        "description": "HTTP/HTTPS management interface",
        "scope": "resource",
        "match": [
            r"^\s*ip http server",
            r"^\s*ip http secure-server",
        ],
        "attributes": {
            "enabled": {
                "extract": "enabled_flag",
            },
            "secure_only": {
                "extract": "secure_only",
                "pattern": r"secure-server",
            },
        },
    },
    "logging.syslog": {
        "description": "Remote syslog configuration",
        "scope": "resource",
        "match": [
            r"^\s*logging host",
            r"^\s*logging server",
        ],
        "attributes": {
            "enabled": {
                "extract": "enabled_flag",
            },
            "remote_hosts": {
                "extract": "logging_hosts",
            },
        },
    },
    "monitoring.ntp": {
        "description": "NTP server configuration",
        "scope": "resource",
        "match": [
            r"^\s*ntp server",
        ],
        "attributes": {
            "enabled": {
                "extract": "enabled_flag",
            },
            "servers": {
                "extract": "ntp_servers",
            },
        },
    },
    "network.interface": {
        "description": "Network interface configuration",
        "scope": "endpoint",
        "block_type": "interface",
        "match": [
            r"^\s*interface\s+",
        ],
        "attributes": {
            "enabled": {
                "extract": "interface_enabled",
                "default": True,
            },
        },
    },
}


def compute_resource_id(resource_type: str, name: str, scope: str, extra: str = "") -> str:
    """Compute a deterministic resource ID."""
    content = f"{resource_type}:{name}:{scope}:{extra}"
    return hashlib.sha256(content.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Cisco IOS Adapter — Naive, Spec-Driven Implementation
# ---------------------------------------------------------------------------
class CiscoIOSAdapter(VendorAdapter):
    """Cisco IOS configuration → Canonical IR v1 adapter."""

    vendor_id = "cisco_ios"

    @property
    def mapping_spec(self) -> dict:
        return CISCO_TO_IR_MAPPING

    def parse(self, raw_config: str, metadata: dict | None = None) -> list[CanonicalResource]:
        """Parse Cisco IOS config into Canonical IR.

        Pipeline:
            1. Tokenize (split lines)
            2. Group into blocks (interface, line vty, global)
            3. Interpret mapping spec for each block
            4. Build CanonicalResource list
            5. Deduplicate
        """
        lines = self._tokenize(raw_config)
        blocks = self._group_blocks(lines)

        resources = []
        for block in blocks:
            mapped = self._map_block(block, metadata or {})
            resources.extend(mapped)

        return self._deduplicate(resources)

    def _tokenize(self, config: str) -> list[dict]:
        """Split config into labeled lines with metadata."""
        lines = []
        for i, line in enumerate(config.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("!"):
                continue
            lines.append({
                "raw": line,
                "stripped": stripped,
                "line_num": i,
            })
        return lines

    def _group_blocks(self, lines: list[dict]) -> list[dict]:
        """Group lines into configuration blocks.

        Key principle: Global config lines (aaa, snmp, logging, ntp, http)
        are NEVER part of interface/line blocks — they are always global.

        Returns list of blocks, each with:
            - type: "interface" | "line" | "global"
            - name: block name (e.g., "GigabitEthernet0/1" or "vty 0 4")
            - lines: list of lines in block
        """
        blocks = []
        current_block = None
        pending_global_lines = []

        # Lines that are always global, never part of interface/line blocks
        GLOBAL_ONLY_KEYWORDS = [
            "aaa new-model",
            "no aaa new-model",
            "snmp-server",
            "ip http",
            "logging host",
            "logging server",
            "ntp server",
            "ntp master",
        ]

        def is_global_line(stripped: str) -> bool:
            for kw in GLOBAL_ONLY_KEYWORDS:
                if kw in stripped:
                    return True
            return False

        for line in lines:
            stripped = line["stripped"]

            # Interface block
            if stripped.startswith("interface "):
                # Flush any pending global lines first
                if pending_global_lines:
                    blocks.append({
                        "type": "global",
                        "name": "global",
                        "lines": pending_global_lines[:],
                    })
                    pending_global_lines.clear()
                if current_block:
                    blocks.append(current_block)
                current_block = {
                    "type": "interface",
                    "name": stripped.replace("interface ", ""),
                    "lines": [line],
                }
                continue

            # Line block (line vty, line con)
            if stripped.startswith("line "):
                # Flush any pending global lines first
                if pending_global_lines:
                    blocks.append({
                        "type": "global",
                        "name": "global",
                        "lines": pending_global_lines[:],
                    })
                    pending_global_lines.clear()
                if current_block:
                    blocks.append(current_block)
                current_block = {
                    "type": "line",
                    "name": stripped.replace("line ", ""),
                    "lines": [line],
                }
                continue

            # Global-only line — never part of interface/line blocks
            if is_global_line(stripped):
                if current_block:
                    blocks.append(current_block)
                    current_block = None
                pending_global_lines.append(line)
                continue

            # Normal line
            if current_block:
                current_block["lines"].append(line)
            else:
                pending_global_lines.append(line)

        # Flush any remaining global lines or current block
        if pending_global_lines:
            blocks.append({
                "type": "global",
                "name": "global",
                "lines": pending_global_lines[:],
            })
        if current_block:
            blocks.append(current_block)

        return blocks

    def _map_block(self, block: dict, metadata: dict) -> list[CanonicalResource]:
        """Interpret mapping spec for a configuration block.

        For each resource type in the mapping spec, check if the block
        matches the resource's match patterns. If so, extract attributes
        and build a CanonicalResource.
        """
        resources = []
        block_type = block["type"]
        block_name = block["name"]
        block_lines = block["lines"]

        # Check each resource type in mapping spec
        for resource_type, spec in CISCO_TO_IR_MAPPING.items():
            spec_block_type = spec.get("block_type", "global")

            # Filter by block type if specified
            if spec_block_type != "global" and spec_block_type != block_type:
                continue

            # Check if block matches this resource's patterns
            if not self._block_matches(block_lines, spec["match"]):
                continue

            # Extract attributes per the spec
            attributes = self._extract_attributes(block_lines, block_type, spec)

            # Build resource ID
            # For global resources, name is "default"; for endpoint, use block name
            if block_type == "global":
                resource_name = "default"
            else:
                resource_name = block_name

            extra = resource_name
            rid = compute_resource_id(resource_type, extra, spec["scope"], resource_name)

            resource = CanonicalResource(
                id=rid,
                resource_type=resource_type,
                name=resource_name,
                attributes=attributes,
                scope=spec["scope"],
                source={
                    "vendor": self.vendor_id,
                    "block_type": block_type,
                    "block_name": block_name,
                    "line_count": len(block_lines),
                    "metadata": metadata,
                },
                relationships=[],
                tags=self._compute_tags(resource_type, attributes),
            )
            resources.append(resource)

        return resources

    def _block_matches(self, block_lines: list[dict], patterns: list[str]) -> bool:
        """Check if any line in block matches any of the patterns."""
        for line in block_lines:
            for pattern in patterns:
                if re.search(pattern, line["stripped"], re.IGNORECASE):
                    return True
        return False

    def _extract_attributes(
        self,
        block_lines: list[dict],
        block_type: str,
        spec: dict
    ) -> dict:
        """Extract attributes from block lines per mapping spec."""
        attributes = {}

        for attr_name, attr_spec in spec.get("attributes", {}).items():
            extract_method = attr_spec["extract"]
            value = self._extract_attribute_value(
                block_lines, block_type, attr_name, extract_method, attr_spec
            )

            # Apply default if extraction returned None and default specified
            if value is None and "default" in attr_spec:
                value = attr_spec["default"]

            if value is not None:
                attributes[attr_name] = value

        return attributes

    def _extract_attribute_value(
        self,
        block_lines: list[dict],
        block_type: str,
        attr_name: str,
        extract_method: str,
        attr_spec: dict
    ) -> Any:
        """Extract a single attribute value using the specified method."""
        lines = [l["stripped"] for l in block_lines]

        if extract_method == "enabled_flag":
            for line in lines:
                if "no aaa new-model" in line:
                    return False
                if "aaa new-model" in line:
                    return True
            return None

        elif extract_method == "model_type":
            for line in lines:
                if "aaa new-model" in line:
                    if line.strip().startswith("no"):
                        return "legacy"
                    return "new-model"
            return "legacy"

        elif extract_method == "transport_input":
            for line in lines:
                if "transport input" in line.lower():
                    # Extract methods: "transport input telnet ssh"
                    parts = line.split()
                    if "input" in parts:
                        idx = parts.index("input")
                        methods = [p.lower() for p in parts[idx+1:] if p.lower() in ("telnet", "ssh", "vtp")]
                        return methods if methods else None
            return None

        elif extract_method == "auth_required":
            # Default to True for VTY lines
            if block_type == "line":
                return True
            return None

        elif extract_method == "snmp_communities":
            communities = []
            for line in lines:
                match = re.search(r"snmp-server community\s+(\S+)", line, re.IGNORECASE)
                if match:
                    communities.append(match.group(1))
            return communities if communities else None

        elif extract_method == "snmp_version":
            for line in lines:
                if "snmp-server" in line.lower():
                    if "2c" in line.lower():
                        return "v2c"
                    if "version 1" in line.lower():
                        return "v1"
                    if "version 2" in line.lower() and "2c" not in line.lower():
                        return "v2"
            return "v2c"  # default

        elif extract_method == "snmp_access_level":
            for line in lines:
                if "snmp-server community" in line.lower():
                    if " RW" in line or "read-write" in line.lower():
                        return "RW"
                    return "RO"
            return "RO"  # default

        elif extract_method == "secure_only":
            for line in lines:
                if "secure-server" in line:
                    return True
                if "http server" in line and "secure" not in line:
                    return False
            return None

        elif extract_method == "logging_hosts":
            hosts = []
            for line in lines:
                match = re.search(r"logging host\s+(\S+)", line, re.IGNORECASE)
                if match:
                    hosts.append(match.group(1))
            return hosts if hosts else None

        elif extract_method == "ntp_servers":
            servers = []
            for line in lines:
                match = re.search(r"ntp server\s+(\S+)", line, re.IGNORECASE)
                if match:
                    servers.append(match.group(1))
            return servers if servers else None

        elif extract_method == "interface_enabled":
            for line in lines:
                stripped = line.strip()
                if stripped == "shutdown":
                    return False
                if stripped.startswith("no shutdown") or stripped == "no shutdown":
                    return True
            return True  # default: no shutdown = enabled

        return None

    def _compute_tags(self, resource_type: str, attributes: dict) -> list[str]:
        """Compute tags based on resource type and attributes."""
        tags = []

        if resource_type.startswith("auth."):
            tags.append("security-critical")
        elif resource_type.startswith("network."):
            tags.append("mgmt-plane")
        elif resource_type.startswith("logging."):
            tags.append("observability")
        elif resource_type.startswith("monitoring."):
            tags.append("observability")

        # Security-relevant attributes
        if "insecure_methods" in attributes or "telnet" in attributes.get("methods", []):
            tags.append("security-risk")
        if attributes.get("enabled") is False:
            tags.append("security-risk")

        return tags

    def _deduplicate(self, resources: list[CanonicalResource]) -> list[CanonicalResource]:
        """Remove duplicate resources (same id keeps first)."""
        seen = set()
        unique = []
        for r in resources:
            if r.id not in seen:
                seen.add(r.id)
                unique.append(r)
        return unique
