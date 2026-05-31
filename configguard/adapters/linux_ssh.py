"""Linux SSH (sshd_config) → Canonical IR Adapter — v0.3.

This adapter validates that Canonical IR is truly vendor-neutral by showing
that Linux SSH security config maps to the SAME resource types as Cisco IOS.

Goal:
    /etc/ssh/sshd_config  →  auth.remote_access
    Cisco VTY             →  auth.remote_access
    → SAME resource_type, SAME attributes, SAME rule engine

Evidence that IR is universal, not Cisco-biased.
"""
import re
import hashlib
from configguard.adapters.base import VendorAdapter
from configguard.models import CanonicalResource


def compute_resource_id(resource_type: str, name: str, scope: str, extra: str = "") -> str:
    content = f"{resource_type}:{name}:{scope}:{extra}"
    return hashlib.sha256(content.encode()).hexdigest()[:12]


LINUX_SSH_MAPPING = {
    "auth.remote_access": {
        "description": "SSH daemon security configuration",
        "scope": "resource",
        "match": ["sshd_config"],
        "attributes": {
            "password_auth": {"extract": "bool"},
            "pubkey_auth": {"extract": "bool"},
            "root_login": {"extract": "bool"},
            "protocol_version": {"extract": "int"},
        },
    },
}


class LinuxSShadapter(VendorAdapter):
    """Linux SSH (sshd_config) → Canonical IR adapter."""

    vendor_id = "linux_ssh"

    @property
    def mapping_spec(self) -> dict:
        return LINUX_SSH_MAPPING

    def parse(self, raw_config: str, metadata: dict | None = None) -> list[CanonicalResource]:
        """Parse sshd_config into Canonical IR.

        Linux sshd_config                          → IR
        PasswordAuthentication no                 → auth.remote_access.password_auth
        PubkeyAuthentication yes                 → auth.remote_access.pubkey_auth
        PermitRootLogin no                        → auth.remote_access.root_login
        Protocol 2                                → auth.remote_access.protocol_version
        Ciphers aes256-ctr,aes192-ctr            → auth.remote_access.cipher_suite
        """
        lines = self._tokenize(raw_config)
        resources = self._parse(lines, metadata or {})
        return self._deduplicate(resources)

    def _tokenize(self, config: str) -> list[dict]:
        """Split sshd_config into key-value lines."""
        result = []
        for i, line in enumerate(config.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Handle "Key Value" and "Key = Value" formats
            if "=" in stripped:
                parts = stripped.split("=", 1)
            else:
                parts = stripped.split(None, 1)
            if len(parts) == 2:
                result.append({
                    "key": parts[0].strip(),
                    "value": parts[1].strip(),
                    "raw": line,
                    "line_num": i,
                })
            else:
                result.append({
                    "key": parts[0].strip(),
                    "value": "",
                    "raw": line,
                    "line_num": i,
                })
        return result

    def _parse(self, lines: list[dict], metadata: dict) -> list[CanonicalResource]:
        """Parse sshd_config directives into auth.remote_access resources."""
        resources = []

        # Aggregate all security-relevant directives into one auth.remote_access
        auth_attrs = {
            "password_auth": None,
            "pubkey_auth": None,
            "root_login": None,
            "protocol_version": None,
            "cipher_suite": [],
            "kex_algorithms": [],
            "mac_algorithms": [],
            "login_grace_time": None,
            "max_auth_tries": None,
        }

        for line in lines:
            key = line["key"]
            value = line["value"]

            if key == "PasswordAuthentication":
                auth_attrs["password_auth"] = value.lower() == "yes"
            elif key == "PubkeyAuthentication":
                auth_attrs["pubkey_auth"] = value.lower() == "yes"
            elif key == "PermitRootLogin":
                auth_attrs["root_login"] = value.lower() == "yes"
            elif key == "Protocol":
                auth_attrs["protocol_version"] = int(value.strip()) if value.strip().isdigit() else 2
            elif key == "Ciphers":
                auth_attrs["cipher_suite"] = [c.strip() for c in value.split(",")]
            elif key == "KexAlgorithms":
                auth_attrs["kex_algorithms"] = [k.strip() for k in value.split(",")]
            elif key == "MACs":
                auth_attrs["mac_algorithms"] = [m.strip() for m in value.split(",")]
            elif key == "LoginGraceTime":
                auth_attrs["login_grace_time"] = int(value) if value.isdigit() else None
            elif key == "MaxAuthTries":
                auth_attrs["max_auth_tries"] = int(value) if value.isdigit() else None

        # Compute derived security attributes
        security_methods = []
        if auth_attrs.get("pubkey_auth"):
            security_methods.append("pubkey")
        if auth_attrs.get("password_auth"):
            security_methods.append("password")
        if auth_attrs.get("root_login"):
            security_methods.append("root")

        # Infer secure_methods vs insecure_methods
        # In Linux SSH context: pubkey=yes is secure, password=yes is weaker
        secure_methods = [m for m in security_methods if m in ("pubkey",)]
        insecure_methods = [m for m in security_methods if m in ("password",)]

        rid = compute_resource_id("auth.remote_access", "sshd", "resource", "sshd")

        resource = CanonicalResource(
            id=rid,
            resource_type="auth.remote_access",
            name="sshd",
            attributes={
                "password_auth": auth_attrs.get("password_auth"),
                "pubkey_auth": auth_attrs.get("pubkey_auth"),
                "root_login": auth_attrs.get("root_login"),
                "protocol_version": auth_attrs.get("protocol_version"),
                "cipher_suite": auth_attrs.get("cipher_suite") or [],
                "security_methods": security_methods,
                "secure_methods": secure_methods,
                "insecure_methods": insecure_methods,
                "login_grace_time": auth_attrs.get("login_grace_time"),
                "max_auth_tries": auth_attrs.get("max_auth_tries"),
            },
            scope="resource",
            source={
                "vendor": self.vendor_id,
                "parser": "sshd_config",
                "file": "/etc/ssh/sshd_config",
            },
            relationships=[],
            tags=self._compute_tags(auth_attrs),
        )
        resources.append(resource)
        return resources

    def _compute_tags(self, attrs: dict) -> list[str]:
        tags = ["security-critical", "auth"]
        if attrs.get("password_auth") is False:
            tags.append("secure-auth")
        if attrs.get("pubkey_auth") is True:
            tags.append("secure-auth")
        if attrs.get("root_login") is False:
            tags.append("secure-auth")
        if attrs.get("root_login") is True:
            tags.append("security-risk")
        return tags

    def _deduplicate(self, resources: list[CanonicalResource]) -> list[CanonicalResource]:
        seen = set()
        unique = []
        for r in resources:
            if r.id not in seen:
                seen.add(r.id)
                unique.append(r)
        return unique
