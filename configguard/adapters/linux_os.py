"""Linux OS Security → Canonical IR Adapter — v0.3.

Covers Linux security baseline configs:
- /etc/security/pwquality.conf (PAM password quality)
- /etc/sudoers (sudo access control)
- /etc/sysctl.conf (kernel hardening via sysctl)

This adapter extends IR beyond networking into OS security domain,
validating that IR v1 is truly universal (not just network-focused).

Purpose:
    Prove IR v1 can model OS-level security policies, not just network configs.
    auth.remote_access    → network domain
    os.pam, os.sudoers  → OS security domain
    → Same IR schema, different domains
"""
import re
import hashlib
from configguard.adapters.base import VendorAdapter
from configguard.models import CanonicalResource


def compute_resource_id(resource_type: str, name: str, scope: str, extra: str = "") -> str:
    content = f"{resource_type}:{name}:{scope}:{extra}"
    return hashlib.sha256(content.encode()).hexdigest()[:12]


LINUX_OS_MAPPING = {
    "os.pam": {
        "description": "PAM password quality configuration",
        "scope": "resource",
        "match": ["pwquality", "pam_pwquality"],
        "attributes": {
            "minlen": {"extract": "pwquality_minlen"},
            "dcredit": {"extract": "pwquality_dcredit"},
            "ucredit": {"extract": "pwquality_ucredit"},
            "lcredit": {"extract": "pwquality_lcredit"},
            "ocredit": {"extract": "pwquality_ocredit"},
        },
    },
    "os.sudoers": {
        "description": "Sudo access control configuration",
        "scope": "resource",
        "match": ["sudo", "sudoers"],
        "attributes": {
            "permit_root": {"extract": "sudo_permit_root"},
            "nopasswd": {"extract": "sudo_nopasswd"},
            "requiretty": {"extract": "sudo_requiretty"},
        },
    },
    "os.sysctl": {
        "description": "Kernel hardening (sysctl) configuration",
        "scope": "resource",
        "match": ["sysctl", "kernel"],
        "attributes": {
            "ipv4_conf_all_accept_redirects": {"extract": "sysctl_ipv4_accept_redirects"},
            "ipv4_conf_all_send_redirects": {"extract": "sysctl_ipv4_send_redirects"},
            "ipv4_tcp_syncookies": {"extract": "sysctl_ipv4_tcp_syncookies"},
            "net_ipv4_ip_forward": {"extract": "sysctl_ipv4_forward"},
        },
    },
}


class LinuxOSSecurityAdapter(VendorAdapter):
    """Linux OS security configuration → Canonical IR adapter."""

    vendor_id = "linux_os"

    @property
    def mapping_spec(self) -> dict:
        return LINUX_OS_MAPPING

    def parse(self, raw_config: str, metadata: dict | None = None) -> list[CanonicalResource]:
        """Parse Linux OS security configs into Canonical IR.

        Supports:
        - pwquality.conf style: minlen = 12
        - sysctl.conf style: kernel.param = value
        - sudoers style: user hosts = commands
        """
        lines = raw_config.splitlines()
        resources = []

        # PAM pwquality
        pwquality_attrs = self._parse_pwquality(lines)
        if pwquality_attrs:
            rid = compute_resource_id("os.pam", "pwquality", "resource", "pwquality")
            resources.append(CanonicalResource(
                id=rid,
                resource_type="os.pam",
                name="pwquality",
                attributes=pwquality_attrs,
                scope="resource",
                source={"vendor": self.vendor_id, "parser": "pwquality.conf"},
                relationships=[],
                tags=["os-security", "authentication"],
            ))

        # Sudoers
        sudoers_attrs = self._parse_sudoers(lines)
        if sudoers_attrs:
            rid = compute_resource_id("os.sudoers", "sudoers", "resource", "sudoers")
            resources.append(CanonicalResource(
                id=rid,
                resource_type="os.sudoers",
                name="sudoers",
                attributes=sudoers_attrs,
                scope="resource",
                source={"vendor": self.vendor_id, "parser": "sudoers"},
                relationships=[],
                tags=["os-security", "privilege-escalation"],
            ))

        # Sysctl
        sysctl_attrs = self._parse_sysctl(lines)
        if sysctl_attrs:
            rid = compute_resource_id("os.sysctl", "kernel", "resource", "sysctl")
            resources.append(CanonicalResource(
                id=rid,
                resource_type="os.sysctl",
                name="kernel",
                attributes=sysctl_attrs,
                scope="resource",
                source={"vendor": self.vendor_id, "parser": "sysctl.conf"},
                relationships=[],
                tags=["os-security", "kernel-hardening"],
            ))

        return self._deduplicate(resources)

    def _parse_pwquality(self, lines: list[str]) -> dict:
        attrs = {}
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                key, value = stripped.split("=", 1)
                key = key.strip()
                value = value.strip()

                if key == "minlen":
                    attrs["pwquality_minlen"] = int(value) if value.isdigit() else None
                elif key == "dcredit":
                    attrs["pwquality_dcredit"] = int(value) if value.lstrip("-").isdigit() else None
                elif key == "ucredit":
                    attrs["pwquality_ucredit"] = int(value) if value.lstrip("-").isdigit() else None
                elif key == "lcredit":
                    attrs["pwquality_lcredit"] = int(value) if value.lstrip("-").isdigit() else None
                elif key == "ocredit":
                    attrs["pwquality_ocredit"] = int(value) if value.lstrip("-").isdigit() else None
        return attrs

    def _parse_sudoers(self, lines: list[str]) -> dict:
        attrs = {}
        permit_root = None
        nopasswd_count = 0
        requiretty = None

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Skip if not sudoers-style directive
            if "=" in stripped or "ALL" in stripped:
                line_lower = stripped.lower()

                # Check for root permission
                if "nopasswd" in line_lower or "NOPASSWD" in stripped:
                    nopasswd_count += 1
                if "permit_root" in line_lower or "root" in line_lower:
                    permit_root = True
                if "requiretty" in line_lower or "requiretty" in stripped:
                    requiretty = True

        # Infer from findings
        if nopasswd_count > 0:
            attrs["sudo_nopasswd"] = True
        if permit_root is not None:
            attrs["sudo_permit_root"] = permit_root
        if requiretty is not None:
            attrs["sudo_requiretty"] = requiretty

        return attrs

    def _parse_sysctl(self, lines: list[str]) -> dict:
        attrs = {}
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                continue

            key, value = stripped.split("=", 1)
            key = key.strip()
            value = value.strip()

            # Normalize IPv4 keys to semantic attribute names
            if key == "net.ipv4.conf.all.accept_redirects":
                attrs["ipv4_conf_all_accept_redirects"] = int(value)
            elif key == "net.ipv4.conf.all.send_redirects":
                attrs["ipv4_conf_all_send_redirects"] = int(value)
            elif key == "net.ipv4.tcp_syncookies":
                attrs["ipv4_tcp_syncookies"] = int(value)
            elif key == "net.ipv4.ip_forward":
                attrs["ipv4_ip_forward"] = int(value)

        return attrs

    def _deduplicate(self, resources: list[CanonicalResource]) -> list[CanonicalResource]:
        seen = set()
        unique = []
        for r in resources:
            if r.id not in seen:
                seen.add(r.id)
                unique.append(r)
        return unique
