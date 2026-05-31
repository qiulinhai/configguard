# Canonical IR v1 — Architecture Freeze Specification

**Status**: FROZEN (v1.0) — Do not modify without ADR
**Version**: IR v1.0
**Date**: 2026-05-30
**Purpose**: Lock the IR v1 contract for v0.3+ development

---

## 0. Why Freeze Now

IR v1 has been validated across:

| Validation | Cisco IOS | Linux SSH |
|------------|-----------|-----------|
| Schema invariants | ✅ | ✅ |
| Rule coverage (8 rules) | ✅ | ✅ |
| Deterministic output | ✅ | ✅ |
| Vendor-neutral resource types | ✅ | ✅ |
| Cross-domain scope stability | ✅ | ✅ |

**IR v1 is ABI-stable.** Further changes require ADR process (see Section 7).

---

## 1. CanonicalResource — Frozen ABI

```python
@dataclass
class CanonicalResource:
    """Vendor-neutral semantic model of a security-relevant configuration resource."""
    id: str                           # Frozen: format documented in Section 3
    resource_type: str               # Frozen: see Section 4 taxonomy
    name: str                         # Frozen: logical name
    attributes: dict                  # Frozen: see Section 5 attribute contract
    scope: str                        # Frozen: see Section 2 scope enum
    source: dict                      # Frozen: required fields in Section 6
    relationships: list[str]          # Frozen: list of CanonicalResource IDs
    tags: list[str]                   # Frozen: classification hints
```

**ABI Invariants (enforced by `test_schema_invariants.py`)**:

```python
# All of these are enforced by pytest — any change to CanonicalResource
# that breaks these invariants is a BREAKING CHANGE requiring ADR.

1.  isinstance(r.id, str) and len(r.id) > 0
2.  isinstance(r.resource_type, str) and len(r.resource_type) > 0
3.  isinstance(r.attributes, dict)
4.  r.scope in {"global", "endpoint", "resource"}
5.  "vendor" in r.source and "line" in r.source
6.  isinstance(r.relationships, list)
7.  isinstance(r.tags, list)
8.  len(set(r.id for r in ir)) == len(ir)  # IDs unique within IR
9.  No vendor keywords in resource_type: cisco, ios, juniper, junos, nxos, linux
```

---

## 2. Scope — Frozen Enum

Three scopes only:

| Scope | Meaning | Used For |
|-------|---------|----------|
| `resource` | Global/daemon-level configuration | AAA, SNMP, syslog, NTP, HTTP, SSH daemon |
| `endpoint` | Interface or line-level configuration | VTY, Console, Physical Interface |
| `global` | Reserved for future use | Not used in v1 |

**Rules**:
- Scope is a coarse classification, not a granular identifier
- Do NOT add new scopes without ADR
- Scope determines evaluation context, not security semantics

---

## 3. ID Format — Frozen Specification

**Format**: `{domain}:{type}:{name}:{scope_hash}`

- `domain`: Top-level security domain (e.g., `auth`, `network`, `logging`, `monitoring`)
- `type`: Subtype within domain (e.g., `remote_access`, `snmp`, `syslog`, `ntp`)
- `name`: Logical resource name (e.g., `vty0-4`, `default`, `GigabitEthernet0/1`)
- `scope_hash`: 12-char deterministic hash of scope content

**Example IDs**:

```
auth.remote_access:vty0-4:endpoint:a1b2c3d4e5f6
auth.aaa:default:resource:abc123def456
network.snmp:default:resource:b2c3d4e5f6a1
```

**ID Stability Rules**:
- ID must be deterministically computable from resource content
- Same semantic content from any vendor MUST produce same ID
- ID is NOT used for rule matching — only for deduplication and relationships

---

## 4. Resource Type Taxonomy — Frozen v1

**Rule**: resource_type format is `domain.subtype` (lowercase, dot-separated).

### 4.1 Auth Domain

| resource_type | Meaning | Scope |
|---------------|---------|-------|
| `auth.aaa` | AAA configuration | resource |
| `auth.remote_access` | Remote access (VTY/SSH/Console) | endpoint or resource |

### 4.2 Network Domain

| resource_type | Meaning | Scope |
|---------------|---------|-------|
| `network.snmp` | SNMP configuration | resource |
| `network.management` | HTTP/HTTPS management interface | resource |
| `network.interface` | Network interface | endpoint |

### 4.3 Logging Domain

| resource_type | Meaning | Scope |
|---------------|---------|-------|
| `logging.syslog` | Remote syslog | resource |

### 4.4 Monitoring Domain

| resource_type | Meaning | Scope |
|---------------|---------|-------|
| `monitoring.ntp` | NTP server configuration | resource |

### 4.5 Crypto Domain (RESERVED for v1.1)

| resource_type | Status |
|---------------|--------|
| `crypto.tls` | Reserved |
| `crypto.certificate` | Reserved |

### 4.6 OS Security Domain (RESERVED for v1.1)

| resource_type | Status |
|---------------|--------|
| `os.pam` | Reserved |
| `os.sudoers` | Reserved |
| `os.sysctl` | Reserved |

**Adding new resource types requires ADR** (see Section 7).

---

## 5. Attribute Contract — Frozen

**Principles**:
1. Attributes encode **semantic facts** (what the config means), NOT syntax
2. Attribute names are vendor-neutral by design
3. Attribute values are primitive types or lists — no nested dicts
4. Every attribute must have a clear, security-relevant meaning

### 5.1 Core Attribute Conventions

| Attribute Pattern | Meaning | Type |
|-------------------|---------|------|
| `enabled` | Whether resource is active | `bool` or `None` |
| `methods` | Access/transport methods available | `list[str]` |
| `secure_methods` | Secure access methods | `list[str]` |
| `insecure_methods` | Insecure access methods | `list[str]` |
| `communities` | SNMP communities or access strings | `list[str]` |
| `access_level` | RO/RW access level | `list[str]` |
| `servers` | List of server IPs/hosts | `list[str]` |
| `remote_hosts` | List of remote log hosts | `list[str]` |

### 5.2 auth.remote_access Attributes

```python
{
    "methods": list[str],              # e.g., ["telnet", "ssh"]
    "insecure_methods": list[str],     # e.g., ["telnet"]
    "secure_methods": list[str],        # e.g., ["ssh"]
    "authentication_required": bool,    # default True
    "password_auth": bool | None,      # Linux SSH only
    "pubkey_auth": bool | None,        # Linux SSH only
    "root_login": bool | None,         # Linux SSH only
    "protocol_version": int | None,    # e.g., 2
}
```

### 5.3 network.snmp Attributes

```python
{
    "enabled": bool,
    "version": str,                    # "v1", "v2c", "v2", "v3"
    "communities": list[str],          # community strings
    "access_level": list[str],         # ["RO"] or ["RW"]
}
```

### 5.4 OS Security Attributes (for future Linux Security Adapter)

```python
{
    "pwquality_minlen": int | None,
    "pwquality_dcredit": int | None,
    "sudo_without_password": bool | None,
    "sysctl_net_ipv4_conf_all_accept_redirects": int | None,
}
```

---

## 6. Source Contract — Frozen

Every CanonicalResource MUST have a `source` dict with these required fields:

```python
source: {
    "vendor": str,           # e.g., "cisco_ios", "linux_ssh"
    "line": str | None,      # Original config line (or block summary)
}
```

Optional fields (recommended but not required):
```python
source: {
    "vendor": str,
    "line": str | None,
    "block_type": str | None,        # e.g., "interface", "line", "global"
    "block_name": str | None,       # e.g., "GigabitEthernet0/1"
    "file": str | None,             # e.g., "/etc/ssh/sshd_config"
    "parser": str | None,            # e.g., "sshd_config"
    "metadata": dict | None,         # Extra vendor-specific context
}
```

---

## 7. IR Change Process (ADR Required)

**Any change to frozen IR v1 requires Architecture Decision Record**:

| Change Type | Requires ADR | Examples |
|-------------|-------------|----------|
| ABI change | YES | Add required field to CanonicalResource |
| New resource_type | YES | Adding `crypto.tls` |
| Scope change | YES | Adding `user` scope |
| Attribute rename | YES | Renaming `methods` to `access_methods` |
| New attribute | NO (opt-in) | Adding `max_auth_tries` to auth.remote_access |
| New adapter | NO | Adding Juniper adapter |

**ADR Process**:
1. Propose change in `docs/superpowers/adr/YYYY-MM-DD-<topic>.md`
2. Must include: rationale, impact analysis, migration path
3. IR Core Team review required
4. Version bump: v1.0 → v1.1 for additive, v2.0 for breaking

---

## 8. Validation Suite

The IR v1 contract is enforced by the validation suite at:

```
tests/ir_validation/
├── test_schema_invariants.py      # ABI invariants
├── test_rule_coverage_matrix.py   # 8 rules ↔ IR coverage
├── test_determinism.py           # Pure function guarantees
├── test_golden_ir_snapshots.py   # Regression prevention
└── test_cross_domain.py          # Cisco + Linux vendor neutrality
```

**All 91+ tests must pass for any IR change to be considered valid.**

---

## 9. Adapters — v1.0 Status

| Adapter | Status | Notes |
|---------|--------|-------|
| `CiscoIOSAdapter` | ✅ Production | Covers auth, network, logging, monitoring |
| `LinuxSShadapter` | ✅ Production | Covers auth.remote_access |

**Future adapters (not implemented)**:
- Juniper JunOS adapter
- Nginx TLS adapter
- Kubernetes RBAC adapter
- AWS IAM adapter

---

## 10. Summary

IR v1 is a **frozen, vendor-neutral, semantic security model**.

It is NOT:
- A Cisco abstraction
- A network-specific model
- A parser output format

It IS:
- A universal security intent model
- Cross-domain compatible (auth + network + logging + monitoring)
- Cross-vendor validated (Cisco IOS + Linux SSH)
- Deterministic and lossless
- Rule-engine agnostic

**Freeze date**: 2026-05-30
**Next review**: v1.1 planning (post v0.3 release)
