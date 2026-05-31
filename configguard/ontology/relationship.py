"""Security Relationship Model — IR v1 Relationship Extension.

Purpose:
Extend IR v1 from flat resource list to structured knowledge graph by
adding typed cross-resource relationships.

Relationship Types:
    depends_on       — Resource requires another to function (e.g., VTY requires interface)
    constrained_by   — Resource behavior is limited by another (e.g., SSH by sysctl)
    exposed_by       — Resource creates attack surface via another (e.g., mgmt via SNMP)
    peer_of          — Resources are at same layer, related by configuration
    grants_access_to — RBAC: role grants permissions to subjects
    network_path_to  — Network connectivity between endpoints

Architecture:
    CanonicalResource.relationships (already exists, was under-used)
        ↓
    RelationshipBuilder (new)
        ↓
    SecurityKnowledgeGraph (new)
        ↓
    Relationship-aware Rule Engine (future)

Example Relationship Graph:
    auth.remote_access (vty0-4)
        ├── depends_on → network.interface (physical interface)
        ├── constrained_by → os.sysctl (kernel hardening)
        ├── peer_of → network.snmp (both mgmt-plane)
        └── exposed_by → network.management (HTTP mgmt)

    k8s.role_binding
        ├── grants_access_to → k8s.service_account
        ├── bound_to → auth.rbac.role
        └── subject_of → k8s.namespace
"""
from dataclasses import dataclass, field
from typing import TypedDict


class RelationshipType(str):
    """Relationship type taxonomy."""
    DEPENDS_ON = "depends_on"           # Functional dependency
    CONSTRAINED_BY = "constrained_by"  # Policy constraint
    EXPOSED_BY = "exposed_by"           # Attack surface exposure
    PEER_OF = "peer_of"                # Same-layer relationship
    GRANTS_ACCESS_TO = "grants_access_to"  # RBAC binding
    BOUND_TO = "bound_to"              # RBAC role binding
    SUBJECT_OF = "subject_of"           # RBAC subject scope
    NETWORK_PATH_TO = "network_path_to"  # Network connectivity
    CONTAINS = "contains"              # Container relationship


class Relationship(TypedDict):
    """A typed directed relationship between two resources."""
    type: RelationshipType
    source_id: str       # CanonicalResource.id of source
    target_id: str       # CanonicalResource.id of target
    direction: str       # "outbound" or "inbound"
    weight: int          # 1-10, importance of relationship


class ResourceGraphNode(TypedDict):
    """A resource node in the knowledge graph."""
    resource_id: str
    resource_type: str
    name: str
    relationships: list[Relationship]
