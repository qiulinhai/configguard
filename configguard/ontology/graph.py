"""Security Knowledge Graph — IR v1 Relationship Engine.

Builds a typed relationship graph from CanonicalResource list.

The knowledge graph captures cross-resource relationships that are
implicit in flat IR but become explicit in graph form:

    Flat IR:  [vty, snmp, sysctl] — 3 resources, no connections
    Graph:    vty → depends_on → interface
              vty → constrained_by → sysctl
              snmp → peer_of → vty (both mgmt-plane)

Usage:
    ir = [auth.remote_access, os.sysctl, ...]
    kg = SecurityKnowledgeGraph(ir)
    kg.build()
    kg.find_relationships("depends_on")
    kg.find_path("auth.remote_access", "os.sysctl")
"""
from dataclasses import dataclass, field
from typing import TypedDict

from configguard.models import CanonicalResource
from configguard.ontology.relationship import (
    Relationship,
    RelationshipType,
    ResourceGraphNode,
)


# ---------------------------------------------------------------------------
# Cross-Domain Relationship Rules
# ---------------------------------------------------------------------------
# Define relationship inference rules between resource types.
# Format: (source_type, target_type) -> relationship_type
# ---------------------------------------------------------------------------
RESOURCE_RELATIONSHIP_RULES: dict[tuple[str, str], RelationshipType] = {
    # Auth depends on network infrastructure
    ("auth.remote_access", "network.interface"): RelationshipType.DEPENDS_ON,
    ("auth.remote_access", "network.management"): RelationshipType.EXPOSED_BY,

    # OS security constrains auth
    ("auth.remote_access", "os.sysctl"): RelationshipType.CONSTRAINED_BY,
    ("auth.remote_access", "os.pam"): RelationshipType.CONSTRAINED_BY,

    # SNMP is management-plane peer of auth
    ("network.snmp", "auth.remote_access"): RelationshipType.PEER_OF,
    ("network.management", "auth.remote_access"): RelationshipType.PEER_OF,

    # K8s RBAC bindings
    ("auth.rbac.role_binding", "k8s.service_account"): RelationshipType.GRANTS_ACCESS_TO,
    ("auth.rbac.role_binding", "auth.rbac.role"): RelationshipType.BOUND_TO,
    ("auth.rbac.cluster_role_binding", "auth.rbac.cluster_role"): RelationshipType.BOUND_TO,

    # Network policy relates to network.interface
    ("k8s.network_policy", "network.interface"): RelationshipType.NETWORK_PATH_TO,

    # PSP related to pod execution context
    ("k8s.pod_security_policy", "os.sysctl"): RelationshipType.PEER_OF,  # kernel hardening related
}


# ---------------------------------------------------------------------------
# Knowledge Graph Builder
# ---------------------------------------------------------------------------
class SecurityKnowledgeGraph:
    """Build and query a security knowledge graph from IR resources."""

    def __init__(self, resources: list[CanonicalResource]):
        """Initialize graph with CanonicalResource list."""
        self.resources = {r.id: r for r in resources}
        self.nodes: dict[str, ResourceGraphNode] = {}
        self.relationships: list[Relationship] = []
        self._built = False

    def build(self) -> "SecurityKnowledgeGraph":
        """Build the knowledge graph from resources.

        Pipeline:
            1. Create graph nodes for each resource
            2. Infer relationships based on domain rules
            3. Infer relationships based on attribute analysis
        """
        # Phase 1: Create nodes
        for rid, resource in self.resources.items():
            self.nodes[rid] = ResourceGraphNode(
                resource_id=rid,
                resource_type=resource.resource_type,
                name=resource.name,
                relationships=[],
            )

        # Phase 2: Infer relationships from rules
        self._infer_relationships()

        # Phase 3: Populate node relationships
        self._populate_node_relationships()

        self._built = True
        return self

    def _infer_relationships(self):
        """Infer relationships based on resource type pairs."""
        resource_ids = list(self.resources.keys())
        resource_types = {rid: self.resources[rid].resource_type for rid in resource_ids}

        for i, source_id in enumerate(resource_ids):
            source_type = resource_types[source_id]
            source = self.resources[source_id]

            for target_id in resource_ids[i + 1:]:
                if source_id == target_id:
                    continue

                target_type = resource_types[target_id]
                target = self.resources[target_id]

                # Check explicit relationship rules
                pair = (source_type, target_type)
                if pair in RESOURCE_RELATIONSHIP_RULES:
                    rel_type = RESOURCE_RELATIONSHIP_RULES[pair]
                    self._add_relationship(source_id, target_id, rel_type)
                    continue

                # Check reverse direction
                reverse_pair = (target_type, source_type)
                if reverse_pair in RESOURCE_RELATIONSHIP_RULES:
                    rel_type = RESOURCE_RELATIONSHIP_RULES[reverse_pair]
                    self._add_relationship(target_id, source_id, rel_type)
                    continue

                # Attribute-based inference
                inferred = self._infer_from_attributes(source, target)
                if inferred:
                    self._add_relationship(source_id, target_id, inferred)

    def _infer_from_attributes(
        self,
        source: CanonicalResource,
        target: CanonicalResource
    ) -> RelationshipType | None:
        """Infer relationship from attribute analysis."""
        source_type = source.resource_type
        target_type = target.resource_type

        # Same security domain suggests peer relationship
        source_domain = source_type.split(".")[0]
        target_domain = target_type.split(".")[0]
        if source_domain == target_domain and source_domain in ("auth", "network", "os"):
            return RelationshipType.PEER_OF

        # K8s RBAC specific: binding links subjects to roles
        if source_type.startswith("auth.rbac.role_binding"):
            if "bound_subjects" in source.attributes:
                for subject in source.attributes.get("bound_subjects", []):
                    if target_type == "k8s.service_account" and target.name in subject:
                        return RelationshipType.GRANTS_ACCESS_TO
                    if target_type.startswith("auth.rbac.role") and target.name in source.attributes.get("role_ref_name", ""):
                        return RelationshipType.BOUND_TO

        return None

    def _add_relationship(
        self,
        source_id: str,
        target_id: str,
        rel_type: RelationshipType,
        weight: int = 5
    ):
        """Add a relationship to the graph."""
        rel = Relationship(
            type=rel_type,
            source_id=source_id,
            target_id=target_id,
            direction="outbound",
            weight=weight,
        )
        self.relationships.append(rel)

        # Also add inbound relationship to target
        inbound = Relationship(
            type=rel_type,
            source_id=source_id,
            target_id=target_id,
            direction="inbound",
            weight=weight,
        )
        self.relationships.append(inbound)

    def _populate_node_relationships(self):
        """Populate each node's relationships list."""
        for rel in self.relationships:
            if rel["direction"] == "outbound":
                if rel["target_id"] in self.nodes:
                    self.nodes[rel["target_id"]]["relationships"].append(rel)

    def find_relationships(
        self,
        rel_type: RelationshipType | None = None,
        resource_id: str | None = None
    ) -> list[Relationship]:
        """Find relationships by type and/or source resource."""
        results = []
        for rel in self.relationships:
            if rel_type and rel["type"] != rel_type:
                continue
            if resource_id and rel["source_id"] != resource_id:
                continue
            if rel["direction"] != "outbound":
                continue
            results.append(rel)
        return results

    def find_path(
        self,
        source_id: str,
        target_id: str
    ) -> list[list[str]] | None:
        """Find all paths from source to target (BFS).

        Returns list of paths, each path is a list of resource IDs.
        Returns None if no path exists.
        Returns empty list if source == target (no traversal needed).
        """
        if source_id == target_id:
            return []

        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        # Build adjacency list
        adj: dict[str, list[str]] = {rid: [] for rid in self.nodes}
        for rel in self.relationships:
            if rel["direction"] == "outbound":
                adj[rel["source_id"]].append(rel["target_id"])

        # BFS
        paths: list[list[str]] = []
        queue: list[tuple[str, list[str]]] = [(source_id, [source_id])]

        while queue:
            current, path = queue.pop(0)

            if current == target_id:
                paths.append(path)

            for neighbor in adj.get(current, []):
                if neighbor not in path:  # Avoid cycles
                    queue.append((neighbor, path + [neighbor]))

        return paths if paths else None

    def get_connected_resources(
        self,
        resource_id: str,
        rel_type: RelationshipType | None = None,
        max_depth: int = 2
    ) -> set[str]:
        """Get all resources connected to given resource within max_depth hops."""
        if resource_id not in self.nodes:
            return set()

        visited: set[str] = {resource_id}
        current_level: set[str] = {resource_id}

        for _ in range(max_depth):
            next_level: set[str] = set()
            for rel in self.relationships:
                if rel["direction"] != "outbound":
                    continue
                if rel_type and rel["type"] != rel_type:
                    continue
                if rel["source_id"] in current_level and rel["target_id"] not in visited:
                    next_level.add(rel["target_id"])
                    visited.add(rel["target_id"])
            current_level = next_level
            if not current_level:
                break

        visited.discard(resource_id)
        return visited

    def to_dict(self) -> dict:
        """Export graph as dictionary for serialization."""
        return {
            "nodes": [
                {
                    "resource_id": node["resource_id"],
                    "resource_type": node["resource_type"],
                    "name": node["name"],
                    "relationship_count": len(node["relationships"]),
                }
                for node in self.nodes.values()
            ],
            "relationship_count": len([r for r in self.relationships if r["direction"] == "outbound"]),
            "relationship_types": list(set(r["type"] for r in self.relationships if r["direction"] == "outbound")),
        }

    @property
    def stats(self) -> dict:
        """Graph statistics."""
        outbound_rels = [r for r in self.relationships if r["direction"] == "outbound"]
        return {
            "total_resources": len(self.nodes),
            "total_relationships": len(outbound_rels),
            "resource_types": len(set(n["resource_type"] for n in self.nodes.values())),
            "relationship_types": list(set(r["type"] for r in outbound_rels)),
        }
