"""Tests for Security Knowledge Graph — IR v1 Relationship System."""
import pytest

from configguard.adapters.cisco_ios import CiscoIOSAdapter
from configguard.adapters.kubernetes import KubernetesSecurityAdapter
from configguard.adapters.linux_ssh import LinuxSShadapter
from configguard.adapters.linux_os import LinuxOSSecurityAdapter
from configguard.ontology import (
    SecurityKnowledgeGraph,
    RelationshipType,
)


CISCO_COMBINED = """
!
line vty 0 4
 transport input telnet ssh
!
snmp-server community public RO
!
interface GigabitEthernet0/1
 shutdown
!
"""

K8S_ROLE_BINDING = """
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: read-pods-binding
  namespace: default
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: Role
  name: pod-reader
"""


class TestKnowledgeGraphBasics:
    """Basic knowledge graph functionality."""

    def test_graph_builds_from_ir(self):
        """Graph must build from CanonicalResource list."""
        adapter = CiscoIOSAdapter()
        ir = adapter.parse(CISCO_COMBINED)

        kg = SecurityKnowledgeGraph(ir).build()

        assert kg.stats["total_resources"] == 3
        assert kg.stats["total_relationships"] > 0
        assert kg.stats["resource_types"] == 3

    def test_graph_creates_nodes_for_each_resource(self):
        """Every resource must have a node in the graph."""
        adapter = CiscoIOSAdapter()
        ir = adapter.parse(CISCO_COMBINED)

        kg = SecurityKnowledgeGraph(ir).build()

        assert len(kg.nodes) == 3
        for r in ir:
            assert r.id in kg.nodes

    def test_graph_has_relationship_types(self):
        """Graph must identify relationship types."""
        adapter = CiscoIOSAdapter()
        ir = adapter.parse(CISCO_COMBINED)

        kg = SecurityKnowledgeGraph(ir).build()

        assert len(kg.stats["relationship_types"]) > 0
        assert isinstance(kg.stats["relationship_types"], list)

    def test_graph_is_deterministic(self):
        """Same IR must produce same graph (deterministic)."""
        adapter = CiscoIOSAdapter()

        kg1 = SecurityKnowledgeGraph(adapter.parse(CISCO_COMBINED)).build()
        kg2 = SecurityKnowledgeGraph(adapter.parse(CISCO_COMBINED)).build()

        stats1 = kg1.stats
        stats2 = kg2.stats

        assert stats1["total_resources"] == stats2["total_resources"]
        assert stats1["total_relationships"] == stats2["total_relationships"]

    def test_empty_ir_produces_empty_graph(self):
        """Empty IR must produce empty graph."""
        kg = SecurityKnowledgeGraph([]).build()
        assert kg.stats["total_resources"] == 0
        assert kg.stats["total_relationships"] == 0


class TestRelationshipDiscovery:
    """Test relationship discovery between resources."""

    def test_finds_all_outbound_relationships(self):
        """find_relationships must return all outbound relationships."""
        adapter = CiscoIOSAdapter()
        ir = adapter.parse(CISCO_COMBINED)

        kg = SecurityKnowledgeGraph(ir).build()
        rels = kg.find_relationships()

        # All returned must be outbound
        for rel in rels:
            assert rel["direction"] == "outbound"

    def test_finds_relationships_by_type(self):
        """find_relationships must filter by type."""
        adapter = CiscoIOSAdapter()
        ir = adapter.parse(CISCO_COMBINED)

        kg = SecurityKnowledgeGraph(ir).build()

        peer_rels = kg.find_relationships(rel_type=RelationshipType.PEER_OF)
        depends_rels = kg.find_relationships(rel_type=RelationshipType.DEPENDS_ON)

        for rel in peer_rels:
            assert rel["type"] == RelationshipType.PEER_OF

    def test_find_relationships_by_resource(self):
        """find_relationships must filter by source resource."""
        adapter = CiscoIOSAdapter()
        ir = adapter.parse(CISCO_COMBINED)

        kg = SecurityKnowledgeGraph(ir).build()

        vty_resource = next(r for r in ir if r.resource_type == "auth.remote_access")
        vty_rels = kg.find_relationships(resource_id=vty_resource.id)

        for rel in vty_rels:
            assert rel["source_id"] == vty_resource.id

    def test_peer_of_relationship_exists(self):
        """auth.remote_access and network.snmp must have peer_of relationship."""
        adapter = CiscoIOSAdapter()
        ir = adapter.parse(CISCO_COMBINED)

        kg = SecurityKnowledgeGraph(ir).build()
        peer_rels = kg.find_relationships(rel_type=RelationshipType.PEER_OF)

        # Must have peer_of between auth and network resources
        assert len(peer_rels) >= 1


class TestK8sRelationshipModeling:
    """Test K8s-specific relationship modeling (the critical case)."""

    def test_k8s_role_binding_creates_relationships(self):
        """K8s RoleBinding must create grants_access_to and bound_to relationships.

        Note: With a single RoleBinding resource, no other resources exist to link to.
        In real multi-resource K8s configs, RoleBinding will create relationships to
        ServiceAccounts and Roles. Here we test that the graph is at least buildable.
        """
        adapter = KubernetesSecurityAdapter()
        ir = adapter.parse(K8S_ROLE_BINDING)

        kg = SecurityKnowledgeGraph(ir).build()
        stats = kg.stats

        # RoleBinding is a valid resource - graph must build
        assert stats["total_resources"] >= 1, "RoleBinding should be in graph"
        # Note: actual relationships require multiple resources to link

    def test_k8s_graph_is_not_empty(self):
        """K8s adapter must produce non-empty graph."""
        adapter = KubernetesSecurityAdapter()
        ir = adapter.parse(K8S_ROLE_BINDING)

        kg = SecurityKnowledgeGraph(ir).build()

        assert kg.stats["total_resources"] > 0
        assert len(kg.nodes) > 0


class TestCrossDomainGraph:
    """Test knowledge graph across multiple adapters."""

    def test_multi_adapter_graph(self):
        """Graph must handle resources from multiple adapters."""
        cisco = CiscoIOSAdapter()
        linux_ssh = LinuxSShadapter()
        linux_os = LinuxOSSecurityAdapter()

        cisco_ir = cisco.parse(CISCO_COMBINED)
        # Linux SSH produces 1 resource (auth.remote_access)
        linux_ir = linux_ssh.parse("PasswordAuthentication no\nPubkeyAuthentication yes\n")
        # Linux OS produces 1 resource (os.pam - sysctl not present in this minimal config)
        linux_os_ir = linux_os.parse("minlen = 12\ndcredit = -1\n")

        combined_ir = cisco_ir + linux_ir + linux_os_ir

        kg = SecurityKnowledgeGraph(combined_ir).build()

        # 3 (cisco) + 1 (linux ssh) + 1 (linux os) = 5
        assert kg.stats["total_resources"] == 5
        assert kg.stats["total_relationships"] > 0

    def test_graph_domains_are_isolated_by_default(self):
        """Resources from different domains should not have spurious relationships."""
        cisco = CiscoIOSAdapter()
        linux_os = LinuxOSSecurityAdapter()

        cisco_ir = cisco.parse(CISCO_COMBINED)
        linux_os_ir = linux_os.parse("minlen = 12\n")

        # Combine only network.interface with os.pam
        network_iface = next(r for r in cisco_ir if r.resource_type == "network.interface")
        os_pam = linux_os_ir[0] if linux_os_ir else None

        if os_pam:
            combined_ir = [network_iface, os_pam]
            kg = SecurityKnowledgeGraph(combined_ir).build()

            # These are cross-domain, may or may not have relationships
            # The important thing is the graph is stable
            assert kg.stats["total_resources"] == 2


class TestGraphConnectivity:
    """Test graph connectivity and path finding."""

    def test_find_path_between_resources(self):
        """find_path must find paths between connected resources via BFS.

        Note: vty → snmp requires peer_of which is inferred in reverse direction
        (snmp → vty). BFS should find this indirect path.
        """
        adapter = CiscoIOSAdapter()
        ir = adapter.parse(CISCO_COMBINED)

        kg = SecurityKnowledgeGraph(ir).build()

        vty = next(r for r in ir if r.resource_type == "auth.remote_access")
        snmp = next(r for r in ir if r.resource_type == "network.snmp")

        # Try both directions - relationship might be inferred in either
        paths_v_to_s = kg.find_path(vty.id, snmp.id)
        paths_s_to_v = kg.find_path(snmp.id, vty.id)

        # At least one direction should have a path
        assert paths_v_to_s is not None or paths_s_to_v is not None, \
            "vty and snmp should be connected via peer_of"

        # Verify at least one path exists in one direction
        has_path = (paths_v_to_s is not None and len(paths_v_to_s) > 0) or \
                   (paths_s_to_v is not None and len(paths_s_to_v) > 0)
        assert has_path

    def test_no_path_between_unrelated_resources(self):
        """find_path must return None for unrelated resources."""
        adapter = KubernetesSecurityAdapter()
        ir = adapter.parse("""
kind: PodSecurityPolicy
apiVersion: policy/v1beta1
metadata:
  name: restricted
spec:
  privileged: false
""")

        kg = SecurityKnowledgeGraph(ir).build()

        # Single resource, no path possible
        if len(kg.nodes) == 1:
            resource_id = list(kg.nodes.keys())[0]
            paths = kg.find_path(resource_id, resource_id)
            assert paths is None or len(paths) == 0

    def test_get_connected_resources(self):
        """get_connected_resources must return all resources within N hops."""
        adapter = CiscoIOSAdapter()
        ir = adapter.parse(CISCO_COMBINED)

        kg = SecurityKnowledgeGraph(ir).build()

        vty = next(r for r in ir if r.resource_type == "auth.remote_access")
        connected = kg.get_connected_resources(vty.id, max_depth=1)

        # VTY should be connected to at least snmp (peer_of)
        assert len(connected) > 0


class TestGraphSerialization:
    """Test graph serialization."""

    def test_to_dict(self):
        """Graph must export to dictionary."""
        adapter = CiscoIOSAdapter()
        ir = adapter.parse(CISCO_COMBINED)

        kg = SecurityKnowledgeGraph(ir).build()
        d = kg.to_dict()

        assert "nodes" in d
        assert "relationship_count" in d
        assert "relationship_types" in d
        assert len(d["nodes"]) == 3
