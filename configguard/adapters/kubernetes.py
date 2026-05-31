"""Kubernetes Security → Canonical IR Adapter — v0.3.

Covers Kubernetes RBAC and security configuration:
- Role / ClusterRole
- RoleBinding / ClusterRoleBinding
- ServiceAccount
- PodSecurityPolicy

This adapter validates that IR v1 can model cloud-native security semantics,
not just traditional infrastructure configs.

Purpose:
    Prove IR v1 can model:
    - Multi-resource relationships (RBAC bindings)
    - Policy inheritance (PSP)
    - Network segmentation (NetworkPolicy)
    - Secret management

    This is the CRITICAL ontology stress test:
    Kubernetes RBAC is fundamentally different from Cisco IOS / Linux SSH
    because security decisions involve RELATIONSHIPS between resources,
    not just attributes of individual resources.
"""
import re
import hashlib
import json
from configguard.adapters.base import VendorAdapter
from configguard.models import CanonicalResource


def compute_resource_id(resource_type: str, name: str, scope: str, extra: str = "") -> str:
    content = f"{resource_type}:{name}:{scope}:{extra}"
    return hashlib.sha256(content.encode()).hexdigest()[:12]


K8S_RESOURCE_TYPES = {
    "rbac.role": {
        "description": "Kubernetes RBAC Role",
        "scope": "resource",
        "api_version": "rbac.authorization.k8s.io/v1",
    },
    "rbac.cluster_role": {
        "description": "Kubernetes RBAC ClusterRole",
        "scope": "global",
        "api_version": "rbac.authorization.k8s.io/v1",
    },
    "rbac.role_binding": {
        "description": "Kubernetes RBAC RoleBinding",
        "scope": "resource",
    },
    "k8s.service_account": {
        "description": "Kubernetes ServiceAccount",
        "scope": "resource",
    },
    "k8s.pod_security_policy": {
        "description": "Kubernetes Pod Security Policy",
        "scope": "global",
    },
    "k8s.network_policy": {
        "description": "Kubernetes Network Policy",
        "scope": "resource",
    },
}


class KubernetesSecurityAdapter(VendorAdapter):
    """Kubernetes security configuration → Canonical IR adapter.

    Handles:
    - RBAC (Role, ClusterRole, RoleBinding, ClusterRoleBinding)
    - Pod Security Policy
    - Network Policy
    - Service Accounts

    Key challenge: K8s security is RELATIONSHIP-based, not attribute-based.
    A RoleBinding links a subject (ServiceAccount/User/Group) to a role.
    IR must capture these relationships explicitly.
    """

    vendor_id = "kubernetes"

    @property
    def mapping_spec(self) -> dict:
        return K8S_RESOURCE_TYPES

    def parse(self, raw_config: str, metadata: dict | None = None) -> list[CanonicalResource]:
        """Parse Kubernetes YAML into Canonical IR.

        Input formats supported:
        - Single YAML document per parse call
        - Multiple YAML documents (separated by ---)
        """
        # Split multi-document YAML
        docs = []
        current_doc = []
        for line in raw_config.splitlines():
            if line.strip() == "---":
                if current_doc:
                    docs.append("\n".join(current_doc))
                    current_doc = []
            else:
                current_doc.append(line)
        if current_doc:
            docs.append("\n".join(current_doc))

        resources = []
        for doc in docs:
            if not doc.strip():
                continue
            parsed = self._parse_yaml_doc(doc)
            if parsed:
                resources.extend(parsed)

        return self._deduplicate(resources)

    def _parse_yaml_doc(self, doc: str) -> list[CanonicalResource]:
        """Parse a single YAML document into IR resources."""
        try:
            import yaml
            data = yaml.safe_load(doc)
        except ImportError:
            # Fallback: simple line-based parsing for Role/ClusterRole
            data = self._simple_parse(doc)

        if not data:
            return []

        kind = data.get("kind", "")
        metadata = data.get("metadata", {})
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", None)
        resources = []

        # RBAC Roles
        if kind == "Role":
            rules = data.get("rules", [])
            verbs = self._extract_verbs(rules)
            resources.append(self._build_rbac_role(name, rules, namespace))
        elif kind == "ClusterRole":
            rules = data.get("rules", [])
            resources.append(self._build_cluster_role(name, rules))
        elif kind == "RoleBinding":
            subjects = data.get("subjects", [])
            role_ref = data.get("roleRef", {})
            resources.append(self._build_role_binding(name, subjects, role_ref, namespace))
        elif kind == "ClusterRoleBinding":
            subjects = data.get("subjects", [])
            role_ref = data.get("roleRef", {})
            resources.append(self._build_cluster_role_binding(name, subjects, role_ref))
        elif kind == "ServiceAccount":
            resources.append(self._build_service_account(name, namespace, data))
        elif kind == "PodSecurityPolicy":
            resources.append(self._build_psp(name, data))
        elif kind == "NetworkPolicy":
            resources.append(self._build_network_policy(name, namespace, data))

        return resources

    def _simple_parse(self, doc: str) -> dict | None:
        """Fallback simple parser when YAML lib unavailable."""
        lines = doc.splitlines()
        result = {}
        current_key = None

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Simple key: value parsing
            if ":" in stripped and not stripped.startswith("-"):
                key, value = stripped.split(":", 1)
                current_key = key.strip()
                result[current_key] = value.strip() if value.strip() else {}
            elif stripped.startswith("- kind:"):
                result["kind"] = stripped.split("kind:")[1].strip()
            elif current_key and stripped.startswith("-"):
                # List item
                if isinstance(result.get(current_key), list):
                    pass  # handled elsewhere
            elif current_key and result.get(current_key) == {}:
                result[current_key] = stripped

        if not result.get("kind"):
            return None
        return result

    def _extract_verbs(self, rules: list) -> list[str]:
        """Extract all verbs from RBAC rules."""
        verbs = set()
        for rule in rules:
            rule_verbs = rule.get("verbs", [])
            if isinstance(rule_verbs, list):
                verbs.update(rule_verbs)
            elif rule_verbs == "*":
                verbs.add("*")
        return sorted(list(verbs))

    def _build_rbac_role(self, name: str, rules: list, namespace: str | None) -> CanonicalResource:
        """Build auth.rbac.resource from Role."""
        verbs = self._extract_verbs(rules)
        resources = self._extract_resource_names(rules)
        namespaces = list(set(r.get("namespace") or "default" for r in rules if isinstance(r, dict)))

        rid = compute_resource_id("auth.rbac", f"role:{name}", "resource", namespace or "default")

        attributes = {
            "role_name": name,
            "namespace": namespace or "default",
            "verbs": verbs,
            "resource_types": resources,
            "wildcard": "*" in verbs,
        }

        return CanonicalResource(
            id=rid,
            resource_type="auth.rbac.role",
            name=f"role:{name}",
            attributes=attributes,
            scope="resource",
            source={
                "vendor": "kubernetes",
                "kind": "Role",
                "namespace": namespace,
                "api_version": "rbac.authorization.k8s.io/v1",
            },
            relationships=[],
            tags=["cloud-native", "rbac", "authorization"],
        )

    def _build_cluster_role(self, name: str, rules: list) -> CanonicalResource:
        """Build auth.rbac.cluster_role from ClusterRole."""
        verbs = self._extract_verbs(rules)
        resources = self._extract_resource_names(rules)

        rid = compute_resource_id("auth.rbac", f"cluster_role:{name}", "global", "cluster")

        attributes = {
            "role_name": name,
            "cluster_scoped": True,
            "verbs": verbs,
            "resource_types": resources,
            "wildcard": "*" in verbs,
        }

        return CanonicalResource(
            id=rid,
            resource_type="auth.rbac.cluster_role",
            name=f"cluster_role:{name}",
            attributes=attributes,
            scope="global",
            source={
                "vendor": "kubernetes",
                "kind": "ClusterRole",
                "api_version": "rbac.authorization.k8s.io/v1",
            },
            relationships=[],
            tags=["cloud-native", "rbac", "authorization", "cluster-scoped"],
        )

    def _build_role_binding(self, name: str, subjects: list, role_ref: dict, namespace: str | None) -> CanonicalResource:
        """Build auth.rbac.role_binding from RoleBinding.

        RoleBinding creates a RELATIONSHIP between subjects and a role.
        This is captured via the 'bound_subjects' and 'role_ref' attributes.
        """
        subject_ids = []
        subject_kinds = []
        for s in subjects:
            kind = s.get("kind", "Unknown")
            name = s.get("name", "")
            ns = s.get("namespace", namespace)
            subject_kinds.append(kind)
            subject_ids.append(f"{kind}:{name}:{ns}")

        role_name = role_ref.get("name", "unknown")
        role_kind = role_ref.get("kind", "Role")

        rid = compute_resource_id("auth.rbac", f"binding:{name}", "resource", namespace or "default")

        attributes = {
            "binding_name": name,
            "namespace": namespace or "default",
            "role_ref_kind": role_kind,
            "role_ref_name": role_name,
            "subject_kinds": subject_kinds,
            "bound_subjects": subject_ids,
            "subject_count": len(subjects),
        }

        return CanonicalResource(
            id=rid,
            resource_type="auth.rbac.role_binding",
            name=f"binding:{name}",
            attributes=attributes,
            scope="resource",
            source={
                "vendor": "kubernetes",
                "kind": "RoleBinding",
                "namespace": namespace,
                "api_version": "rbac.authorization.k8s.io/v1",
            },
            relationships=[],
            tags=["cloud-native", "rbac", "authorization", "relationship"],
        )

    def _build_cluster_role_binding(self, name: str, subjects: list, role_ref: dict) -> CanonicalResource:
        """Build auth.rbac.cluster_role_binding from ClusterRoleBinding."""
        subject_ids = []
        subject_kinds = []
        for s in subjects:
            kind = s.get("kind", "Unknown")
            name = s.get("name", "")
            subject_kinds.append(kind)
            subject_ids.append(f"{kind}:{name}")

        role_name = role_ref.get("name", "unknown")

        rid = compute_resource_id("auth.rbac", f"cluster_binding:{name}", "global", "cluster")

        attributes = {
            "binding_name": name,
            "cluster_scoped": True,
            "role_ref_kind": role_ref.get("kind", "ClusterRole"),
            "role_ref_name": role_name,
            "subject_kinds": subject_kinds,
            "bound_subjects": subject_ids,
            "subject_count": len(subjects),
        }

        return CanonicalResource(
            id=rid,
            resource_type="auth.rbac.cluster_role_binding",
            name=f"cluster_binding:{name}",
            attributes=attributes,
            scope="global",
            source={
                "vendor": "kubernetes",
                "kind": "ClusterRoleBinding",
                "api_version": "rbac.authorization.k8s.io/v1",
            },
            relationships=[],
            tags=["cloud-native", "rbac", "authorization", "relationship", "cluster-scoped"],
        )

    def _build_service_account(self, name: str, namespace: str | None, data: dict) -> CanonicalResource:
        """Build k8s.service_account resource."""
        rid = compute_resource_id("k8s.service_account", f"sa:{name}", "resource", namespace or "default")

        return CanonicalResource(
            id=rid,
            resource_type="k8s.service_account",
            name=f"sa:{name}",
            attributes={
                "name": name,
                "namespace": namespace or "default",
                "automount_token": data.get("automountServiceAccountToken"),
            },
            scope="resource",
            source={
                "vendor": "kubernetes",
                "kind": "ServiceAccount",
                "namespace": namespace,
            },
            relationships=[],
            tags=["cloud-native", "service-account"],
        )

    def _build_psp(self, name: str, data: dict) -> CanonicalResource:
        """Build k8s.pod_security_policy resource."""
        spec = data.get("spec", {})

        rid = compute_resource_id("k8s.psp", f"psp:{name}", "global", "cluster")

        return CanonicalResource(
            id=rid,
            resource_type="k8s.pod_security_policy",
            name=f"psp:{name}",
            attributes={
                "policy_name": name,
                "privileged": spec.get("privileged", False),
                "allow_privilege_escalation": spec.get("allowPrivilegeEscalation", False),
                "run_as_user": spec.get("runAsUser", {}),
                "se_linux": spec.get("seLinux", {}),
                "volumes": spec.get("volumes", []),
                "host_network": spec.get("hostNetwork", False),
                "host_ports": spec.get("hostPorts", []),
            },
            scope="global",
            source={
                "vendor": "kubernetes",
                "kind": "PodSecurityPolicy",
                "api_version": "policy/v1beta1",
            },
            relationships=[],
            tags=["cloud-native", "pod-security", "admission-control"],
        )

    def _build_network_policy(self, name: str, namespace: str | None, data: dict) -> CanonicalResource:
        """Build k8s.network_policy resource."""
        spec = data.get("spec", {})

        rid = compute_resource_id("k8s.network_policy", f"netpol:{name}", "resource", namespace or "default")

        return CanonicalResource(
            id=rid,
            resource_type="k8s.network_policy",
            name=f"netpol:{name}",
            attributes={
                "policy_name": name,
                "namespace": namespace or "default",
                "pod_selector": str(spec.get("podSelector", {})),
                "policy_types": spec.get("policyTypes", []),
                "ingress_rules": len(spec.get("ingress", [])),
                "egress_rules": len(spec.get("egress", [])),
            },
            scope="resource",
            source={
                "vendor": "kubernetes",
                "kind": "NetworkPolicy",
                "namespace": namespace,
            },
            relationships=[],
            tags=["cloud-native", "network-policy", "segmentation"],
        )

    def _extract_resource_names(self, rules: list) -> list[str]:
        """Extract all resource names from RBAC rules."""
        resources = set()
        for rule in rules:
            rule_resources = rule.get("resources", [])
            if isinstance(rule_resources, list):
                resources.update(rule_resources)
        return sorted(list(resources))

    def _deduplicate(self, resources: list[CanonicalResource]) -> list[CanonicalResource]:
        seen = set()
        unique = []
        for r in resources:
            if r.id not in seen:
                seen.add(r.id)
                unique.append(r)
        return unique
