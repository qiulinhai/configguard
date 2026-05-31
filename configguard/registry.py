"""SignalDefinition Registry - Declarative Signal Metadata Store.

v0.2.1: Replaces hardcoded SIGNAL_CONTEXT_CLUSTERS with typed declarations.

This module implements the Binding Layer of ConfigGuard's three-layer IR model:
    Layer 1 (Binding): context_template - how signal extracts data from context
    Layer 2 (Aggregation): aggregation_strategy - singleton vs per_instance
    Layer 3 (Reasoning): security_domain - management_plane, observability, etc.

The registry provides:
- Static validation of context_template placeholders (prevents injection attacks)
- Category index for O(1) rule matching
- Singleton enforcement for global signals
"""
import re
from dataclasses import dataclass, field
from typing import ClassVar, Optional

# Strict whitelist of valid placeholder variables
VALID_PLACEHOLDERS = {"{context}", "{interface}", "{vrf}"}

# Maximum template length to prevent string bomb attacks
MAX_TEMPLATE_LENGTH = 64


class SignalDefinitionError(ValueError):
    """Raised when signal definition validation fails."""
    pass


@dataclass
class SignalDefinition:
    """Declarative metadata for a signal type.

    This is the core type definition in ConfigGuard's semantic model.
    All signals must be registered before use.

    Attributes:
        signal_type: Unique identifier (e.g., "snmp_version", "transport_input")
        category: Execution dimension category (e.g., "snmp", "vty", "interface")
        security_domain: Reasoning dimension - "management_plane", "observability", etc.
        context_template: Binding template - "singleton" or "{placeholder}" combination
        aggregation_strategy: "singleton" or "per_instance"
        scope: Optional scope hint - "global", "line", "interface"
    """
    signal_type: str
    category: str
    security_domain: str
    context_template: str
    aggregation_strategy: str
    scope: str | None = None

    # Standard aggregation strategies
    STRATEGY_SINGLETON = "singleton"
    STRATEGY_PER_INSTANCE = "per_instance"

    # Standard security domains
    DOMAIN_MANAGEMENT_PLANE = "management_plane"
    DOMAIN_DATA_PLANE = "data_plane"
    DOMAIN_OBSERVABILITY = "observability"
    DOMAIN_COMPLIANCE = "compliance"
    DOMAIN_ACCESS_CONTROL = "access_control"

    def validate(self) -> None:
        """Static validation - raises SignalDefinitionError on failure.

        Validates:
        1. context_template uses only allowed placeholders
        2. Template length is within bounds
        3. Singleton signals have static (non-dynamic) templates
        4. aggregation_strategy is valid
        """
        # Validate aggregation_strategy
        valid_strategies = {self.STRATEGY_SINGLETON, self.STRATEGY_PER_INSTANCE}
        if self.aggregation_strategy not in valid_strategies:
            raise SignalDefinitionError(
                f"Signal '{self.signal_type}' has invalid aggregation_strategy "
                f"'{self.aggregation_strategy}'. Must be one of: {valid_strategies}"
            )

        # Validate template
        self._validate_template()

    def _validate_template(self) -> None:
        """Validate context_template format and placeholders."""
        template = self.context_template

        # Singleton must have static template
        if self.aggregation_strategy == self.STRATEGY_SINGLETON:
            if "{" in template:
                raise SignalDefinitionError(
                    f"Singleton signal '{self.signal_type}' cannot have dynamic "
                    f"template '{template}'. Use 'singleton' as context_template."
                )
            return

        # Dynamic templates must have valid placeholders
        if template == "singleton":
            raise SignalDefinitionError(
                f"Signal '{self.signal_type}' with per_instance strategy "
                f"must have a dynamic template, not 'singleton'."
            )

        # Check template length
        if len(template) > MAX_TEMPLATE_LENGTH:
            raise SignalDefinitionError(
                f"Template for '{self.signal_type}' is too long "
                f"({len(template)} > {MAX_TEMPLATE_LENGTH} chars)."
            )

        # Extract and validate placeholders
        placeholders = re.findall(r"\{.*?\}", template)
        if not placeholders:
            raise SignalDefinitionError(
                f"Signal '{self.signal_type}' template '{template}' must be "
                f"'singleton' or contain a valid placeholder like {{context}}."
            )

        for ph in placeholders:
            if ph not in VALID_PLACEHOLDERS:
                raise SignalDefinitionError(
                    f"Invalid placeholder '{ph}' in signal '{self.signal_type}'. "
                    f"Allowed: {VALID_PLACEHOLDERS}"
                )


class SignalRegistry:
    """Singleton registry for signal definitions.

    Provides:
    - Centralized registration of signal types
    - Static validation at registration time
    - Category index for fast lookup
    - Guard rail against duplicate registrations
    """

    _instance: ClassVar[Optional["SignalRegistry"]] = None

    def __init__(self):
        self._definitions: dict[str, SignalDefinition] = {}
        self._category_index: dict[str, list[str]] = {}  # category → [signal_types]

    @classmethod
    def get_instance(cls) -> 'SignalRegistry':
        """Get the singleton registry instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton - for testing only."""
        cls._instance = None

    def register(self, definition: SignalDefinition) -> None:
        """Register a signal definition with static validation.

        Args:
            definition: SignalDefinition to register

        Raises:
            SignalDefinitionError: If validation fails
            ValueError: If signal_type is already registered
        """
        # Validate before registration
        definition.validate()

        # Check for duplicates
        if definition.signal_type in self._definitions:
            raise ValueError(
                f"Duplicate signal type registration: '{definition.signal_type}'"
            )

        # Store definition
        self._definitions[definition.signal_type] = definition

        # Rebuild category index
        self._rebuild_category_index()

    def _rebuild_category_index(self) -> None:
        """Rebuild category → signal_types index."""
        self._category_index.clear()
        for sig_type, defn in self._definitions.items():
            category = defn.category  # Use direct category field
            if category not in self._category_index:
                self._category_index[category] = []
            self._category_index[category].append(sig_type)

    def _get_category_from_template(self, template: str) -> str:
        """Derive category from context_template.

        Examples:
            "snmp_security" → "snmp"
            "interface_{context}" → "interface"
            "{context}" → "global"
        """
        if template == "singleton":
            return "global"

        # Extract base name before first underscore or placeholder
        if "{" in template:
            base = template.split("{")[0].rstrip("_")
            return base if base else "global"

        return template.split("_")[0]

    def get(self, signal_type: str) -> SignalDefinition | None:
        """Get signal definition by type."""
        return self._definitions.get(signal_type)

    def get_by_category(self, category: str) -> list[SignalDefinition]:
        """Get all signal definitions for a category."""
        sig_types = self._category_index.get(category, [])
        return [self._definitions[st] for st in sig_types]

    def get_all_categories(self) -> list[str]:
        """Get all registered categories."""
        return list(self._category_index.keys())

    def get_all_signal_types(self) -> list[str]:
        """Get all registered signal types."""
        return list(self._definitions.keys())

    def is_registered(self, signal_type: str) -> bool:
        """Check if a signal type is registered."""
        return signal_type in self._definitions


def create_signal_registry_with_defaults() -> SignalRegistry:
    """Create a registry pre-populated with standard ConfigGuard signals.

    This provides backward compatibility with v0.2 signal types.
    """
    registry = SignalRegistry.get_instance()
    reset_instance = registry._definitions  # Clear if re-running

    # Standard signal definitions
    standard_signals = [
        # SNMP signals
        SignalDefinition(
            signal_type="snmp_version",
            category="snmp",
            security_domain="management_plane",
            context_template="singleton",
            aggregation_strategy="singleton",
            scope="global",
        ),
        SignalDefinition(
            signal_type="snmp_community",
            category="snmp",
            security_domain="management_plane",
            context_template="singleton",
            aggregation_strategy="singleton",
            scope="global",
        ),
        # VTY signals - per instance
        SignalDefinition(
            signal_type="transport_input",
            category="vty",
            security_domain="management_plane",
            context_template="{context}",
            aggregation_strategy="per_instance",
            scope="line",
        ),
        SignalDefinition(
            signal_type="auth_method",
            category="vty",
            security_domain="access_control",
            context_template="{context}",
            aggregation_strategy="per_instance",
            scope="line",
        ),
        # Interface signals - per instance
        SignalDefinition(
            signal_type="interface_state",
            category="interface",
            security_domain="data_plane",
            context_template="interface_{context}",
            aggregation_strategy="per_instance",
            scope="interface",
        ),
        SignalDefinition(
            signal_type="interface_description",
            category="interface",
            security_domain="observability",
            context_template="interface_{context}",
            aggregation_strategy="per_instance",
            scope="interface",
        ),
        # Global signals - singleton
        SignalDefinition(
            signal_type="aaa_enabled",
            category="aaa",
            security_domain="access_control",
            context_template="singleton",
            aggregation_strategy="singleton",
            scope="global",
        ),
        SignalDefinition(
            signal_type="http_server",
            category="http",
            security_domain="management_plane",
            context_template="singleton",
            aggregation_strategy="singleton",
            scope="global",
        ),
        SignalDefinition(
            signal_type="syslog_host",
            category="syslog",
            security_domain="observability",
            context_template="singleton",
            aggregation_strategy="singleton",
            scope="global",
        ),
        SignalDefinition(
            signal_type="ntp_server",
            category="ntp",
            security_domain="observability",
            context_template="singleton",
            aggregation_strategy="singleton",
            scope="global",
        ),
    ]

    # Register all standard signals
    for sig in standard_signals:
        try:
            registry.register(sig)
        except ValueError:
            # Already registered, skip
            pass

    return registry