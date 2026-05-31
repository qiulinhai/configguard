"""Unit tests for SignalDefinition Registry.

Tests cover:
- SignalDefinition validation logic
- SignalRegistry registration and lookup
- Placeholder whitelist enforcement
- Singleton vs per_instance rules
- Category index building
"""
import pytest
from configguard.registry import (
    SignalDefinition,
    SignalRegistry,
    SignalDefinitionError,
    VALID_PLACEHOLDERS,
    MAX_TEMPLATE_LENGTH,
    create_signal_registry_with_defaults,
)


class TestSignalDefinitionValidation:
    """Tests for SignalDefinition.validate()."""

    def test_valid_singleton_signal(self):
        """Singleton signals must have static (non-dynamic) templates."""
        sig = SignalDefinition(
            signal_type="snmp_version",
            category="snmp",
            context_template="singleton",
            aggregation_strategy="singleton",
            security_domain="management_plane",
        )
        sig.validate()  # Should not raise

    def test_valid_per_instance_with_context_placeholder(self):
        """per_instance signals can use {context} placeholder."""
        sig = SignalDefinition(
            signal_type="transport_input",
            category="vty",
            context_template="{context}",
            aggregation_strategy="per_instance",
            security_domain="management_plane",
        )
        sig.validate()  # Should not raise

    def test_valid_per_instance_with_interface_placeholder(self):
        """per_instance signals can use {interface} placeholder."""
        sig = SignalDefinition(
            signal_type="interface_state",
            category="interface",
            context_template="interface_{context}",
            aggregation_strategy="per_instance",
            security_domain="data_plane",
        )
        sig.validate()  # Should not raise

    def test_singleton_cannot_have_dynamic_template(self):
        """Singleton signals cannot use {placeholder} in template."""
        sig = SignalDefinition(
            signal_type="test_signal",
            category="snmp",
            context_template="snmp_{context}",
            aggregation_strategy="singleton",
            security_domain="management_plane",
        )
        with pytest.raises(SignalDefinitionError, match="cannot have dynamic template"):
            sig.validate()

    def test_per_instance_cannot_use_singleton_template(self):
        """per_instance signals must have a dynamic template."""
        sig = SignalDefinition(
            signal_type="test_signal",
            category="vty",
            context_template="singleton",
            aggregation_strategy="per_instance",
            security_domain="management_plane",
        )
        with pytest.raises(SignalDefinitionError, match="must have a dynamic template"):
            sig.validate()

    def test_invalid_placeholder_rejected(self):
        """Illegal placeholders like {interfaceee} must be rejected."""
        sig = SignalDefinition(
            signal_type="test_signal",
            category="interface",
            context_template="{interfaceee}",
            aggregation_strategy="per_instance",
            security_domain="management_plane",
        )
        with pytest.raises(SignalDefinitionError, match="Invalid placeholder"):
            sig.validate()

    def test_multiple_invalid_placeholders(self):
        """Multiple invalid placeholders all reported."""
        sig = SignalDefinition(
            signal_type="test_signal",
            category="interface",
            context_template="{foo}{bar}{baz}",
            aggregation_strategy="per_instance",
            security_domain="management_plane",
        )
        with pytest.raises(SignalDefinitionError, match="Invalid placeholder"):
            sig.validate()

    def test_template_too_long_rejected(self):
        """Templates exceeding MAX_TEMPLATE_LENGTH are rejected."""
        sig = SignalDefinition(
            signal_type="test_signal",
            category="interface",
            context_template="a" * (MAX_TEMPLATE_LENGTH + 1),
            aggregation_strategy="per_instance",
            security_domain="management_plane",
        )
        with pytest.raises(SignalDefinitionError, match="too long"):
            sig.validate()

    def test_invalid_aggregation_strategy(self):
        """Unknown aggregation strategies are rejected."""
        sig = SignalDefinition(
            signal_type="test_signal",
            category="snmp",
            context_template="{context}",
            aggregation_strategy="invalid_strategy",
            security_domain="management_plane",
        )
        with pytest.raises(SignalDefinitionError, match="invalid aggregation_strategy"):
            sig.validate()

    def test_missing_placeholder_in_dynamic_template(self):
        """Dynamic template without any placeholder is invalid."""
        sig = SignalDefinition(
            signal_type="test_signal",
            category="interface",
            context_template="just_a_string",
            aggregation_strategy="per_instance",
            security_domain="management_plane",
        )
        with pytest.raises(SignalDefinitionError, match="must be 'singleton' or contain a valid placeholder"):
            sig.validate()


class TestSignalRegistry:
    """Tests for SignalRegistry registration and lookup."""

    def setup_method(self):
        """Reset registry before each test."""
        SignalRegistry.reset_instance()

    def test_register_valid_signal(self):
        """Valid signals register successfully."""
        registry = SignalRegistry.get_instance()
        sig = SignalDefinition(
            signal_type="test_snmp",
            category="snmp",
            context_template="singleton",
            aggregation_strategy="singleton",
            security_domain="management_plane",
        )
        registry.register(sig)
        assert registry.is_registered("test_snmp")

    def test_duplicate_registration_rejected(self):
        """Duplicate signal type raises ValueError."""
        registry = SignalRegistry.get_instance()
        sig = SignalDefinition(
            signal_type="test_dup",
            category="snmp",
            context_template="singleton",
            aggregation_strategy="singleton",
            security_domain="management_plane",
        )
        registry.register(sig)
        with pytest.raises(ValueError, match="Duplicate signal type"):
            registry.register(sig)

    def test_invalid_signal_rejected_at_registration(self):
        """Invalid signals are rejected during registration, not later."""
        registry = SignalRegistry.get_instance()
        sig = SignalDefinition(
            signal_type="bad_signal",
            category="interface",
            context_template="{invalid}",
            aggregation_strategy="per_instance",
            security_domain="management_plane",
        )
        with pytest.raises(SignalDefinitionError):
            registry.register(sig)
        assert not registry.is_registered("bad_signal")

    def test_get_existing_signal(self):
        """get() returns the registered signal definition."""
        registry = SignalRegistry.get_instance()
        sig = SignalDefinition(
            signal_type="test_get",
            category="snmp",
            context_template="singleton",
            aggregation_strategy="singleton",
            security_domain="management_plane",
        )
        registry.register(sig)
        retrieved = registry.get("test_get")
        assert retrieved is sig

    def test_get_nonexistent_signal(self):
        """get() returns None for unregistered signals."""
        registry = SignalRegistry.get_instance()
        assert registry.get("nonexistent") is None

    def test_get_by_category(self):
        """get_by_category() returns signals for that category."""
        registry = SignalRegistry.get_instance()
        sig = SignalDefinition(
            signal_type="test_cat",
            category="interface",
            context_template="interface_{context}",
            aggregation_strategy="per_instance",
            security_domain="data_plane",
        )
        registry.register(sig)
        results = registry.get_by_category("interface")
        assert any(s.signal_type == "test_cat" for s in results)


class TestCategoryIndex:
    """Tests for category indexing."""

    def setup_method(self):
        SignalRegistry.reset_instance()

    def test_category_index_built_on_register(self):
        """Category index is rebuilt after each registration."""
        registry = SignalRegistry.get_instance()
        sig = SignalDefinition(
            signal_type="test_index",
            category="interface",
            context_template="interface_{context}",
            aggregation_strategy="per_instance",
            security_domain="data_plane",
        )
        registry.register(sig)
        categories = registry.get_all_categories()
        assert "interface" in categories

    def test_singleton_category_uses_category_field(self):
        """Singleton signals use category field directly."""
        registry = SignalRegistry.get_instance()
        sig = SignalDefinition(
            signal_type="test_global",
            category="snmp",
            context_template="singleton",
            aggregation_strategy="singleton",
            security_domain="management_plane",
        )
        registry.register(sig)
        results = registry.get_by_category("snmp")
        assert any(s.signal_type == "test_global" for s in results)


class TestCreateWithDefaults:
    """Tests for create_signal_registry_with_defaults()."""

    def test_creates_singleton(self):
        """Factory creates or returns existing singleton."""
        SignalRegistry.reset_instance()
        registry = create_signal_registry_with_defaults()
        assert isinstance(registry, SignalRegistry)

    def test_registers_standard_signals(self):
        """Factory registers all standard ConfigGuard signals."""
        SignalRegistry.reset_instance()
        registry = create_signal_registry_with_defaults()

        # Check critical signals are registered
        assert registry.is_registered("snmp_version")
        assert registry.is_registered("snmp_community")
        assert registry.is_registered("transport_input")
        assert registry.is_registered("interface_state")
        assert registry.is_registered("aaa_enabled")
        assert registry.is_registered("http_server")

    def test_all_signals_valid(self):
        """All pre-registered signals pass validation."""
        SignalRegistry.reset_instance()
        registry = create_signal_registry_with_defaults()

        for sig_type in registry.get_all_signal_types():
            sig = registry.get(sig_type)
            assert sig is not None
            sig.validate()  # Should not raise for any standard signal


class TestPlaceholderWhitelist:
    """Explicit tests for placeholder validation."""

    def test_allowed_placeholders_accepted(self):
        """All placeholders in VALID_PLACEHOLDERS are accepted."""
        for placeholder in VALID_PLACEHOLDERS:
            sig = SignalDefinition(
                signal_type="test",
                category="vty",
                context_template=placeholder,
                aggregation_strategy="per_instance",
                security_domain="management_plane",
            )
            sig.validate()  # Should not raise

    def test_composite_template_with_interface(self):
        """Templates like 'interface_{context}' are valid."""
        sig = SignalDefinition(
            signal_type="test",
            category="interface",
            context_template="interface_{context}",
            aggregation_strategy="per_instance",
            security_domain="data_plane",
        )
        sig.validate()  # Should not raise

    def test_typo_placeholder_rejected(self):
        """Near-miss placeholders like {interfac} are rejected."""
        sig = SignalDefinition(
            signal_type="test",
            category="interface",
            context_template="{interfac}",
            aggregation_strategy="per_instance",
            security_domain="management_plane",
        )
        with pytest.raises(SignalDefinitionError, match="Invalid placeholder"):
            sig.validate()

    def test_completely_wrong_placeholder_rejected(self):
        """Completely invalid placeholders are rejected."""
        sig = SignalDefinition(
            signal_type="test",
            category="interface",
            context_template="{nonexistent_var}",
            aggregation_strategy="per_instance",
            security_domain="management_plane",
        )
        with pytest.raises(SignalDefinitionError, match="Invalid placeholder"):
            sig.validate()