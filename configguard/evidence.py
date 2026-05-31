"""Evidence Builder - transforms SignalContext to human-readable evidence."""
from configguard.context import SignalContext
from configguard.models import Finding


class EvidenceBuilder:
    """Transforms raw SignalContext into human-readable evidence summary.

    This is a PURE formatting layer - no rule logic, no severity changes,
    no aggregation changes. Only transforms existing context data.
    """

    def build(self, context: SignalContext) -> dict:
        """Build human-readable evidence from SignalContext.

        Args:
            context: SignalContext from ContextBuilder

        Returns:
            dict with:
                - summary: One-line human-readable summary
                - details: List of specific items found
                - raw_count: Number of raw signals
        """
        signal_types = set(s.type for s in context.signals)

        # SNMP evidence
        if "snmp_community" in signal_types or "snmp_version" in signal_types:
            return self._build_snmp_evidence(context)

        # VTY evidence
        if "transport_input" in signal_types or "auth_method" in signal_types:
            return self._build_vty_evidence(context)

        # Interface evidence
        if "interface_state" in signal_types:
            return self._build_interface_evidence(context)

        # HTTP evidence
        if "http_server" in signal_types:
            return self._build_http_evidence(context)

        # AAA evidence
        if "aaa_enabled" in signal_types:
            return self._build_aaa_evidence(context)

        # Syslog evidence
        if "syslog_host" in signal_types:
            return self._build_syslog_evidence(context)

        # NTP evidence
        if "ntp_server" in signal_types:
            return self._build_ntp_evidence(context)

        # Default: generic summary
        return self._build_generic_evidence(context)

    def _build_snmp_evidence(self, context: SignalContext) -> dict:
        """Build SNMP-specific evidence summary."""
        communities = [s.value for s in context.signals if s.type == "snmp_community"]
        version = next(
            (s.value for s in context.signals if s.type == "snmp_version"),
            "v2c"
        )

        summary = f"SNMP {version} enabled with {len(communities)} community strings"
        if communities:
            summary += f": {', '.join(communities)}"

        return {
            "summary": summary,
            "details": communities,
            "raw_count": len(context.signals),
        }

    def _build_vty_evidence(self, context: SignalContext) -> dict:
        """Build VTY-specific evidence summary."""
        transports = [s.value for s in context.signals if s.type == "transport_input"]
        auth_methods = [s.value for s in context.signals if s.type == "auth_method"]

        summary_parts = []
        if transports:
            summary_parts.append(f"transports: {', '.join(transports)}")
        if auth_methods:
            summary_parts.append(f"auth: {', '.join(auth_methods)}")

        summary = f"VTY line ({context.context_key})"
        if summary_parts:
            summary += " with " + ", ".join(summary_parts)

        return {
            "summary": summary,
            "details": transports + auth_methods,
            "raw_count": len(context.signals),
        }

    def _build_interface_evidence(self, context: SignalContext) -> dict:
        """Build interface-specific evidence summary."""
        state = context.metadata.get("state", "unknown")
        description = context.metadata.get("description", "missing")

        interface_name = context.context_key.replace("interface_", "")
        summary = f"Interface {interface_name}: {state}"
        if description != "missing":
            summary += f", description: {description}"

        return {
            "summary": summary,
            "details": [state, description] if description != "missing" else [state],
            "raw_count": len(context.signals),
        }

    def _build_http_evidence(self, context: SignalContext) -> dict:
        """Build HTTP-specific evidence summary."""
        http_signals = [s for s in context.signals if s.type == "http_server"]
        states = [s.value for s in http_signals]

        summary = f"HTTP server: {', '.join(states)}"

        return {
            "summary": summary,
            "details": states,
            "raw_count": len(context.signals),
        }

    def _build_aaa_evidence(self, context: SignalContext) -> dict:
        """Build AAA-specific evidence summary."""
        aaa_signals = [s for s in context.signals if s.type == "aaa_enabled"]
        states = [s.value for s in aaa_signals]

        summary = f"AAA: {', '.join(states)}"

        return {
            "summary": summary,
            "details": states,
            "raw_count": len(context.signals),
        }

    def _build_syslog_evidence(self, context: SignalContext) -> dict:
        """Build syslog-specific evidence summary."""
        summary = "Remote syslog configured"
        return {
            "summary": summary,
            "details": ["logging host configured"],
            "raw_count": len(context.signals),
        }

    def _build_ntp_evidence(self, context: SignalContext) -> dict:
        """Build NTP-specific evidence summary."""
        summary = "NTP server configured"
        return {
            "summary": summary,
            "details": ["ntp server configured"],
            "raw_count": len(context.signals),
        }

    def _build_generic_evidence(self, context: SignalContext) -> dict:
        """Build generic evidence summary for unknown context types."""
        signal_types = list(set(s.type for s in context.signals))
        summary = f"Context: {context.context_key} ({len(context.signals)} signals)"

        return {
            "summary": summary,
            "details": signal_types,
            "raw_count": len(context.signals),
        }

    def attach_evidence_summary(self, finding: Finding, context: SignalContext) -> Finding:
        """Attach human-readable evidence summary to a Finding.

        This modifies the finding in-place by adding evidence_summary.
        """
        evidence_dict = self.build(context)
        finding.evidence_summary = evidence_dict
        return finding