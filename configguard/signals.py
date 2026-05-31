"""Signal extraction from ConfigIR."""
import re
from configguard.models import ConfigIR, Block, Signal


class SignalExtractor:
    def extract(self, config_ir: ConfigIR) -> list[Signal]:
        """Extract signals from parsed ConfigIR with deduplication.

        Deduplication strategy:
        - For block-level signals (VTY, interface): deduplicate by (type, context)
          to keep one signal per block instance.
        - For global signals: deduplicate by (type, context, value) to preserve
          ALL distinct values (e.g., all SNMP communities).
        """
        signals = []
        seen = set()

        # Extract from blocks
        for block in config_ir.blocks:
            block_sigs = self._extract_from_block(block)
            for sig in block_sigs:
                key = (sig.type, sig.context)
                if key not in seen:
                    seen.add(key)
                    signals.append(sig)

        # Extract global-level signals
        global_sigs = self._extract_global_signals(config_ir)
        for sig in global_sigs:
            # Global signals include value in key to preserve all distinct values
            key = (sig.type, sig.context, sig.value)
            if key not in seen:
                seen.add(key)
                signals.append(sig)

        return signals

    def _extract_from_block(self, block: Block) -> list[Signal]:
        if block.type == "line":
            return self._extract_line_signals(block)
        elif block.type == "interface":
            return self._extract_interface_signals(block)
        return []

    def _extract_line_signals(self, block: Block) -> list[Signal]:
        signals = []
        context = block.name

        for cmd in block.commands:
            if cmd.startswith("transport input"):
                if "telnet" in cmd:
                    signals.append(Signal(
                        type="transport_input",
                        value="telnet",
                        context=context,
                        block_type="line",
                        raw=cmd,
                    ))
                if "ssh" in cmd:
                    signals.append(Signal(
                        type="transport_input",
                        value="ssh",
                        context=context,
                        block_type="line",
                        raw=cmd,
                    ))
            elif cmd.startswith("login"):
                if "local" in cmd:
                    signals.append(Signal(
                        type="auth_method",
                        value="local",
                        context=context,
                        block_type="line",
                        raw=cmd,
                    ))

        return signals

    def _extract_interface_signals(self, block: Block) -> list[Signal]:
        signals = []
        context = block.name

        is_shutdown = any(cmd == "shutdown" for cmd in block.commands)
        signals.append(Signal(
            type="interface_state",
            value="shutdown" if is_shutdown else "up",
            context=context,
            block_type="interface",
            raw="shutdown" if is_shutdown else "no shutdown",
        ))

        has_description = any(cmd.startswith("description") for cmd in block.commands)
        signals.append(Signal(
            type="interface_description",
            value="present" if has_description else "missing",
            context=context,
            block_type="interface",
            raw=next((cmd for cmd in block.commands if cmd.startswith("description")), "") if has_description else "",
        ))

        return signals

    def _extract_global_signals(self, config_ir: ConfigIR) -> list[Signal]:
        signals = []
        raw_text = "\n".join(config_ir.raw_lines)

        # AAA - emit signal for all three states
        if "aaa new-model" in raw_text and "no aaa new-model" not in raw_text:
            signals.append(Signal(
                type="aaa_enabled",
                value="true",
                context="global",
                block_type="global",
                raw="aaa new-model",
            ))
        elif "no aaa new-model" in raw_text:
            signals.append(Signal(
                type="aaa_enabled",
                value="false",
                context="global",
                block_type="global",
                raw="no aaa new-model",
            ))
        else:
            # AAA not mentioned - emit missing signal with placeholder
            signals.append(Signal(
                type="aaa_enabled",
                value="missing",
                context="global",
                block_type="global",
                raw="AAA_MISSING",
            ))

        # HTTP server - emit signal for all states
        if "ip http server" in raw_text and "no ip http server" not in raw_text:
            # Only plain HTTP server (not secure-only)
            signals.append(Signal(
                type="http_server",
                value="enabled",
                context="global",
                block_type="global",
                raw="HTTP_ENABLED",
            ))
        elif "no ip http server" in raw_text:
            signals.append(Signal(
                type="http_server",
                value="disabled",
                context="global",
                block_type="global",
                raw="no ip http server",
            ))
        elif "ip http secure-server" in raw_text and "ip http server" not in raw_text:
            signals.append(Signal(
                type="http_server",
                value="secure-only",
                context="global",
                block_type="global",
                raw="ip http secure-server",
            ))
        else:
            signals.append(Signal(
                type="http_server",
                value="missing",
                context="global",
                block_type="global",
                raw="HTTP_MISSING",
            ))

        # SNMP - extract version and all community strings
        # Check for any snmp-server community lines to determine version signal
        community_pattern = re.compile(r'snmp-server\s+community\s+(\S+)', re.MULTILINE)
        communities = community_pattern.findall(raw_text)

        if communities:
            signals.append(Signal(
                type="snmp_version",
                value="v2c",
                context="global",
                block_type="global",
                raw="snmp-server community",
            ))
            for community in communities:
                signals.append(Signal(
                    type="snmp_community",
                    value=community,
                    context="global",
                    block_type="global",
                    raw=f"snmp-server community {community}",
                ))

        # Syslog
        if "logging host" in raw_text:
            signals.append(Signal(
                type="syslog_host",
                value="configured",
                context="global",
                block_type="global",
                raw="logging host",
            ))

        # NTP
        if "ntp server" in raw_text:
            signals.append(Signal(
                type="ntp_server",
                value="configured",
                context="global",
                block_type="global",
                raw="ntp server",
            ))

        return signals