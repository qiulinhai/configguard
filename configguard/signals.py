"""Signal extraction from ConfigIR."""
from configguard.models import ConfigIR, Block, Signal


class SignalExtractor:
    def extract(self, config_ir: ConfigIR) -> list[Signal]:
        """Extract signals from parsed ConfigIR with deduplication."""
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
            key = (sig.type, sig.context)
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

        # AAA
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

        # HTTP server
        if "ip http server" in raw_text and "no ip http server" not in raw_text:
            signals.append(Signal(
                type="http_server",
                value="enabled",
                context="global",
                block_type="global",
                raw="ip http server",
            ))
        elif "no ip http server" in raw_text:
            signals.append(Signal(
                type="http_server",
                value="disabled",
                context="global",
                block_type="global",
                raw="no ip http server",
            ))

        # SNMP
        if "snmp-server community public" in raw_text or "snmp-server community private" in raw_text:
            signals.append(Signal(
                type="snmp_version",
                value="v2c",
                context="global",
                block_type="global",
                raw="snmp-server community",
            ))
            if "snmp-server community public" in raw_text:
                signals.append(Signal(
                    type="snmp_community",
                    value="public",
                    context="global",
                    block_type="global",
                    raw="snmp-server community public",
                ))
            if "snmp-server community private" in raw_text:
                signals.append(Signal(
                    type="snmp_community",
                    value="private",
                    context="global",
                    block_type="global",
                    raw="snmp-server community private",
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