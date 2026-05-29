"""Block-aware Cisco IOS parser producing dual representation + IR."""
from configguard.models import ConfigIR, Block


class CiscoIOSParser:
    BLOCK_STARTERS = {
        "interface": "interface",
        "line": "line",
        "router": "router",
        "access-list": "access-list",
    }

    def __init__(self, config_text: str):
        self.config_text = config_text
        self.lines = config_text.strip().splitlines()
        self.current_block = None
        self.blocks = []
        self.raw_lines = []

    def parse(self) -> ConfigIR:
        for line in self.lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("!"):
                if self.current_block:
                    self._finalize_block()
                continue

            self.raw_lines.append(stripped)

            block_type = self._detect_block_start(stripped)
            if block_type:
                if self.current_block:
                    self._finalize_block()
                # Extract the name portion after the keyword
                name = stripped[len(block_type):].strip()
                self.current_block = {
                    "type": block_type,
                    "name": name,
                    "commands": [],
                }
            elif self.current_block is not None:
                self.current_block["commands"].append(stripped)

        if self.current_block:
            self._finalize_block()

        normalized = self._build_normalized_ir()
        metadata = {
            "total_lines": len(self.raw_lines),
            "block_count": len(self.blocks),
        }

        return ConfigIR(
            raw_lines=self.raw_lines,
            blocks=self.blocks,
            normalized=normalized,
            metadata=metadata,
        )

    def _detect_block_start(self, line: str) -> str | None:
        for keyword, block_type in self.BLOCK_STARTERS.items():
            if line.startswith(keyword):
                return block_type
        return None

    def _finalize_block(self):
        if self.current_block:
            self.blocks.append(Block(**self.current_block))
            self.current_block = None

    def _build_normalized_ir(self) -> dict:
        ir = {
            "services": {},
            "management": {},
            "logging": {},
            "snmp": {},
            "interfaces": {},
        }

        # Extract telnet/ssh from VTY blocks
        for block in self.blocks:
            if block.type == "line" and "vty" in block.name.lower():
                for cmd in block.commands:
                    if "transport input" in cmd:
                        if "telnet" in cmd:
                            ir["services"]["telnet"] = {"status": "enabled", "scope": "vty"}
                        if "ssh" in cmd:
                            ir["services"]["ssh"] = {"status": "enabled", "scope": "vty"}

        # Extract management settings
        for block in self.blocks:
            if block.type == "global" or block.type == "line":
                for cmd in block.commands:
                    if cmd.startswith("logging"):
                        ir["logging"]["syslog"] = {"status": "configured"}

        return ir