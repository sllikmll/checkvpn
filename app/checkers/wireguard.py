from __future__ import annotations

from app.checkers.base import BaseChecker, CheckOutcome
from app.models import CheckStatus, Protocol
from app.netutils import resolve_host
from app.parsers import parse_target_config


class WireGuardChecker(BaseChecker):
    protocol = Protocol.WIREGUARD

    def check_text(self, config_text: str) -> CheckOutcome:
        parsed = parse_target_config(self.protocol, config_text)
        try:
            ips = resolve_host(parsed["host"])
            return CheckOutcome(
                protocol=self.protocol,
                status=CheckStatus.DEGRADED,
                stage="endpoint_resolution",
                summary="WireGuard endpoint resolved; full tunnel probe requires privileged runtime and real config import",
                details={"host": parsed["host"], "port": parsed["port"], "resolved_ips": ips},
            )
        except Exception as exc:
            return CheckOutcome(
                protocol=self.protocol,
                status=CheckStatus.OFFLINE,
                stage="endpoint_resolution",
                summary=f"WireGuard endpoint resolution failed: {exc}",
                details={"host": parsed.get("host"), "port": parsed.get("port")},
            )
