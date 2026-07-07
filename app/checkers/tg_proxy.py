from __future__ import annotations

from app.checkers.base import BaseChecker, CheckOutcome
from app.models import CheckStatus, Protocol
from app.netutils import measure_tcp_connect, resolve_host
from app.parsers import parse_target_config


class TelegramProxyChecker(BaseChecker):
    protocol = Protocol.TG_PROXY

    def check_text(self, config_text: str) -> CheckOutcome:
        parsed = parse_target_config(self.protocol, config_text)
        try:
            latency = measure_tcp_connect(parsed["host"], parsed["port"], timeout=3.0)
            return CheckOutcome(
                protocol=self.protocol,
                status=CheckStatus.ONLINE,
                stage="tcp_connect",
                summary="Telegram proxy endpoint reachable",
                latency_ms=latency,
                details={
                    "host": parsed["host"],
                    "port": parsed["port"],
                    "secret_present": bool(parsed.get("secret")),
                    "kind": parsed.get("kind"),
                    "resolved_ips": resolve_host(parsed["host"]),
                },
            )
        except Exception as exc:
            return CheckOutcome(
                protocol=self.protocol,
                status=CheckStatus.OFFLINE,
                stage="tcp_connect",
                summary=f"Telegram proxy endpoint unreachable: {exc}",
                details={"host": parsed["host"], "port": parsed["port"]},
            )
