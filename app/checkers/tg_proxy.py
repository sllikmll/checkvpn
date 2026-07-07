from __future__ import annotations

from app.checkers.base import BaseChecker, CheckOutcome
from app.models import Protocol
from app.tg_proxy_probe import probe_tg_proxy_uri


class TelegramProxyChecker(BaseChecker):
    protocol = Protocol.TG_PROXY

    def check_text(self, config_text: str) -> CheckOutcome:
        return probe_tg_proxy_uri(config_text)
