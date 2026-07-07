from __future__ import annotations

from app.checkers.base import BaseChecker, CheckOutcome
from app.models import Protocol
from app.vless_probe import probe_vless_uri


class VlessChecker(BaseChecker):
    protocol = Protocol.VLESS

    def check_text(self, config_text: str) -> CheckOutcome:
        return probe_vless_uri(config_text)
