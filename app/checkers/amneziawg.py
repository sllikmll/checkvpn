from __future__ import annotations

from app.checkers.base import BaseChecker, CheckOutcome
from app.models import Protocol
from app.vpn_probe import probe_vpn_tunnel


class AmneziaWGChecker(BaseChecker):
    protocol = Protocol.AMNEZIAWG

    def check_text(self, config_text: str) -> CheckOutcome:
        return probe_vpn_tunnel(self.protocol, config_text)
