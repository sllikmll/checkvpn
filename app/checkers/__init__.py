from app.checkers.amneziawg import AmneziaWGChecker
from app.checkers.base import CheckOutcome
from app.checkers.tg_proxy import TelegramProxyChecker
from app.checkers.vless import VlessChecker
from app.checkers.wireguard import WireGuardChecker
from app.models import Protocol

_REGISTRY = {
    Protocol.WIREGUARD: WireGuardChecker(),
    Protocol.AMNEZIAWG: AmneziaWGChecker(),
    Protocol.VLESS: VlessChecker(),
    Protocol.TG_PROXY: TelegramProxyChecker(),
}


def get_checker(protocol) -> object:
    if protocol not in _REGISTRY:
        raise KeyError(protocol)
    return _REGISTRY[protocol]


__all__ = ["CheckOutcome", "get_checker"]
