from app.checkers.base import CheckOutcome
from app.models import Protocol


def get_checker(protocol) -> object:
    match protocol:
        case Protocol.WIREGUARD:
            from app.checkers.wireguard import WireGuardChecker

            return WireGuardChecker()
        case Protocol.AMNEZIAWG:
            from app.checkers.amneziawg import AmneziaWGChecker

            return AmneziaWGChecker()
        case Protocol.VLESS:
            from app.checkers.vless import VlessChecker

            return VlessChecker()
        case Protocol.TG_PROXY:
            from app.checkers.tg_proxy import TelegramProxyChecker

            return TelegramProxyChecker()
        case _:
            raise KeyError(protocol)


__all__ = ["CheckOutcome", "get_checker"]
