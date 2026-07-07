from app.checkers.tg_proxy import TelegramProxyChecker
from app.checkers.vless import VlessChecker
from app.checkers.base import CheckOutcome
from app.models import CheckStatus, Protocol


VLESS_URI = (
    "vless://12345678-1234-1234-1234-123456789012@example.com:443"
    "?security=reality&type=tcp&sni=yandex.ru&pbk=KEY&sid=ac#demo"
)

TG_URI = "tg://proxy?server=telegram.example.com&port=443&secret=abcdef"


def test_vless_checker_reports_online_with_deep_probe(monkeypatch):
    checker = VlessChecker()

    monkeypatch.setattr(
        "app.checkers.vless.probe_vless_uri",
        lambda config_text: CheckOutcome(
            protocol=Protocol.VLESS,
            status=CheckStatus.ONLINE,
            stage="usable_connectivity",
            summary="VLESS tunnel established",
            latency_ms=84,
            details={"egress_ip": "198.51.100.77"},
        ),
    )

    outcome = checker.check_text(VLESS_URI)

    assert outcome.status is CheckStatus.ONLINE
    assert outcome.stage == "usable_connectivity"
    assert outcome.latency_ms == 84
    assert outcome.details["egress_ip"] == "198.51.100.77"


def test_vless_checker_reports_offline_when_deep_probe_fails(monkeypatch):
    checker = VlessChecker()

    monkeypatch.setattr(
        "app.checkers.vless.probe_vless_uri",
        lambda config_text: CheckOutcome(
            protocol=Protocol.VLESS,
            status=CheckStatus.OFFLINE,
            stage="proxy_http",
            summary="VLESS deep-check failed: timed out",
            details={"host": "example.com", "port": 443},
        ),
    )

    outcome = checker.check_text(VLESS_URI)

    assert outcome.status is CheckStatus.OFFLINE
    assert outcome.stage == "proxy_http"
    assert "timed out" in outcome.summary.lower()


def test_tg_proxy_checker_reports_online_with_deep_probe(monkeypatch):
    checker = TelegramProxyChecker()

    monkeypatch.setattr(
        "app.checkers.tg_proxy.probe_tg_proxy_uri",
        lambda config_text: CheckOutcome(
            protocol=Protocol.TG_PROXY,
            status=CheckStatus.ONLINE,
            stage="usable_connectivity",
            summary="Telegram proxy accepted MTProto request",
            latency_ms=55,
            details={"dc_id": 2, "response_len": 24},
        ),
    )

    outcome = checker.check_text(TG_URI)

    assert outcome.status is CheckStatus.ONLINE
    assert outcome.stage == "usable_connectivity"
    assert outcome.latency_ms == 55
    assert outcome.details["dc_id"] == 2


def test_tg_proxy_checker_reports_offline_when_deep_probe_fails(monkeypatch):
    checker = TelegramProxyChecker()

    monkeypatch.setattr(
        "app.checkers.tg_proxy.probe_tg_proxy_uri",
        lambda config_text: CheckOutcome(
            protocol=Protocol.TG_PROXY,
            status=CheckStatus.OFFLINE,
            stage="mtproto_response",
            summary="Telegram proxy deep-check failed: no MTProto response",
            details={"host": "telegram.example.com", "port": 443},
        ),
    )

    outcome = checker.check_text(TG_URI)

    assert outcome.status is CheckStatus.OFFLINE
    assert outcome.stage == "mtproto_response"
    assert "no mtproto response" in outcome.summary.lower()
