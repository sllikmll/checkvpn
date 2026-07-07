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


def test_tg_proxy_checker_reports_online_with_secret_presence(monkeypatch):
    checker = TelegramProxyChecker()

    monkeypatch.setattr("app.checkers.tg_proxy.measure_tcp_connect", lambda host, port, timeout=3.0: 12)
    monkeypatch.setattr("app.checkers.tg_proxy.resolve_host", lambda host: ["198.51.100.20"])

    outcome = checker.check_text(TG_URI)

    assert outcome.status is CheckStatus.ONLINE
    assert outcome.stage == "tcp_connect"
    assert outcome.latency_ms == 12
    assert outcome.summary == "Telegram proxy endpoint reachable"
    assert outcome.details == {
        "host": "telegram.example.com",
        "port": 443,
        "secret_present": True,
        "kind": "proxy",
        "resolved_ips": ["198.51.100.20"],
    }


def test_tg_proxy_checker_reports_offline_when_tcp_connect_fails(monkeypatch):
    checker = TelegramProxyChecker()

    def raise_oserror(host, port, timeout=3.0):
        raise OSError("connection refused")

    monkeypatch.setattr("app.checkers.tg_proxy.measure_tcp_connect", raise_oserror)

    outcome = checker.check_text(TG_URI)

    assert outcome.status is CheckStatus.OFFLINE
    assert outcome.stage == "tcp_connect"
    assert "unreachable" in outcome.summary.lower()
    assert "connection refused" in outcome.summary.lower()
    assert outcome.latency_ms is None
    assert outcome.details == {"host": "telegram.example.com", "port": 443}
