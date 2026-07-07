from app.checkers import get_checker
from app.checkers.base import CheckOutcome
from app.models import Protocol


def test_unknown_protocol_fails_cleanly():
    try:
        get_checker("unknown")
    except KeyError:
        pass
    else:
        raise AssertionError("Expected KeyError for unknown protocol")


def test_checker_output_contract_for_vless():
    checker = get_checker(Protocol.VLESS)
    outcome = checker.check_text("vless://12345678-1234-1234-1234-123456789012@example.com:443?security=reality&type=tcp&sni=yandex.ru&pbk=KEY&sid=ac#demo")
    assert isinstance(outcome, CheckOutcome)
    assert outcome.protocol == Protocol.VLESS
    assert outcome.stage
    assert outcome.summary is not None
