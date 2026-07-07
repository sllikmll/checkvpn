from pathlib import Path

from app.db import create_engine_for_path, init_db
from app.models import Protocol
from app.services import CheckVPNService


def test_create_and_list_target(tmp_path: Path):
    engine = create_engine_for_path(tmp_path / "checkvpn.db")
    init_db(engine)
    service = CheckVPNService(engine)

    service.create_target(
        name="demo-vless",
        protocol=Protocol.VLESS,
        config_text="vless://12345678-1234-1234-1234-123456789012@example.com:443?security=tls&type=ws&sni=example.com#demo",
    )

    targets = service.list_targets()
    assert len(targets) == 1
    assert targets[0].name == "demo-vless"


def test_run_check_persists_result(tmp_path: Path):
    engine = create_engine_for_path(tmp_path / "checkvpn.db")
    init_db(engine)
    service = CheckVPNService(engine)

    target = service.create_target(
        name="demo-tg",
        protocol=Protocol.TG_PROXY,
        config_text="tg://proxy?server=example.com&port=443&secret=abcdef",
    )
    result = service.run_check(target.id)
    latest = service.get_latest_result(target.id)

    assert result.id is not None
    assert latest is not None
    assert latest.target_id == target.id
