from pathlib import Path

from sqlmodel import Session, select

from app.db import create_engine_for_path, init_db
from app.models import CheckResult, CheckStatus, Protocol, Target


def test_target_model_roundtrip(tmp_path: Path):
    db_path = tmp_path / "checkvpn.db"
    engine = create_engine_for_path(db_path)
    init_db(engine)

    target = Target(
        name="wg-main",
        protocol=Protocol.WIREGUARD,
        config_text="[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nEndpoint = 1.2.3.4:51820",
        enabled=True,
    )

    with Session(engine) as session:
        session.add(target)
        session.commit()
        session.refresh(target)
        loaded = session.exec(select(Target)).one()

    assert loaded.id is not None
    assert loaded.name == "wg-main"
    assert loaded.protocol == Protocol.WIREGUARD


def test_check_result_model_roundtrip(tmp_path: Path):
    db_path = tmp_path / "checkvpn.db"
    engine = create_engine_for_path(db_path)
    init_db(engine)

    with Session(engine) as session:
        target = Target(
            name="vless-main",
            protocol=Protocol.VLESS,
            config_text="vless://uuid@example.com:443?security=tls&type=ws#demo",
            enabled=True,
        )
        session.add(target)
        session.commit()
        session.refresh(target)

        target_id = target.id
        result = CheckResult(
            target_id=target_id,
            protocol=Protocol.VLESS,
            status=CheckStatus.ONLINE,
            latency_ms=123,
            stage="http_probe",
            summary="Proxy reachable",
            details_json='{"http_status":200}',
        )
        session.add(result)
        session.commit()
        session.refresh(result)

        loaded = session.exec(select(CheckResult)).one()

    assert loaded.target_id == target_id
    assert loaded.status == CheckStatus.ONLINE
    assert loaded.latency_ms == 123
