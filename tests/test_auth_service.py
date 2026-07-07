from pathlib import Path

from app.db import create_engine_for_path, init_db
from app.services import CheckVPNService


def test_bootstrap_admin_and_authenticate(tmp_path: Path):
    engine = create_engine_for_path(tmp_path / "checkvpn.db")
    init_db(engine)
    service = CheckVPNService(engine)

    user = service.ensure_admin_user("admin", "secret123")

    assert user.username == "admin"
    assert user.password_hash != "secret123"
    assert service.authenticate_user("admin", "secret123") is not None
    assert service.authenticate_user("admin", "wrong") is None


def test_create_session_and_resolve_current_user(tmp_path: Path):
    engine = create_engine_for_path(tmp_path / "checkvpn.db")
    init_db(engine)
    service = CheckVPNService(engine)

    user = service.ensure_admin_user("admin", "secret123")
    token = service.create_session_for_user(user.id)
    resolved = service.get_user_by_session_token(token)

    assert isinstance(token, str)
    assert len(token) >= 20
    assert resolved is not None
    assert resolved.id == user.id
