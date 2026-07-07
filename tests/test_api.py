from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app


def test_health_endpoint(tmp_path: Path):
    app = create_app(db_url=f"sqlite:///{tmp_path / 'checkvpn.db'}")
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_index_requires_login(tmp_path: Path):
    app = create_app(
        db_url=f"sqlite:///{tmp_path / 'checkvpn.db'}",
        admin_username="admin",
        admin_password="secret123",
    )
    client = TestClient(app)

    response = client.get("/", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert response.headers["location"] == "/login"


def test_login_page_renders(tmp_path: Path):
    app = create_app(
        db_url=f"sqlite:///{tmp_path / 'checkvpn.db'}",
        admin_username="admin",
        admin_password="secret123",
    )
    client = TestClient(app)

    response = client.get("/login")
    assert response.status_code == 200
    assert "Sign in" in response.text


def test_login_and_access_index(tmp_path: Path):
    app = create_app(
        db_url=f"sqlite:///{tmp_path / 'checkvpn.db'}",
        admin_username="admin",
        admin_password="secret123",
    )
    client = TestClient(app)

    login = client.post(
        "/login",
        data={"username": "admin", "password": "secret123"},
        follow_redirects=False,
    )
    assert login.status_code in (302, 303)
    assert login.headers["location"] == "/"
    assert "checkvpn_session" in login.cookies

    page = client.get("/")
    assert page.status_code == 200
    assert "CheckVPN" in page.text


def test_create_target_endpoint_requires_authenticated_session(tmp_path: Path):
    app = create_app(
        db_url=f"sqlite:///{tmp_path / 'checkvpn.db'}",
        admin_username="admin",
        admin_password="secret123",
    )
    client = TestClient(app)

    response = client.post(
        "/targets",
        data={
            "name": "demo-vless",
            "protocol": "vless",
            "config_text": "vless://12345678-1234-1234-1234-123456789012@example.com:443?security=tls&type=ws&sni=example.com#demo",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)
    assert response.headers["location"] == "/login"


def test_create_target_endpoint_after_login(tmp_path: Path):
    app = create_app(
        db_url=f"sqlite:///{tmp_path / 'checkvpn.db'}",
        admin_username="admin",
        admin_password="secret123",
    )
    client = TestClient(app)
    client.post("/login", data={"username": "admin", "password": "secret123"})

    response = client.post(
        "/targets",
        data={
            "name": "demo-vless",
            "protocol": "vless",
            "config_text": "vless://12345678-1234-1234-1234-123456789012@example.com:443?security=tls&type=ws&sni=example.com#demo",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)

    page = client.get("/")
    assert "demo-vless" in page.text
