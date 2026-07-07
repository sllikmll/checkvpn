from app.main import create_app


def test_create_app_exists():
    app = create_app()
    assert app is not None
