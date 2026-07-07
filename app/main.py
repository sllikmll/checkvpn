from __future__ import annotations

from pathlib import Path
import os

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.services import CheckVPNService

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))
SESSION_COOKIE_NAME = "checkvpn_session"


def create_app(
    db_url: str | None = None,
    admin_username: str | None = None,
    admin_password: str | None = None,
) -> FastAPI:
    db_url = db_url or os.getenv("CHECKVPN_DB_URL", "sqlite:///./checkvpn.db")
    admin_username = admin_username or os.getenv("CHECKVPN_ADMIN_USERNAME")
    admin_password = admin_password or os.getenv("CHECKVPN_ADMIN_PASSWORD")

    app = FastAPI(title="CheckVPN")
    service = CheckVPNService.from_db_url(db_url)
    if admin_username and admin_password:
        service.ensure_admin_user(admin_username, admin_password)
    app.state.service = service
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    def current_user(request: Request):
        token = request.cookies.get(SESSION_COOKIE_NAME)
        return service.get_user_by_session_token(token)

    def require_user(request: Request):
        user = current_user(request)
        if user is None:
            return None, RedirectResponse(url="/login", status_code=303)
        return user, None

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, error: str | None = None):
        return TEMPLATES.TemplateResponse(
            request=request,
            name="login.html",
            context={"request": request, "error": error},
        )

    @app.post("/login")
    def login(request: Request, username: str = Form(...), password: str = Form(...)):
        user = service.authenticate_user(username, password)
        if user is None:
            return TEMPLATES.TemplateResponse(
                request=request,
                name="login.html",
                context={"request": request, "error": "Invalid username or password"},
                status_code=401,
            )
        assert user.id is not None
        token = service.create_session_for_user(user.id)
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE_NAME,
            token,
            httponly=True,
            samesite="lax",
            max_age=7 * 24 * 60 * 60,
            path="/",
        )
        return response

    @app.post("/logout")
    def logout(request: Request):
        service.delete_session(request.cookies.get(SESSION_COOKIE_NAME))
        response = RedirectResponse(url="/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")
        return response

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        user, redirect = require_user(request)
        if redirect is not None:
            return redirect
        targets = service.list_targets()
        rows = []
        for target in targets:
            rows.append({"target": target, "latest": service.get_latest_result(target.id)})
        return TEMPLATES.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "request": request,
                "rows": rows,
                "protocols": ["wireguard", "amneziawg", "vless", "tg-proxy"],
                "current_user": user,
            },
        )

    @app.post("/targets")
    def create_target(request: Request, name: str = Form(...), protocol: str = Form(...), config_text: str = Form(...)):
        _, redirect = require_user(request)
        if redirect is not None:
            return redirect
        service.create_target(name=name, protocol=protocol, config_text=config_text)
        return RedirectResponse(url="/", status_code=303)

    @app.post("/targets/{target_id}/run")
    def run_target(request: Request, target_id: int):
        _, redirect = require_user(request)
        if redirect is not None:
            return redirect
        service.run_check(target_id)
        return RedirectResponse(url="/", status_code=303)

    return app


app = create_app()
