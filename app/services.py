from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlmodel import Session, create_engine, select

from app.auth import hash_password, make_session_token, session_expiry, utc_now, verify_password
from app.checkers import get_checker
from app.db import init_db
from app.models import CheckResult, Protocol, Target, User, UserSession


class CheckVPNService:
    def __init__(self, engine):
        self.engine = engine
        init_db(self.engine)

    @classmethod
    def from_db_url(cls, db_url: str):
        connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
        engine = create_engine(db_url, connect_args=connect_args)
        return cls(engine)

    def ensure_admin_user(self, username: str, password: str) -> User:
        with Session(self.engine) as session:
            statement = select(User).where(User.username == username)
            user = session.exec(statement).first()
            password_hash = hash_password(password)
            if user is None:
                user = User(username=username, password_hash=password_hash, is_active=True)
                session.add(user)
            else:
                user.password_hash = password_hash
                user.is_active = True
                user.updated_at = utc_now()
                session.add(user)
            session.commit()
            session.refresh(user)
            return user

    def authenticate_user(self, username: str, password: str) -> User | None:
        with Session(self.engine) as session:
            statement = select(User).where(User.username == username, User.is_active == True)
            user = session.exec(statement).first()
            if user is None:
                return None
            if not verify_password(password, user.password_hash):
                return None
            return user

    def create_session_for_user(self, user_id: int) -> str:
        token = make_session_token()
        with Session(self.engine) as session:
            session.add(UserSession(user_id=user_id, token=token, expires_at=session_expiry()))
            session.commit()
        return token

    def get_user_by_session_token(self, token: str | None) -> User | None:
        if not token:
            return None
        with Session(self.engine) as session:
            statement = select(UserSession).where(UserSession.token == token)
            user_session = session.exec(statement).first()
            if user_session is None:
                return None
            if user_session.expires_at <= utc_now():
                session.delete(user_session)
                session.commit()
                return None
            user = session.get(User, user_session.user_id)
            if user is None or not user.is_active:
                return None
            return user

    def delete_session(self, token: str | None) -> None:
        if not token:
            return
        with Session(self.engine) as session:
            statement = select(UserSession).where(UserSession.token == token)
            user_session = session.exec(statement).first()
            if user_session is not None:
                session.delete(user_session)
                session.commit()

    def create_target(self, *, name: str, protocol: Protocol | str, config_text: str, enabled: bool = True):
        protocol = Protocol(protocol)
        target = Target(name=name, protocol=protocol, config_text=config_text, enabled=enabled)
        with Session(self.engine) as session:
            session.add(target)
            session.commit()
            session.refresh(target)
            return target

    def list_targets(self):
        with Session(self.engine) as session:
            return list(session.exec(select(Target).order_by(Target.id)).all())

    def get_target(self, target_id: int):
        with Session(self.engine) as session:
            return session.get(Target, target_id)

    def run_check(self, target_id: int):
        with Session(self.engine) as session:
            target = session.get(Target, target_id)
            if not target:
                raise KeyError(target_id)
            checker = get_checker(target.protocol)
            outcome = checker.check_text(target.config_text)
            result = CheckResult(
                target_id=target.id,
                protocol=target.protocol,
                status=outcome.status,
                latency_ms=outcome.latency_ms,
                stage=outcome.stage,
                summary=outcome.summary,
                details_json=json.dumps(outcome.details, ensure_ascii=False),
            )
            session.add(result)
            session.commit()
            session.refresh(result)
            return result

    def get_latest_result(self, target_id: int):
        with Session(self.engine) as session:
            statement = (
                select(CheckResult)
                .where(CheckResult.target_id == target_id)
                .order_by(CheckResult.created_at.desc(), CheckResult.id.desc())
            )
            return session.exec(statement).first()
