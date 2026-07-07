from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Optional

from sqlmodel import Field, SQLModel


class Protocol(StrEnum):
    WIREGUARD = "wireguard"
    AMNEZIAWG = "amneziawg"
    VLESS = "vless"
    TG_PROXY = "tg-proxy"


class CheckStatus(StrEnum):
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    ERROR = "error"
    UNKNOWN = "unknown"


class Target(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    protocol: Protocol
    config_text: str
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CheckResult(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(index=True, foreign_key="target.id")
    protocol: Protocol
    status: CheckStatus = CheckStatus.UNKNOWN
    latency_ms: Optional[int] = None
    stage: str = "unknown"
    summary: str = ""
    details_json: str = "{}"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserSession(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="user.id")
    token: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    expires_at: datetime = Field(index=True)
