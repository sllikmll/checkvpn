from __future__ import annotations

from pathlib import Path

from sqlmodel import SQLModel, create_engine


def create_engine_for_path(path: str | Path):
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{db_path}")


def init_db(engine) -> None:
    SQLModel.metadata.create_all(engine)
