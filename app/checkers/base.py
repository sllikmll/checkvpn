from __future__ import annotations

from dataclasses import dataclass, field

from app.models import CheckStatus, Protocol


@dataclass
class CheckOutcome:
    protocol: Protocol
    status: CheckStatus
    stage: str
    summary: str
    latency_ms: int | None = None
    details: dict = field(default_factory=dict)


class BaseChecker:
    protocol: Protocol

    def check_text(self, config_text: str) -> CheckOutcome:
        raise NotImplementedError
