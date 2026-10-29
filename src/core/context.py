"""Contexto imutável que identifica uma execução."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4


@dataclass(frozen=True)
class RunContext:
    run_id: UUID
    timestamp_utc: datetime
    mode: str

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, UUID):
            raise TypeError("run_id deve ser um UUID.")
        if not isinstance(self.timestamp_utc, datetime):
            raise TypeError("timestamp_utc deve ser um datetime.")
        if (
            self.timestamp_utc.tzinfo is None
            or self.timestamp_utc.utcoffset() != timedelta(0)
        ):
            raise ValueError("timestamp_utc deve ser timezone-aware e estar em UTC.")
        if not isinstance(self.mode, str) or not self.mode.strip():
            raise ValueError("mode deve ser uma string não vazia.")
        object.__setattr__(self, "mode", self.mode.strip())

    @classmethod
    def create(cls, mode: str) -> "RunContext":
        return cls(
            run_id=uuid4(),
            timestamp_utc=datetime.now(timezone.utc),
            mode=mode,
        )
