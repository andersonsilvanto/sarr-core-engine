"""Barramento síncrono de eventos em processo."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock
from types import MappingProxyType
from uuid import UUID, uuid4


@dataclass(frozen=True)
class Event:
    run_id: UUID | None
    name: str
    payload: Mapping[str, object] = field(default_factory=dict)
    event_id: UUID = field(default_factory=uuid4)
    timestamp_utc: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.run_id is not None and not isinstance(self.run_id, UUID):
            raise TypeError("run_id do evento deve ser um UUID ou None.")
        if not isinstance(self.event_id, UUID):
            raise TypeError("event_id deve ser um UUID.")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name do evento deve ser uma string não vazia.")
        if (
            not isinstance(self.timestamp_utc, datetime)
            or self.timestamp_utc.tzinfo is None
            or self.timestamp_utc.utcoffset() != timedelta(0)
        ):
            raise ValueError("timestamp_utc do evento deve estar em UTC.")
        if not isinstance(self.payload, Mapping):
            raise TypeError("payload deve ser um mapping.")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(
            self, "payload", MappingProxyType(dict(self.payload))
        )


class DuplicateEventError(ValueError):
    """Raised when an event ID is published more than once on this bus."""


EventHandler = Callable[[Event], None]


class EventBus:
    def __init__(self) -> None:
        self._lock = RLock()
        self._event_ids: set[UUID] = set()
        self._history: list[Event] = []
        self._subscribers: list[tuple[str | None, EventHandler]] = []

    @property
    def history(self) -> tuple[Event, ...]:
        with self._lock:
            return tuple(self._history)

    def subscribe(
        self, handler: EventHandler, *, event_name: str | None = None
    ) -> None:
        if not callable(handler):
            raise TypeError("handler deve ser chamável.")
        if event_name is not None and (
            not isinstance(event_name, str) or not event_name.strip()
        ):
            raise ValueError("event_name deve ser None ou uma string não vazia.")
        normalized_name = event_name.strip() if event_name is not None else None
        with self._lock:
            subscription = (normalized_name, handler)
            if any(
                name == normalized_name and existing is handler
                for name, existing in self._subscribers
            ):
                raise ValueError("Esta inscrição de evento já existe.")
            self._subscribers.append(subscription)

    def unsubscribe(
        self, handler: EventHandler, *, event_name: str | None = None
    ) -> None:
        normalized_name = event_name.strip() if event_name is not None else None
        with self._lock:
            for index, (name, existing) in enumerate(self._subscribers):
                if name == normalized_name and existing is handler:
                    del self._subscribers[index]
                    return
        raise KeyError("Inscrição de evento não encontrada.")

    def publish(self, event: Event) -> None:
        if not isinstance(event, Event):
            raise TypeError("publish exige um Event.")
        with self._lock:
            if event.event_id in self._event_ids:
                raise DuplicateEventError(
                    f"Evento já publicado: {event.event_id}."
                )
            self._event_ids.add(event.event_id)
            self._history.append(event)
            subscribers = tuple(self._subscribers)

        try:
            for event_name, handler in subscribers:
                if event_name is None or event_name == event.name:
                    handler(event)
        except BaseException:
            with self._lock:
                self._event_ids.discard(event.event_id)
                self._history = [
                    published
                    for published in self._history
                    if published.event_id != event.event_id
                ]
            raise
