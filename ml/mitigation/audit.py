from datetime import datetime
from threading import Lock
from typing import Iterable
from uuid import uuid4

from ml.mitigation.models import AuditEvent


class AuditTrail:
    """In-memory, structured audit storage suitable for later evidence export."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = Lock()

    def record(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            self._events.append(event)
        return event

    def events(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def records(self) -> list[dict[str, object]]:
        return [event.to_record() for event in self.events()]


def new_event_id() -> str:
    return str(uuid4())


def make_timestamp(value: datetime) -> datetime:
    return value


def event_records(events: Iterable[AuditEvent]) -> list[dict[str, object]]:
    return [event.to_record() for event in events]
