import datetime as dt

from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class UTCDateTime(TypeDecorator):
    """DateTime that round-trips as tz-aware UTC regardless of backend.

    SQLite has no native timezone-aware storage — a plain
    DateTime(timezone=True) silently comes back tz-naive after a round trip,
    which breaks comparisons against tz-aware `utcnow()` values. This type
    normalizes to UTC on the way in and re-attaches UTC tzinfo on the way
    out, so callers never have to think about it. Harmless (a no-op) on a
    backend that does preserve tzinfo natively, e.g. Postgres.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: dt.datetime | None, dialect) -> dt.datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc)

    def process_result_value(self, value: dt.datetime | None, dialect) -> dt.datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
