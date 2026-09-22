from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

IST_TIMEZONE = ZoneInfo("Asia/Kolkata")


def now_utc() -> datetime:
    """Return current timezone-aware UTC datetime.
    
    This is the single centralized authority for generating current timestamps
    across the CYBER-14 backend to eliminate naive datetime ambiguity.
    """
    return datetime.now(timezone.utc)


def utc_now() -> datetime:
    """Backwards-compatible alias for now_utc()."""
    return now_utc()


def format_iso_utc(dt: datetime | None) -> str | None:
    """Format a datetime into standard ISO-8601 UTC string with trailing 'Z'.
    
    Guarantees that frontend and external clients explicitly know the timestamp
    is in UTC (e.g., '2026-09-22T02:51:45Z'), preventing browsers from misinterpreting
    database values as local naive time.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso_to_utc(val: Any) -> datetime | None:
    """Parse string, timestamp, or datetime into a timezone-aware UTC datetime."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(val, tz=timezone.utc)
    if isinstance(val, str):
        cleaned = val.strip()
        if not cleaned:
            return None
        # Handle space-separated SQL datetimes
        if " " in cleaned and "T" not in cleaned:
            cleaned = cleaned.replace(" ", "T")
        # Ensure trailing Z is converted to +00:00 for fromisoformat
        if cleaned.endswith("Z") or cleaned.endswith("z"):
            cleaned = cleaned[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(cleaned)
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


def to_ist(dt: datetime | None) -> datetime | None:
    """Convert a UTC or naive datetime into India Standard Time (Asia/Kolkata)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST_TIMEZONE)


def format_ist(dt: datetime | None) -> str | None:
    """Format a UTC datetime as a human-readable string in India Standard Time."""
    ist_dt = to_ist(dt)
    if ist_dt is None:
        return None
    return ist_dt.strftime("%d %b %Y, %I:%M:%S %p IST")
