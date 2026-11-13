"""Sri Lanka display time; stored application timestamps remain in UTC."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

SRI_LANKA_TIME = timezone(timedelta(hours=5, minutes=30), name='SLST')
TIMEZONE_LABEL = 'SLST (GMT+05:30)'


def to_sri_lanka_time(value) -> datetime | None:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    # SQLite strips timezone information from DateTime fields. Those fields
    # are written in UTC by utcnow(), not in the server's local timezone.
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(SRI_LANKA_TIME)


def format_sri_lanka_time(value, pattern='%d %b %Y, %I:%M %p', show_zone=True) -> str:
    local = to_sri_lanka_time(value)
    if local is None:
        return 'Unavailable'
    text = local.strftime(pattern)
    return f'{text} {TIMEZONE_LABEL}' if show_zone else text


def sri_lanka_isoformat(value) -> str | None:
    local = to_sri_lanka_time(value)
    return local.isoformat(timespec='seconds') if local is not None else None


def sri_lanka_day_window(days=7, *, now=None):
    """Local calendar labels and their UTC lower bound for database queries."""
    local_now = to_sri_lanka_time(now or datetime.now(timezone.utc))
    start = local_now.date() - timedelta(days=days - 1)
    lower_bound = datetime.combine(start, datetime.min.time(), SRI_LANKA_TIME).astimezone(timezone.utc)
    labels = [(start + timedelta(days=offset)).isoformat() for offset in range(days)]
    return lower_bound, labels
