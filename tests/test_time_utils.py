from datetime import datetime, timezone

import pytest

from time_utils import format_sri_lanka_time, sri_lanka_day_window, sri_lanka_isoformat, to_sri_lanka_time


@pytest.mark.parametrize('value', [
    '2026-11-13T16:40:17+00:00',
    '2026-11-13T16:40:17Z',
    '2026-11-13 16:40:17',
    datetime(2026, 11, 13, 16, 40, 17),
    '2026-11-13T22:10:17+05:30',
])
def test_utc_sqlite_and_already_local_timestamps_display_the_same_instant(value):
    assert sri_lanka_isoformat(value) == '2026-11-13T22:10:17+05:30'
    assert format_sri_lanka_time(value) == '13 Nov 2026, 10:10 PM SLST (GMT+05:30)'


def test_conversion_rolls_the_calendar_date_after_local_midnight():
    local = to_sri_lanka_time('2026-11-13T18:45:00Z')
    assert (local.year, local.month, local.day, local.hour, local.minute) == (2026, 11, 14, 0, 15)


def test_date_only_profile_fields_use_the_local_month_at_month_boundary():
    assert format_sri_lanka_time('2026-01-31T20:00:00Z', '%B %Y', False) == 'February 2026'


@pytest.mark.parametrize('value', [None, '', 'invalid time'])
def test_missing_timestamps_do_not_display_a_fabricated_time(value):
    assert format_sri_lanka_time(value) == 'Unavailable'
    assert sri_lanka_isoformat(value) is None


def test_display_conversion_does_not_change_the_original_utc_timestamp():
    original = datetime(2026, 11, 13, 16, 40, tzinfo=timezone.utc)
    local = to_sri_lanka_time(original)
    assert local.hour == 22
    assert original.hour == 16
    assert original.tzinfo == timezone.utc


def test_chart_window_starts_at_local_midnight_and_returns_a_utc_query_boundary():
    lower, labels = sri_lanka_day_window(now=datetime(2026, 11, 13, 19, tzinfo=timezone.utc))
    assert labels == ['2026-11-08', '2026-11-09', '2026-11-10', '2026-11-11', '2026-11-12', '2026-11-13', '2026-11-14']
    assert lower == datetime(2026, 11, 7, 18, 30, tzinfo=timezone.utc)
