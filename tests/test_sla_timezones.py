from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from app.routers.tickets import calculate_due_date, PRIORITY_SLA_DAYS


@pytest.mark.parametrize("tz_name", ["UTC", "America/New_York", "Europe/Paris", "Asia/Kolkata"])
@pytest.mark.parametrize("priority", list(PRIORITY_SLA_DAYS.keys()))
def test_due_date_respects_sla_days_across_timezones(priority, tz_name):
    """Ensure SLA days are applied as exact 24-hour multiples regardless of timezone."""
    days = PRIORITY_SLA_DAYS[priority]
    try:
        tz = ZoneInfo(tz_name)
    except Exception as exc:
        pytest.skip(f"tzdata not available for timezone {tz_name}: {exc}")

    created = datetime(2026, 3, 1, 12, 0, tzinfo=tz)

    due = calculate_due_date(priority, created)

    # preserve tzinfo
    assert due.tzinfo == created.tzinfo

    delta = due - created
    assert delta.total_seconds() == days * 86400


def test_due_date_on_dst_transition_and_month_boundary():
    """Edge cases: DST forward transition and end-of-month crossing produce correct due dates."""
    # DST forward: US (spring forward) 2026-03-08 at 02:00 jumps to 03:00
    try:
        tz_ny = ZoneInfo("America/New_York")
    except Exception as exc:
        pytest.skip(f"tzdata not available for America/New_York: {exc}")
    created_dst = datetime(2026, 3, 8, 1, 30, tzinfo=tz_ny)
    due_dst = calculate_due_date("urgent", created_dst)

    assert due_dst.tzinfo == created_dst.tzinfo
    assert (due_dst - created_dst).total_seconds() == 1 * 86400

    # Month boundary: end of February -> early March
    try:
        tz_utc = ZoneInfo("UTC")
    except Exception as exc:
        pytest.skip(f"tzdata not available for UTC: {exc}")
    created_month = datetime(2026, 2, 27, 23, 0, tzinfo=tz_utc)
    due_month = calculate_due_date("high", created_month)  # high -> 3 days

    assert due_month.tzinfo == created_month.tzinfo
    assert due_month == created_month + timedelta(days=3)
    assert due_month.date().month == 3
