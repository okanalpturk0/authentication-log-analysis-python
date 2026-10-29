"""Tests: regex patterns, window logic on synthetic data, and the real dataset.

The real-dataset tests check that the Python results match the numbers found
earlier in Splunk (README of the Splunk project).
"""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from soc_auth_analyzer.detections import (
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_failures,
)
from soc_auth_analyzer.loader import Event, load_events
from soc_auth_analyzer.patterns import IPV4, INTERNAL_IP, OFF_HOURS, TIMESTAMP, classify_failure

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "small_company_authentication_events.csv"


# --- helpers -----------------------------------------------------------------


def make_event(offset_seconds, username="alice", ip="203.0.113.50", failed=True):
    base = datetime(2026, 10, 20, 10, 0, 0)
    t = base + timedelta(seconds=offset_seconds)
    return Event(
        line=0,
        raw_time=t.strftime("%Y-%m-%d %H:%M:%S"),
        time=t,
        username=username,
        source_ip=ip,
        status="failed" if failed else "success",
        event_id="4625" if failed else "4624",
        message="Incorrect password" if failed else "Interactive sign-in successful",
        hostname="WS-TEST-01",
        auth_method="password",
        mfa_result="not_required",
    )


# --- regex patterns ----------------------------------------------------------


@pytest.mark.parametrize("ip", ["10.20.0.35", "203.0.113.77", "255.255.255.255", "0.0.0.0"])
def test_ipv4_accepts_valid(ip):
    assert IPV4.match(ip)


@pytest.mark.parametrize("ip", ["256.1.1.1", "10.20.0", "10.20.0.1.5", "abc.def.ghi.jkl", "", "01.2.3.4"])
def test_ipv4_rejects_invalid(ip):
    assert not IPV4.match(ip)


def test_timestamp_pattern():
    assert TIMESTAMP.match("2026-10-19 05:36:08")
    assert not TIMESTAMP.match("2026-13-19 05:36:08")
    assert not TIMESTAMP.match("2026-10-19T05:36:08")
    assert not TIMESTAMP.match("2026-10-19 25:00:00")


def test_internal_ip_pattern():
    assert INTERNAL_IP.match("10.20.0.99")
    assert not INTERNAL_IP.match("10.20.1.99")
    assert not INTERNAL_IP.match("203.0.113.12")


@pytest.mark.parametrize(
    "stamp, expected",
    [
        ("2026-10-21 02:13:00", True),
        ("2026-10-23 23:48:10", True),
        ("2026-10-21 05:59:59", True),
        ("2026-10-21 06:00:00", False),
        ("2026-10-21 12:00:00", False),
        ("2026-10-21 21:59:59", False),
    ],
)
def test_off_hours_pattern(stamp, expected):
    assert bool(OFF_HOURS.match(stamp)) is expected


def test_classify_failure():
    assert classify_failure("Incorrect password") == "Wrong password"
    assert classify_failure("MFA challenge failed") == "MFA failure"
    assert classify_failure("Authentication failure from shared source across accounts") == "Shared source across accounts"
    assert classify_failure("something new") == "Other"


# --- detection logic on synthetic data --------------------------------------


def test_brute_force_triggers_on_fast_burst():
    events = [make_event(i * 10) for i in range(6)]  # 6 failures in 50 seconds
    findings = detect_brute_force(events, threshold=5, window_minutes=5)
    assert len(findings) == 1
    assert findings[0].event_count == 6


def test_brute_force_ignores_slow_failures():
    events = [make_event(i * 3600) for i in range(6)]  # one failure per hour
    assert detect_brute_force(events, threshold=5, window_minutes=5) == []


def test_brute_force_needs_same_account_and_ip():
    events = [make_event(i * 10, username=f"user{i}") for i in range(6)]
    assert detect_brute_force(events, threshold=5, window_minutes=5) == []


def test_spraying_triggers_on_many_accounts():
    events = [make_event(i * 9, username=f"user{i}") for i in range(6)]
    findings = detect_password_spraying(events, min_users=5, window_minutes=10)
    assert len(findings) == 1
    assert len(findings[0].usernames) == 6


def test_spraying_ignores_single_account():
    events = [make_event(i * 9) for i in range(10)]
    assert detect_password_spraying(events, min_users=5, window_minutes=10) == []


def test_success_after_failures_is_critical():
    events = [make_event(i * 5) for i in range(6)] + [make_event(40, failed=False)]
    findings = detect_success_after_failures(events, min_failures=5, window_minutes=10)
    assert len(findings) == 1
    assert findings[0].severity == "Critical"


def test_success_without_failures_is_not_flagged():
    events = [make_event(0, failed=False)]
    assert detect_success_after_failures(events) == []


# --- loader validation --------------------------------------------------------

CSV_HEADER = (
    "timestamp,username,source_ip,event_type,status,hostname,event_id,message,"
    "department,auth_method,mfa_result,source_type,dataset\n"
)


def write_csv(tmp_path, *rows):
    path = tmp_path / "events.csv"
    path.write_text(CSV_HEADER + "".join(row + "\n" for row in rows), encoding="utf-8")
    return str(path)


def csv_row(timestamp="2026-10-20 10:00:00", ip="10.20.0.5", status="success", event_id="4624"):
    return (
        f"{timestamp},alice,{ip},authentication,{status},WS-TEST-01,{event_id},"
        "msg,IT,password,not_required,windows_security,test"
    )


def test_impossible_calendar_date_is_rejected_not_crash(tmp_path):
    path = write_csv(
        tmp_path,
        csv_row(),
        csv_row(timestamp="2026-02-31 10:00:00"),  # passes the regex, not a real date
        csv_row(timestamp="2026-04-31 10:00:00"),
    )
    result = load_events(path)
    assert len(result.events) == 1
    assert [line for line, _ in result.rejected] == [3, 4]
    assert all("impossible date" in reason for _, reason in result.rejected)


def test_bad_format_and_bad_ip_are_rejected(tmp_path):
    path = write_csv(
        tmp_path,
        csv_row(timestamp="20/10/2026 10:00"),
        csv_row(ip="300.1.1.1"),
        csv_row(),
    )
    result = load_events(path)
    assert len(result.events) == 1
    assert len(result.rejected) == 2


def test_status_event_id_mismatch_gives_warning(tmp_path):
    path = write_csv(
        tmp_path,
        csv_row(status="success", event_id="4625"),  # contradiction
        csv_row(status="failed", event_id="4625"),  # consistent
        csv_row(status="success", event_id="4672"),  # unknown event id
    )
    result = load_events(path)
    assert len(result.events) == 3  # warnings do not drop rows
    assert [line for line, _ in result.warnings] == [2, 4]
    assert "does not match" in result.warnings[0][1]
    assert "unknown event_id" in result.warnings[1][1]
    assert result.events[0].is_failed  # event_id is the authoritative field


def test_missing_column_raises(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("timestamp,username\n2026-10-20 10:00:00,alice\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required columns"):
        load_events(str(path))


# --- real dataset: must match the Splunk investigation -----------------------


@pytest.fixture(scope="module")
def real_events():
    result = load_events(str(DATA_FILE))
    assert result.rejected == []
    assert result.warnings == []
    return result.events


def test_dataset_totals_match_splunk(real_events):
    assert len(real_events) == 1200
    assert sum(e.is_success for e in real_events) == 1072
    assert sum(e.is_failed for e in real_events) == 128


def test_password_spraying_matches_splunk(real_events):
    findings = detect_password_spraying(real_events)
    assert len(findings) == 1
    assert findings[0].source_ip == "203.0.113.77"
    assert len(findings[0].usernames) == 16
    assert findings[0].event_count == 16


def test_brute_force_matches_splunk(real_events):
    found = {(f.usernames[0], f.source_ip): f.event_count for f in detect_brute_force(real_events)}
    assert found == {
        ("charlie", "198.51.100.24"): 18,
        ("dana", "192.0.2.44"): 14,
        ("bob", "192.0.2.88"): 8,
    }


def test_possible_compromise_is_charlie(real_events):
    findings = detect_success_after_failures(real_events)
    assert len(findings) == 1
    assert findings[0].usernames == ["charlie"]
    assert findings[0].source_ip == "198.51.100.24"
