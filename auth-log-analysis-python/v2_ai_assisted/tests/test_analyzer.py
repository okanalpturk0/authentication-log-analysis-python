"""Tests for the v2 analyzer.

The last class compares v2 against the original v1 script, which is the whole
point of keeping both versions in this repository.
"""

import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from soc_auth_analyzer.detections import (
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_failures,
    run_all,
)
from soc_auth_analyzer.loader import Event, load_events
from soc_auth_analyzer.patterns import (
    INTERNAL_IP, IPV4, OFF_HOURS, TIMESTAMP, classify_failure,
)
from soc_auth_analyzer.report import build_summary

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_FILE = REPO_ROOT / "data" / "small_company_authentication_events.csv"
V1_SCRIPT = REPO_ROOT / "v1_original" / "analyzer.py"

DEFAULT_PARAMS = {
    "bf_threshold": 5, "bf_window": 5,
    "spray_users": 5, "spray_window": 10,
    "sf_failures": 5, "sf_window": 10,
}
START = datetime(2026, 10, 20, 12, 0, 0)


def make_event(offset_seconds, username="alice", ip="203.0.113.9", failed=True):
    """Build a synthetic event `offset_seconds` after START."""
    when = START + timedelta(seconds=offset_seconds)
    return Event(
        line=0, raw_time=when.strftime("%Y-%m-%d %H:%M:%S"), time=when,
        username=username, source_ip=ip,
        status="failed" if failed else "success",
        event_id="4625" if failed else "4624",
        message="Incorrect password", hostname="WS-TEST-01",
        auth_method="password", mfa_result="not_required",
    )


# --- patterns (v1: find_ip, find_time, is_internal, night_hours) -----------------


class TestPatterns:
    def test_ipv4_accepts_valid(self):
        assert IPV4.match("10.20.0.35") and IPV4.match("203.0.113.77")

    @pytest.mark.parametrize("bad", ["999.1.1.1", "1.2.3", "1.2.3.4.5", "a.b.c.d", ""])
    def test_ipv4_rejects_invalid(self, bad):
        assert not IPV4.match(bad)

    def test_timestamp_format(self):
        assert TIMESTAMP.match("2026-10-19 05:36:08")
        assert not TIMESTAMP.match("2026-13-01 00:00:00")
        assert not TIMESTAMP.match("2026-10-19 25:00:00")

    def test_internal_ip(self):
        assert INTERNAL_IP.match("10.20.0.35")
        assert not INTERNAL_IP.match("10.21.0.35")
        assert not INTERNAL_IP.match("203.0.113.12")

    @pytest.mark.parametrize("hour,expected", [
        ("22", True), ("23", True), ("00", True), ("05", True),
        ("06", False), ("12", False), ("21", False),
    ])
    def test_off_hours_matches_v1_night_hours(self, hour, expected):
        assert bool(OFF_HOURS.match(f"2026-10-19 {hour}:30:00")) is expected

    def test_failure_classification(self):
        assert classify_failure("MFA challenge failed") == "MFA failure"
        assert classify_failure("Incorrect password") == "Wrong password"
        assert classify_failure("something new") == "Other"


# --- loader (v1: read_lines) -----------------------------------------------------

HEADER = ("timestamp,username,source_ip,event_type,status,hostname,event_id,"
          "message,department,auth_method,mfa_result,source_type,dataset\n")


def write_csv(tmp_path, *rows):
    path = tmp_path / "events.csv"
    path.write_text(HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    return str(path)


def row(ts="2026-10-19 08:00:00", user="alice", ip="10.20.0.5", status="success", event_id="4624"):
    return f"{ts},{user},{ip},authentication,{status},WS-1,{event_id},msg,IT,password,success,windows_security,x"


class TestLoader:
    def test_valid_row_loaded(self, tmp_path):
        result = load_events(write_csv(tmp_path, row()))
        assert len(result.events) == 1 and not result.rejected and not result.warnings

    def test_bad_rows_rejected_not_crashing(self, tmp_path):
        path = write_csv(tmp_path, row(), row(ts="2026-02-31 10:00:00"),
                         row(ip="999.1.1.1"), row(ts="not a time"))
        result = load_events(path)
        assert len(result.events) == 1
        assert len(result.rejected) == 3

    def test_status_event_id_mismatch_is_warning(self, tmp_path):
        result = load_events(write_csv(tmp_path, row(status="failed", event_id="4624")))
        assert len(result.events) == 1 and len(result.warnings) == 1

    def test_missing_column_raises(self, tmp_path):
        path = tmp_path / "bad.csv"
        path.write_text("timestamp,username\n2026-10-19 08:00:00,alice\n")
        with pytest.raises(ValueError):
            load_events(str(path))

    def test_events_sorted_by_time(self, tmp_path):
        path = write_csv(tmp_path, row(ts="2026-10-19 09:00:00"), row(ts="2026-10-19 08:00:00"))
        events = load_events(path).events
        assert events[0].time < events[1].time


# --- detections (v1: brute force / spraying / streak loops) ----------------------


class TestBruteForce:
    def test_five_failures_in_window_flagged(self):
        events = [make_event(i * 30) for i in range(5)]
        assert len(detect_brute_force(events)) == 1

    def test_four_failures_not_flagged(self):
        assert detect_brute_force([make_event(i * 30) for i in range(4)]) == []

    def test_failures_spread_over_days_not_flagged(self):
        """The main v1 limitation: v1 would have flagged this."""
        events = [make_event(i * 86400) for i in range(5)]
        assert detect_brute_force(events) == []

    def test_different_accounts_are_not_combined(self):
        events = [make_event(i * 10, username=f"user{i}") for i in range(5)]
        assert detect_brute_force(events) == []


class TestPasswordSpraying:
    def test_many_accounts_one_ip_flagged(self):
        events = [make_event(i * 20, username=f"user{i}") for i in range(6)]
        findings = detect_password_spraying(events)
        assert len(findings) == 1 and len(findings[0].usernames) == 6

    def test_same_account_repeated_is_not_spraying(self):
        assert detect_password_spraying([make_event(i * 10) for i in range(10)]) == []

    def test_accounts_spread_over_time_not_flagged(self):
        events = [make_event(i * 3600, username=f"user{i}") for i in range(6)]
        assert detect_password_spraying(events) == []


class TestSuccessAfterFailures:
    def test_success_after_streak_is_critical(self):
        events = [make_event(i * 10) for i in range(5)] + [make_event(60, failed=False)]
        findings = detect_success_after_failures(events)
        assert len(findings) == 1 and findings[0].severity == "Critical"

    def test_success_after_few_failures_ignored(self):
        events = [make_event(i * 10) for i in range(3)] + [make_event(60, failed=False)]
        assert detect_success_after_failures(events) == []

    def test_success_resets_the_streak(self):
        """Same behaviour as v1's streak_counts[position] = 0."""
        events = ([make_event(i * 10) for i in range(5)]
                  + [make_event(60, failed=False), make_event(70, failed=False)])
        assert len(detect_success_after_failures(events)) == 1

    def test_old_failures_outside_window_ignored(self):
        events = [make_event(i * 10) for i in range(5)] + [make_event(3600, failed=False)]
        assert detect_success_after_failures(events) == []


# --- real dataset -----------------------------------------------------------------


@pytest.fixture(scope="module")
def real_data():
    result = load_events(str(DATA_FILE))
    return result, run_all(result.events, DEFAULT_PARAMS)


class TestRealDataset:
    def test_totals_match_splunk_and_v1(self, real_data):
        summary = build_summary(real_data[0].events)
        assert (summary["total"], summary["success"], summary["failed"]) == (1200, 1072, 128)

    def test_no_rejected_rows(self, real_data):
        assert real_data[0].rejected == [] and real_data[0].warnings == []

    def test_expected_findings(self, real_data):
        """The same four leads found in the Splunk investigation and in v1."""
        findings = real_data[1]
        assert any(f.rule == "password_spraying" and f.source_ip == "203.0.113.77"
                   and len(f.usernames) == 16 for f in findings)
        for user, count in [("charlie", 18), ("dana", 14), ("bob", 8)]:
            assert any(f.rule == "brute_force" and f.usernames == (user,)
                       and f.event_count == count for f in findings), user

    def test_charlie_compromise_is_critical(self, real_data):
        critical = [f for f in real_data[1] if f.severity == "Critical"]
        assert len(critical) == 1 and critical[0].usernames == ("charlie",)


# --- v1 vs v2 -----------------------------------------------------------------------


class TestV1Parity:
    """Run the untouched v1 script and check that v2 reaches the same conclusions."""

    @pytest.fixture(scope="class")
    def v1_output(self, tmp_path_factory):
        workdir = tmp_path_factory.mktemp("v1run")
        shutil.copy(V1_SCRIPT, workdir / "analyzer.py")
        shutil.copy(DATA_FILE, workdir / DATA_FILE.name)
        done = subprocess.run([sys.executable, "analyzer.py"], cwd=workdir,
                              capture_output=True, text=True, check=True)
        return done.stdout

    def test_counters_match(self, v1_output, real_data):
        summary = build_summary(real_data[0].events)
        expected = {
            "Total events": summary["total"],
            "Successful logins": summary["success"],
            "Failed logins": summary["failed"],
            "Failed from external IPs": summary["external_failed"],
            "Failed at night (22:00-05:59)": summary["off_hours_failed"],
        }
        for label, value in expected.items():
            assert re.search(rf"{re.escape(label)}: {value}\b", v1_output), label

    def test_same_alerts_as_v1(self, v1_output, real_data):
        """Every v1 alert has a matching v2 finding (v2 may only add detail)."""
        v2 = real_data[1]
        for ip in re.findall(r"HIGH \| password spraying \| (\S+)", v1_output):
            assert any(f.rule == "password_spraying" and f.source_ip == ip for f in v2)
        for user, ip in re.findall(r"HIGH \| brute force \| (\w+) from (\S+)", v1_output):
            assert any(f.rule == "brute_force" and f.usernames == (user,) and f.source_ip == ip for f in v2)
        for user, ip in re.findall(r"CRITICAL \| possible compromise \| (\w+) logged in from (\S+)", v1_output):
            assert any(f.rule == "success_after_failures" and f.usernames == (user,) and f.source_ip == ip for f in v2)

    def test_alert_counts_match(self, v1_output, real_data):
        v1_count = int(re.search(r"ALERTS \((\d+)\)", v1_output).group(1))
        assert len(real_data[1]) == v1_count
