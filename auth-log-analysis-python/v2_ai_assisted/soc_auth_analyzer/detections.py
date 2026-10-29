"""Detection rules. Each rule takes the event list and returns Finding objects.

v1 origin
---------
v1 had three detections, each written as nested loops over plain lists:

    streak_pairs / streak_counts   -> "CRITICAL | possible compromise"
    pairs + count loop             -> "HIGH | brute force"
    failed_ips + users loop        -> "HIGH | password spraying"

The *ideas* are unchanged in v2. What changed:

1. Time windows. v1 counted failures over the whole file, so 5 typos spread
   over 5 days looked the same as 5 failures in 2 minutes. v2 asks "how many
   in the BEST window of N minutes?", which is how brute force really looks.
2. Findings are objects, not strings, so the report and the CSV export can
   both be built from the same data (severity, MITRE ID, times, advice).
3. Dictionaries (defaultdict) replace the "if x not in list" + index() lookups.

The rules use behaviour only (counts, timing, distinct accounts). They never
use the free-text `message` column as evidence.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from .patterns import OFF_HOURS, classify_failure

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass(frozen=True)
class Finding:
    """One alert. v1 stored alerts as formatted strings like 'HIGH | brute force | ...'."""

    rule: str
    severity: str
    mitre: str
    title: str
    source_ip: str
    usernames: tuple
    event_count: int
    first_seen: datetime
    last_seen: datetime
    details: str
    recommendation: str


# --- helpers ------------------------------------------------------------------


def best_window(events, window, score):
    """Slide a time window over time-sorted events and keep the best one.

    `score(window_events)` decides what "best" means: the number of events
    (brute force) or the number of distinct usernames (password spraying).
    Returns (events_in_best_window, best_score).
    """
    best, best_score, left = [], 0, 0
    for right in range(len(events)):
        # Move the left edge forward until the window is short enough again.
        while events[right].time - events[left].time > window:
            left += 1
        current = events[left:right + 1]
        current_score = score(current)
        if current_score > best_score:
            best, best_score = current, current_score
    return best, best_score


def _seconds(burst):
    return int((burst[-1].time - burst[0].time).total_seconds())


def _off_hours_note(burst):
    if OFF_HOURS.match(burst[0].raw_time):
        return " Occurred outside business hours (22:00-05:59)."
    return ""


def _followup_note(events, ip, after):
    """New in v2: did the same IP log in successfully in the hour after the burst?"""
    limit = after + timedelta(hours=1)
    hits = [e for e in events if e.source_ip == ip and e.is_success and after <= e.time <= limit]
    if not hits:
        return "No successful logon from this IP in the following hour."
    users = ", ".join(sorted({e.username for e in hits}))
    return f"{len(hits)} successful logon(s) from this IP in the following hour (accounts: {users})."


# --- rules ----------------------------------------------------------------------


def detect_brute_force(events, threshold=5, window_minutes=5):
    """Many failures for ONE account from ONE IP.   (v1: 'HIGH | brute force')"""
    window = timedelta(minutes=window_minutes)

    # v1 built `pairs` with "if pair not in pairs" and re-scanned every failure
    # for each pair. A dictionary keyed by (user, ip) does it in one pass.
    by_pair = defaultdict(list)
    for e in events:
        if e.is_failed:
            by_pair[(e.username, e.source_ip)].append(e)

    findings = []
    for (username, ip), group in by_pair.items():
        burst, count = best_window(group, window, len)
        if count < threshold:
            continue

        external = not burst[0].is_internal
        reasons = Counter(classify_failure(e.message) for e in burst)
        mfa = Counter(e.mfa_result for e in burst)
        findings.append(
            Finding(
                rule="brute_force",
                severity="High" if (external or count >= 10) else "Medium",
                mitre="T1110.001",
                title=f"Repeated failed logons for '{username}' from {ip}",
                source_ip=ip,
                usernames=(username,),
                event_count=count,
                first_seen=burst[0].time,
                last_seen=burst[-1].time,
                details=(
                    f"{count} failed logons in {_seconds(burst)}s "
                    f"({'external' if external else 'internal'} source). "
                    f"MFA results: {dict(mfa)}. Failure reasons: {dict(reasons)}. "
                    + _followup_note(events, ip, burst[-1].time)
                    + _off_hours_note(burst)
                ),
                recommendation=(
                    "Verify with the user; consider blocking the source IP and "
                    "forcing a password reset if the activity is not legitimate."
                ),
            )
        )
    return findings


def detect_password_spraying(events, min_users=5, window_minutes=10):
    """ONE IP failing against MANY accounts.   (v1: 'HIGH | password spraying')"""
    window = timedelta(minutes=window_minutes)

    by_ip = defaultdict(list)
    for e in events:
        if e.is_failed:
            by_ip[e.source_ip].append(e)

    findings = []
    for ip, group in by_ip.items():
        burst, users_hit = best_window(group, window, lambda b: len({e.username for e in b}))
        if users_hit < min_users:
            continue

        external = not burst[0].is_internal
        findings.append(
            Finding(
                rule="password_spraying",
                severity="High" if external else "Medium",
                mitre="T1110.003",
                title=f"Possible password spraying from {ip}",
                source_ip=ip,
                usernames=tuple(sorted({e.username for e in burst})),
                event_count=len(burst),
                first_seen=burst[0].time,
                last_seen=burst[-1].time,
                details=(
                    f"{len(burst)} failed logons against {users_hit} different accounts "
                    f"in {_seconds(burst)}s ({'external' if external else 'internal'} source). "
                    + _followup_note(events, ip, burst[-1].time)
                    + _off_hours_note(burst)
                ),
                recommendation=(
                    "Block or rate-limit the source IP, review the targeted accounts "
                    "for any later successful logon, and consider enforcing MFA."
                ),
            )
        )
    return findings


def detect_success_after_failures(events, min_failures=5, window_minutes=10):
    """A success right after a run of failures (same account + IP).

    v1: the streak_pairs / streak_counts lists, reported as
    'CRITICAL | possible compromise'. v2 keeps the same reset-on-success
    behaviour but only counts failures inside the time window.
    """
    window = timedelta(minutes=window_minutes)
    recent_failures = defaultdict(list)  # (username, ip) -> failed events
    findings = []

    for e in events:  # time-sorted by the loader
        key = (e.username, e.source_ip)
        if e.is_failed:
            recent_failures[key].append(e)
            continue
        if not e.is_success:
            continue

        failures = [f for f in recent_failures[key] if e.time - f.time <= window]
        if len(failures) >= min_failures:
            gap = int((e.time - failures[-1].time).total_seconds())
            findings.append(
                Finding(
                    rule="success_after_failures",
                    severity="Critical",
                    mitre="T1110 / T1078",
                    title=f"Successful logon for '{e.username}' after repeated failures from {e.source_ip}",
                    source_ip=e.source_ip,
                    usernames=(e.username,),
                    event_count=len(failures) + 1,
                    first_seen=failures[0].time,
                    last_seen=e.time,
                    details=(
                        f"{len(failures)} failed logons were followed by a successful one "
                        f"{gap}s later. The successful logon used auth_method="
                        f"'{e.auth_method}', mfa_result='{e.mfa_result}' on {e.hostname}."
                        + _off_hours_note([e])
                    ),
                    recommendation=(
                        "Treat the account as potentially compromised: reset the password, "
                        "revoke active sessions, review activity after the logon, and "
                        "block the source IP."
                    ),
                )
            )
        # Same as v1's `streak_counts[position] = 0`: a success ends the streak.
        recent_failures[key] = []

    return findings


def run_all(events, params):
    """Run every rule; sort by severity, then time. (v1 sorted alert strings alphabetically.)"""
    findings = []
    findings += detect_brute_force(events, params["bf_threshold"], params["bf_window"])
    findings += detect_password_spraying(events, params["spray_users"], params["spray_window"])
    findings += detect_success_after_failures(events, params["sf_failures"], params["sf_window"])
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen))
    return findings
