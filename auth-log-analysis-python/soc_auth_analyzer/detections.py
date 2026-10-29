"""Detection rules. Each rule takes the list of events and returns Findings.

The rules mirror the investigation done in Splunk, so the Python output can be
compared line by line with the SPL results.

Note: rules look at behaviour only (counts, timing, distinct accounts). They do
NOT use the descriptive `message` text as evidence, because real logs do not
tell you what the attacker is doing.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from .loader import Event
from .patterns import OFF_HOURS, classify_failure

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass
class Finding:
    rule: str
    severity: str
    mitre: str
    title: str
    source_ip: str
    usernames: list
    event_count: int
    first_seen: datetime
    last_seen: datetime
    details: str
    recommendation: str


# --- helpers ----------------------------------------------------------------


def _best_window(events, window, metric):
    """Slide a time window over time-sorted events.

    Returns (events_in_best_window, best_score), where the score is computed by
    `metric` (for example: number of events, or number of distinct usernames).
    """
    best, best_score, left = [], 0, 0
    for right in range(len(events)):
        while events[right].time - events[left].time > window:
            left += 1
        current = events[left : right + 1]
        score = metric(current)
        if score > best_score:
            best, best_score = current, score
    return best, best_score


def _logons_after(events, ip, after, hours=1):
    """Successful logons from `ip` within `hours` after the `after` time."""
    limit = after + timedelta(hours=hours)
    return [e for e in events if e.source_ip == ip and e.is_success and after <= e.time <= limit]


def _followup_text(events, ip, after):
    hits = _logons_after(events, ip, after)
    if not hits:
        return "No successful logon from this IP in the following hour."
    users = ", ".join(sorted({e.username for e in hits}))
    return f"{len(hits)} successful logon(s) from this IP in the following hour (accounts: {users})."


def _span_seconds(burst):
    return int((burst[-1].time - burst[0].time).total_seconds())


def _off_hours_text(burst):
    if OFF_HOURS.match(burst[0].raw_time):
        return " Occurred outside business hours (22:00-05:59)."
    return ""


# --- rules ------------------------------------------------------------------


def detect_brute_force(events, threshold=5, window_minutes=5):
    """Many failed logons for ONE account from ONE source IP in a short time."""
    window = timedelta(minutes=window_minutes)
    groups = defaultdict(list)
    for e in events:
        if e.is_failed:
            groups[(e.username, e.source_ip)].append(e)

    findings = []
    for (username, ip), group in groups.items():
        burst, count = _best_window(group, window, len)
        if count < threshold:
            continue

        external = not burst[0].is_internal
        severity = "High" if (external or count >= 10) else "Medium"
        reasons = Counter(classify_failure(e.message) for e in burst)
        mfa = Counter(e.mfa_result for e in burst)

        findings.append(
            Finding(
                rule="brute_force",
                severity=severity,
                mitre="T1110.001",
                title=f"Repeated failed logons for '{username}' from {ip}",
                source_ip=ip,
                usernames=[username],
                event_count=count,
                first_seen=burst[0].time,
                last_seen=burst[-1].time,
                details=(
                    f"{count} failed logons in {_span_seconds(burst)}s "
                    f"({'external' if external else 'internal'} source). "
                    f"MFA results: {dict(mfa)}. Failure reasons: {dict(reasons)}. "
                    + _followup_text(events, ip, burst[-1].time)
                    + _off_hours_text(burst)
                ),
                recommendation=(
                    "Verify with the user; consider blocking the source IP and "
                    "forcing a password reset if the activity is not legitimate."
                ),
            )
        )
    return findings


def detect_password_spraying(events, min_users=5, window_minutes=10):
    """ONE source IP failing against MANY different accounts in a short time."""
    window = timedelta(minutes=window_minutes)
    groups = defaultdict(list)
    for e in events:
        if e.is_failed:
            groups[e.source_ip].append(e)

    findings = []
    for ip, group in groups.items():
        burst, distinct_users = _best_window(group, window, lambda b: len({e.username for e in b}))
        if distinct_users < min_users:
            continue

        users = sorted({e.username for e in burst})
        external = not burst[0].is_internal
        findings.append(
            Finding(
                rule="password_spraying",
                severity="High" if external else "Medium",
                mitre="T1110.003",
                title=f"Possible password spraying from {ip}",
                source_ip=ip,
                usernames=users,
                event_count=len(burst),
                first_seen=burst[0].time,
                last_seen=burst[-1].time,
                details=(
                    f"{len(burst)} failed logons against {distinct_users} different accounts "
                    f"in {_span_seconds(burst)}s ({'external' if external else 'internal'} source). "
                    + _followup_text(events, ip, burst[-1].time)
                    + _off_hours_text(burst)
                ),
                recommendation=(
                    "Block or rate-limit the source IP, review the targeted accounts "
                    "for any later successful logon, and consider enforcing MFA."
                ),
            )
        )
    return findings


def detect_success_after_failures(events, min_failures=5, window_minutes=10):
    """A successful logon right after a run of failures for the same account + IP.

    This is the pattern that turns 'noisy' into 'possible compromise'.
    """
    window = timedelta(minutes=window_minutes)
    recent_failures = defaultdict(list)  # (username, ip) -> failed events
    findings = []

    for e in events:  # events are time-sorted
        key = (e.username, e.source_ip)
        if e.is_failed:
            recent_failures[key].append(e)
            continue
        if not e.is_success:
            continue

        failures = [f for f in recent_failures[key] if e.time - f.time <= window]
        if len(failures) >= min_failures:
            findings.append(
                Finding(
                    rule="success_after_failures",
                    severity="Critical",
                    mitre="T1110 / T1078",
                    title=f"Successful logon for '{e.username}' after repeated failures from {e.source_ip}",
                    source_ip=e.source_ip,
                    usernames=[e.username],
                    event_count=len(failures) + 1,
                    first_seen=failures[0].time,
                    last_seen=e.time,
                    details=(
                        f"{len(failures)} failed logons were followed by a successful one "
                        f"{int((e.time - failures[-1].time).total_seconds())}s later. "
                        f"The successful logon used auth_method='{e.auth_method}', "
                        f"mfa_result='{e.mfa_result}' on {e.hostname}."
                        + _off_hours_text([e])
                    ),
                    recommendation=(
                        "Treat the account as potentially compromised: reset the password, "
                        "revoke active sessions, review activity after the logon, and "
                        "block the source IP."
                    ),
                )
            )
        recent_failures[key] = []  # avoid re-alerting on the follow-up session

    return findings


def run_all(events, params):
    """Run every rule and return the findings sorted by severity, then time."""
    findings = []
    findings += detect_brute_force(events, params["bf_threshold"], params["bf_window"])
    findings += detect_password_spraying(events, params["spray_users"], params["spray_window"])
    findings += detect_success_after_failures(events, params["sf_failures"], params["sf_window"])
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen))
    return findings
