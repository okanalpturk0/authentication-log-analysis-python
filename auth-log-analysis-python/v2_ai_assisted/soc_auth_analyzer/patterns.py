"""Every regular expression used by the analyzer, kept in one place.

v1 origin
---------
v1 used three small regex ideas, scattered through the script:

    find_ip():    re.findall(r"\\d+\\.\\d+\\.\\d+\\.\\d+", line)   -> first IP anywhere in the line
    find_time():  re.findall(r"\\d\\d:\\d\\d:\\d\\d", line)         -> first time anywhere in the line
    is_internal(): ip[0:8] == "10.20.0."                         -> slicing instead of a pattern

Searching the whole raw line worked on this dataset, but it would pick the
wrong value if another column ever contained something IP-like or time-like.
v2 reads each column by name and uses anchored patterns to *validate* the
value of that one column instead.
"""

import re

# --- Field validation (used by loader.py) -----------------------------------

# v1: r"\d+\.\d+\.\d+\.\d+" accepted things like 999.1.1.1.
# v2: each octet must be 0-255, and the pattern is anchored to the whole value.
IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)

# "YYYY-MM-DD HH:MM:SS" with valid month/day/hour/minute/second ranges.
# (The regex cannot know that February has no 31st; loader.py uses datetime for that.)
TIMESTAMP = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]) "
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d$"
)

# --- Event filtering ---------------------------------------------------------

# Windows Security event IDs. v1 decided by the text in the `status` column;
# v2 treats the event ID as the authoritative field and only *warns* when the
# two disagree.
FAILED_EVENT_ID = re.compile(r"^4625$")
SUCCESS_EVENT_ID = re.compile(r"^4624$")

# v1: is_internal() sliced the first 8 characters. Same network, now a pattern.
INTERNAL_IP = re.compile(r"^10\.20\.0\.\d{1,3}$")

# v1: night_hours = ["22", "23", "00", ..., "05"] and a membership test on the
# hour string. v2: one pattern that matches 22:00-05:59 on the raw timestamp.
OFF_HOURS = re.compile(r"^\S+ (?:2[2-3]|0[0-5]):")

# --- Failure reason labels ---------------------------------------------------
# New in v2 (v1 only counted failures). Used for the report summary only,
# never as detection evidence: real attackers do not label their own activity.
# Order matters: the first matching pattern wins.
FAILURE_REASONS = {
    "MFA failure": re.compile(r"\bMFA\b.*\bfailed\b", re.IGNORECASE),
    "Shared source across accounts": re.compile(r"shared source across accounts", re.IGNORECASE),
    "Unusual source": re.compile(r"unusual source", re.IGNORECASE),
    "Repeated failures": re.compile(r"\brepeated\b", re.IGNORECASE),
    "Isolated failure": re.compile(r"\bisolated\b", re.IGNORECASE),
    "Wrong password": re.compile(r"incorrect password|mistyped password", re.IGNORECASE),
}


def classify_failure(message: str) -> str:
    """Return a short reason label for a failed-logon message."""
    for label, pattern in FAILURE_REASONS.items():
        if pattern.search(message):
            return label
    return "Other"
