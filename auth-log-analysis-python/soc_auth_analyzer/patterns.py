"""All regular expressions used by the analyzer, in one place.

Keeping the patterns together makes them easy to read, explain and test.
"""

import re

# --- Field validation (used by the loader) ---------------------------------

# Dotted-quad IPv4 with each octet limited to 0-255 (no leading zeros).
IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)

# "YYYY-MM-DD HH:MM:SS" with a valid month, day, hour, minute and second range.
TIMESTAMP = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]) "
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d$"
)

# --- Event filtering --------------------------------------------------------

# Windows Security event IDs: 4625 = failed logon, 4624 = successful logon.
FAILED_EVENT_ID = re.compile(r"^4625$")
SUCCESS_EVENT_ID = re.compile(r"^4624$")

# The company's internal workstation network in this dataset.
INTERNAL_IP = re.compile(r"^10\.20\.0\.\d{1,3}$")

# Hours 22:00-05:59, matched against the raw timestamp string.
OFF_HOURS = re.compile(r"^\S+ (?:2[2-3]|0[0-5]):")

# --- Failure reason classification (order matters: first match wins) --------

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
