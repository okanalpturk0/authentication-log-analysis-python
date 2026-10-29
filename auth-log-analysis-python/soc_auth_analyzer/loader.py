"""Read the authentication CSV, validate each row and turn it into Event objects."""

import csv
from dataclasses import dataclass
from datetime import datetime

from .patterns import (
    FAILED_EVENT_ID,
    INTERNAL_IP,
    IPV4,
    SUCCESS_EVENT_ID,
    TIMESTAMP,
)

REQUIRED_COLUMNS = {
    "timestamp",
    "username",
    "source_ip",
    "status",
    "event_id",
    "message",
    "hostname",
    "auth_method",
    "mfa_result",
}


@dataclass(frozen=True)
class Event:
    line: int  # line number in the CSV file (header is line 1)
    raw_time: str
    time: datetime
    username: str
    source_ip: str
    status: str
    event_id: str
    message: str
    hostname: str
    auth_method: str
    mfa_result: str

    @property
    def is_failed(self) -> bool:
        return bool(FAILED_EVENT_ID.match(self.event_id))

    @property
    def is_success(self) -> bool:
        return bool(SUCCESS_EVENT_ID.match(self.event_id))

    @property
    def is_internal(self) -> bool:
        return bool(INTERNAL_IP.match(self.source_ip))


# Which status value each Windows event ID should come with.
EXPECTED_STATUS = {"4625": "failed", "4624": "success"}


@dataclass
class LoadResult:
    events: list
    rejected: list  # rows that were NOT analysed: (line_number, reason)
    warnings: list  # rows that were analysed but look inconsistent: (line_number, reason)


def load_events(path: str) -> LoadResult:
    """Open the CSV, validate every row with regex and return the clean events.

    Rows with a malformed timestamp (including impossible calendar dates such
    as 2026-02-31) or a malformed IP address are not analysed; they are
    reported in `rejected` so data-quality problems stay visible.

    Rows whose `status` contradicts their `event_id` are still analysed (the
    event ID is the authoritative Windows field) but are listed in `warnings`.
    """
    events, rejected, warnings = [], [], []

    with open(path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)

        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing required columns: {sorted(missing)}")

        for line_number, row in enumerate(reader, start=2):
            if not TIMESTAMP.match(row["timestamp"]):
                rejected.append((line_number, f"bad timestamp: {row['timestamp']!r}"))
                continue
            if not IPV4.match(row["source_ip"]):
                rejected.append((line_number, f"bad source_ip: {row['source_ip']!r}"))
                continue

            # The regex checks the format, but only datetime knows the calendar
            # (for example, there is no February 31st).
            try:
                parsed_time = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                rejected.append((line_number, f"impossible date: {row['timestamp']!r}"))
                continue

            event_id = row["event_id"].strip()
            status = row["status"].strip().lower()
            expected_status = EXPECTED_STATUS.get(event_id)
            if expected_status is None:
                warnings.append((line_number, f"unknown event_id {event_id!r}"))
            elif status != expected_status:
                warnings.append(
                    (line_number, f"status {status!r} does not match event_id {event_id}")
                )

            events.append(
                Event(
                    line=line_number,
                    raw_time=row["timestamp"],
                    time=parsed_time,
                    username=row["username"].strip().lower(),
                    source_ip=row["source_ip"],
                    status=status,
                    event_id=event_id,
                    message=row["message"],
                    hostname=row["hostname"],
                    auth_method=row["auth_method"],
                    mfa_result=row["mfa_result"],
                )
            )

    events.sort(key=lambda e: e.time)
    return LoadResult(events=events, rejected=rejected, warnings=warnings)
