"""Read the CSV, validate every row and turn it into Event objects.

v1 origin
---------
v1 did this in three places:

    read_lines()   open + read + split("\\n"), dropping the header with lines[1:]
    line.split(",")  then fields[0], fields[1], fields[4] by position
    find_ip() / find_time()  regex over the raw line

That works until a column is added or reordered, or a message contains a
comma. v2 uses csv.DictReader so columns are read by *name*, validates each
row, and keeps bad rows visible in the report instead of crashing or silently
miscounting.
"""

import csv
from dataclasses import dataclass
from datetime import datetime

from .patterns import FAILED_EVENT_ID, INTERNAL_IP, IPV4, SUCCESS_EVENT_ID, TIMESTAMP

REQUIRED_COLUMNS = {
    "timestamp", "username", "source_ip", "status", "event_id",
    "message", "hostname", "auth_method", "mfa_result",
}

# The status text each Windows event ID should come with.
EXPECTED_STATUS = {"4625": "failed", "4624": "success"}


@dataclass(frozen=True)
class Event:
    """One authentication event. v1 kept these as loose strings and lists."""

    line: int          # line number in the CSV (header = line 1)
    raw_time: str      # original timestamp text (used by the OFF_HOURS pattern)
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


@dataclass
class LoadResult:
    events: list    # valid events, sorted by time
    rejected: list  # rows NOT analysed: (line_number, reason)
    warnings: list  # rows analysed but inconsistent: (line_number, reason)


def load_events(path: str) -> LoadResult:
    """Load and validate the CSV.

    * bad timestamp / impossible date / bad IP  -> rejected (not analysed)
    * status contradicts event_id               -> warning (still analysed)
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

            # The regex checks the shape; only datetime knows the calendar.
            try:
                parsed_time = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                rejected.append((line_number, f"impossible date: {row['timestamp']!r}"))
                continue

            event_id = row["event_id"].strip()
            status = row["status"].strip().lower()
            expected = EXPECTED_STATUS.get(event_id)
            if expected is None:
                warnings.append((line_number, f"unknown event_id {event_id!r}"))
            elif status != expected:
                warnings.append((line_number, f"status {status!r} does not match event_id {event_id}"))

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

    # v1 relied on the file already being in time order. v2 sorts explicitly,
    # because the time-window detections need it.
    events.sort(key=lambda e: e.time)
    return LoadResult(events=events, rejected=rejected, warnings=warnings)
