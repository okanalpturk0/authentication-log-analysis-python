"""Build the dataset summary and write the report files.

v1 origin
---------
v1 counted success_count / night_failed / external_failed while looping, then
built the report with `report = report + ...` and printed it. v2 separates the
two jobs: build_summary() computes the numbers, render_report() only formats
them, and write_outputs() saves a text report plus a machine-readable CSV.
"""

import csv
import os
from collections import Counter

from .patterns import OFF_HOURS, classify_failure


def build_summary(events):
    """The v1 counters (total, success, failed, external, night) plus a few more."""
    failed = [e for e in events if e.is_failed]
    return {
        "total": len(events),
        "success": sum(e.is_success for e in events),
        "failed": len(failed),
        "first": events[0].time,
        "last": events[-1].time,
        "external_failed": sum(not e.is_internal for e in failed),
        "off_hours_failed": sum(bool(OFF_HOURS.match(e.raw_time)) for e in failed),
        # New in v2:
        "reasons": Counter(classify_failure(e.message) for e in failed),
        "top_ips": Counter(e.source_ip for e in failed).most_common(5),
        "top_users": Counter(e.username for e in failed).most_common(5),
    }


def _row_issues(add, title, issues, limit=5):
    if not issues:
        return
    add(title)
    add("-" * 72)
    for line_number, reason in issues[:limit]:
        add(f"  line {line_number}: {reason}")
    if len(issues) > limit:
        add(f"  ... and {len(issues) - limit} more")
    add("")


def render_report(summary, findings, rejected, warnings, params):
    """Return the incident report as one string."""
    lines = []
    add = lines.append

    add("=" * 72)
    add("AUTHENTICATION LOG ANALYSIS - INCIDENT REPORT")
    add("=" * 72)
    add(f"Period analysed          : {summary['first']}  ->  {summary['last']}")
    add(f"Total events             : {summary['total']}")
    add(f"Successful (4624)        : {summary['success']}")
    add(f"Failed (4625)            : {summary['failed']}")
    add(f"Failed from external IPs : {summary['external_failed']}")
    add(f"Failed at night (22:00-05:59): {summary['off_hours_failed']}")
    add(f"Rows rejected by validation  : {len(rejected)}")
    add(f"Rows with consistency warnings: {len(warnings)}")
    add("")

    _row_issues(add, "REJECTED ROWS (not analysed)", rejected)
    _row_issues(add, "ROW WARNINGS (analysed, but inconsistent)", warnings)

    add("FAILURE REASONS")
    add("-" * 72)
    for reason, count in summary["reasons"].most_common():
        add(f"  {reason:<32}{count:>5}")
    add("")

    add("TOP FAILING SOURCE IPs")
    add("-" * 72)
    for ip, count in summary["top_ips"]:
        add(f"  {ip:<20}{count:>5}")
    add("")

    add("TOP FAILING ACCOUNTS")
    add("-" * 72)
    for user, count in summary["top_users"]:
        add(f"  {user:<20}{count:>5}")
    add("")

    add(f"FINDINGS ({len(findings)})")
    add("=" * 72)
    for number, f in enumerate(findings, start=1):
        accounts = ", ".join(f.usernames)
        if len(accounts) > 60:
            accounts = f"{len(f.usernames)} accounts"
        add(f"[{number}] {f.severity.upper()} | {f.rule} | MITRE {f.mitre}")
        add(f"    {f.title}")
        add(f"    Source IP : {f.source_ip}")
        add(f"    Accounts  : {accounts}")
        add(f"    Time      : {f.first_seen}  ->  {f.last_seen}  ({f.event_count} events)")
        add(f"    Details   : {f.details}")
        add(f"    Action    : {f.recommendation}")
        add("")

    add("PARAMETERS USED")
    add("-" * 72)
    for name, value in params.items():
        add(f"  {name:<14}{value}")
    add("")
    add("Note: findings are leads for investigation, not confirmed incidents.")
    return "\n".join(lines)


def write_outputs(output_dir, report_text, findings):
    """Write incident_report.txt and findings.csv. Returns both paths."""
    os.makedirs(output_dir, exist_ok=True)

    report_path = os.path.join(output_dir, "incident_report.txt")
    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write(report_text + "\n")

    csv_path = os.path.join(output_dir, "findings.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(
            ["severity", "rule", "mitre", "source_ip", "accounts", "event_count",
             "first_seen", "last_seen", "title", "details", "recommendation"]
        )
        for f in findings:
            writer.writerow(
                [f.severity, f.rule, f.mitre, f.source_ip, ";".join(f.usernames),
                 f.event_count, f.first_seen, f.last_seen, f.title, f.details,
                 f.recommendation]
            )

    return report_path, csv_path
