"""Command-line entry point: python -m soc_auth_analyzer --file data/<file>.csv"""

import argparse

from .detections import run_all
from .loader import load_events
from .report import build_summary, render_report, write_outputs

DEFAULT_FILE = "data/small_company_authentication_events.csv"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Analyse Windows authentication events (4624/4625) from a CSV file."
    )
    parser.add_argument("--file", default=DEFAULT_FILE, help="path to the CSV file")
    parser.add_argument("--output-dir", default="output", help="where to write the report")

    parser.add_argument("--bf-threshold", type=int, default=5,
                        help="failed logons (same account + IP) to flag brute force")
    parser.add_argument("--bf-window", type=int, default=5,
                        help="brute force time window in minutes")
    parser.add_argument("--spray-users", type=int, default=5,
                        help="distinct accounts from one IP to flag password spraying")
    parser.add_argument("--spray-window", type=int, default=10,
                        help="password spraying time window in minutes")
    parser.add_argument("--sf-failures", type=int, default=5,
                        help="failures before a success to flag a possible compromise")
    parser.add_argument("--sf-window", type=int, default=10,
                        help="success-after-failures time window in minutes")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    params = {
        "bf_threshold": args.bf_threshold,
        "bf_window": args.bf_window,
        "spray_users": args.spray_users,
        "spray_window": args.spray_window,
        "sf_failures": args.sf_failures,
        "sf_window": args.sf_window,
    }

    result = load_events(args.file)
    if not result.events:
        print("No valid events found in the file.")
        return 1

    findings = run_all(result.events, params)
    summary = build_summary(result.events)
    report = render_report(summary, findings, result.rejected, result.warnings, params)
    report_path, csv_path = write_outputs(args.output_dir, report, findings)

    print(report)
    print(f"\nSaved: {report_path}\nSaved: {csv_path}")
    return 0
