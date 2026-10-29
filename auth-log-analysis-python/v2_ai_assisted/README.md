# v2: AI-assisted rewrite

A rewrite of [my v1 script](../v1_original/analyzer.py), built with AI
assistance. It keeps the v1 ideas (same detections, same counters) and adds
validation, time windows, structured findings, reports and tests.

## Usage

Requires Python 3.9+. The analyzer uses only the standard library.
Run these from the `v2_ai_assisted/` folder:

```bash
python -m soc_auth_analyzer
python -m soc_auth_analyzer --file ../data/small_company_authentication_events.csv --output-dir output
python -m soc_auth_analyzer --bf-threshold 10 --spray-users 8   # stricter thresholds
python -m soc_auth_analyzer --help
```

Run the tests:

```bash
pip install -r requirements.txt
python -m pytest
```

## How v1 maps to v2

| v1 (`analyzer.py`) | v2 |
|---|---|
| `read_lines()` and `line.split(",")` | `loader.py`: `csv.DictReader`, validation, `Event` objects |
| `find_ip()`, `find_time()` | `patterns.py`: anchored `IPV4` and `TIMESTAMP` patterns |
| `is_internal()` | `patterns.INTERNAL_IP`, `Event.is_internal` |
| `night_hours` list | `patterns.OFF_HOURS` |
| `threshold = 5`, `file_name` | command-line options in `cli.py` |
| `streak_pairs` / `streak_counts` | `detect_success_after_failures()` |
| brute force loop over `pairs` | `detect_brute_force()` with a sliding window |
| password spraying loop over `failed_ips` | `detect_password_spraying()` with a sliding window |
| `alerts` list of strings | `Finding` objects |
| `report = report + ...` | `report.py`: `build_summary()`, `render_report()`, `write_outputs()` |

## Detections

| Rule | Logic | Default | MITRE ATT&CK |
|---|---|---|---|
| `brute_force` | many failures, one account, one IP | 5 failures in 5 min | T1110.001 |
| `password_spraying` | one IP failing against many accounts | 5 accounts in 10 min | T1110.003 |
| `success_after_failures` | success right after a run of failures (same account + IP) | 5 failures, success within 10 min | T1110 / T1078 |

The rules use behaviour only (counts, timing, distinct accounts). The free-text
`message` column is **not** used as evidence, because real attackers do not
label their own activity. It is only used to group failure reasons in the summary.

## What is new compared to v1

- **Validation:** regex checks the timestamp and IPv4 format, `datetime` rejects impossible dates such as `2026-02-31`, and rows whose `status` contradicts their `event_id` are flagged. Problems appear in the report instead of crashing the run.
- **Time windows:** a sliding window finds the densest burst, so slow, spread-out failures no longer trigger alerts.
- **Follow-up check:** each finding says whether the same IP had a successful logon in the following hour.
- **Context:** MFA results, failure reasons and off-hours activity are added to the details.
- **Outputs:** `output/incident_report.txt` (readable) and `output/findings.csv` (machine-friendly).

## Tests

`tests/test_analyzer.py` covers the regex patterns, the loader, the window
logic on synthetic events, and the real dataset. `TestV1Parity` runs the
untouched v1 script and checks that v2 reports the same counters and the same
alerts, so the two versions cannot drift apart unnoticed.

## Project structure

```
v2_ai_assisted/
├── soc_auth_analyzer/
│   ├── patterns.py     # all regular expressions
│   ├── loader.py       # read the CSV, validate rows, build Event objects
│   ├── detections.py   # brute force, password spraying, success-after-failures
│   ├── report.py       # summary, incident report, findings.csv
│   └── cli.py          # command-line interface (argparse)
├── tests/test_analyzer.py
└── output/             # generated reports
```

## Limitations

- The dataset is **synthetic**; the IPs belong to documentation ranges (RFC 5737).
- Thresholds were chosen for this dataset and would need tuning in a real environment.
- Only the best time window per account/IP pair (or per IP) is reported.
- Findings are leads for investigation, not confirmed incidents.

## Possible next steps

- Enrich IPs with threat intelligence (for example the AbuseIPDB API).
- Add detections for impossible travel and logons from rarely used hosts.
- Export findings in a SIEM-friendly format (JSON).
