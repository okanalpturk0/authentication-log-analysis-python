# Authentication Log Analysis with Python

Python follow-up to my [Splunk authentication investigation](https://github.com/okanalpturk0/authentication-log-analysis-splunk).
It analyses the same synthetic dataset (1,200 Windows authentication events,
event IDs 4624 / 4625) and looks for brute force, password spraying and
possible account compromise.

This repository contains **two versions of the same tool**, on purpose.

## How this project was made

- **v1 (`v1_original/`)** is the script I wrote myself: one file, plain loops
  and lists, a few regular expressions. It is included exactly as I wrote it.
- **v2 (`v2_ai_assisted/`)** is a rewrite built **with AI assistance**. It keeps
  the ideas from v1 (same three detections, same counters) and restructures
  them into a small package with time windows, row validation, tests and
  report files. Each module explains which part of v1 it grew out of.

I kept both so the difference is visible: what I could do on my own, and what
changed when I used AI to take the same idea further.

## Repository layout

```
.
├── data/
│   └── small_company_authentication_events.csv   # shared synthetic dataset
├── v1_original/
│   ├── analyzer.py          # my original script (unchanged)
│   ├── report.txt           # its real output on the dataset
│   └── README.md
└── v2_ai_assisted/
    ├── soc_auth_analyzer/   # loader, patterns, detections, report, cli
    ├── tests/               # includes tests that compare v2 against v1
    ├── output/              # example incident_report.txt and findings.csv
    └── README.md
```

## Quick start

Requires Python 3.9+. Neither version needs third-party packages to run.

```bash
# v1
cd v1_original
python analyzer.py

# v2
cd v2_ai_assisted
python -m soc_auth_analyzer
```

## v1 vs v2

| | v1 (mine) | v2 (AI-assisted) |
|---|---|---|
| Structure | one script | package: `loader`, `patterns`, `detections`, `report`, `cli` |
| Reading the CSV | `split(",")`, columns by position | `csv.DictReader`, columns by name |
| Regex use | find first IP / time anywhere in the line | anchored patterns that validate each field |
| Bad rows | not handled (can crash) | rejected and listed in the report |
| Brute force | total failures per account + IP over the whole file | failures in a sliding time window (5 min) |
| Password spraying | distinct accounts per IP over the whole file | distinct accounts in a sliding window (10 min) |
| Possible compromise | success after a streak of failures | same idea, plus a time window |
| Alerts | formatted strings | `Finding` objects with severity, MITRE ID, times, advice |
| Output | `report.txt` | `incident_report.txt` and `findings.csv` |
| Settings | edit the code | command-line options |
| Tests | none | pytest, including a v1-vs-v2 comparison |

## Both versions agree on this dataset

| Result | v1 | v2 |
|---|---|---|
| Total / successful / failed events | 1,200 / 1,072 / 128 | 1,200 / 1,072 / 128 |
| Failed from external IPs | 78 | 78 |
| Failed between 22:00 and 05:59 | 26 | 26 |
| Password spraying from `203.0.113.77` | 16 accounts | 16 accounts |
| `charlie` from `198.51.100.24` | 18 failures | 18 failures |
| `dana` from `192.0.2.44` | 14 failures | 14 failures |
| `bob` from `192.0.2.88` | 8 failures | 8 failures |
| Possible compromise (`charlie`, after the failures) | 1 alert | 1 finding (Critical) |

v2 adds context that v1 does not give, for example that the successful `charlie`
logon happened 14 seconds after the last failure with `mfa_result=not_required`,
and whether the same IP logged in successfully after a burst.

## Limitations

- The dataset is **synthetic**. The IP addresses come from documentation ranges (RFC 5737), not real attacker infrastructure.
- Thresholds were chosen for this dataset. A real environment would need tuning against normal behaviour.
- Findings are leads for investigation, not confirmed incidents.

See [`v1_original/README.md`](v1_original/README.md) and
[`v2_ai_assisted/README.md`](v2_ai_assisted/README.md) for details on each version.
