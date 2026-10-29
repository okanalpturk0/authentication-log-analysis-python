# v1: original script

This is the first version of the tool, written by me and included unchanged
(`analyzer.py`). It reads the authentication CSV, counts events and raises
three kinds of alert.

## Run

```bash
cd v1_original
python analyzer.py
```

`small_company_authentication_events.csv` sits next to the script because v1
looks for it in the current directory (it is the same file as `../data/`).
The script prints the report and writes `report.txt`.

## What it does

| Alert | Logic |
|---|---|
| `CRITICAL \| possible compromise` | a successful login from an account + IP pair that had 5 or more failed attempts in a row |
| `HIGH \| brute force` | an account + IP pair with 5 or more failed attempts |
| `HIGH \| password spraying` | one IP with failed attempts against 5 or more different accounts |

It also counts total, successful and failed events, failures from external
IPs (anything outside `10.20.0.x`) and failures at night (22:00-05:59).

## Output on the dataset

See [`report.txt`](report.txt). It finds 5 alerts: the `charlie` compromise,
brute force against `bob`, `charlie` and `dana`, and the password spraying from
`203.0.113.77`.

## Known limitations

These are the things I would change, and the reasons v2 exists:

- **No time window.** Brute force and spraying are counted over the whole file, so 5 typos spread over 5 days look the same as 5 failures in 2 minutes.
- **Columns by position.** `line.split(",")` with `fields[4]` breaks if a column is added, moved, or a field contains a comma.
- **Regex searches the whole line.** `find_ip()` and `find_time()` take the first match anywhere in the line, and the IP pattern accepts invalid values such as `999.1.1.1`.
- **Bad rows can crash it.** A line without an IP makes `find_ip()` fail with an `IndexError`.
- **Slow on large files.** Lists with `in` checks and nested loops rescan the data for every pair and every IP.
- **Alerts are plain strings.** They are sorted alphabetically, with no severity ranking, timestamps or advice.
- **Settings are hard-coded.** The file name and threshold are edited in the code.

What worked well: it is short, easy to read, and finds the same four leads
that v2 finds on this dataset.
