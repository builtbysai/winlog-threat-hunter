# WinLog Threat Hunter

A small, dependency-free Python tool that parses exported Windows Security /
Sysmon events (JSON Lines or CSV) and flags four patterns a SOC analyst
would actually look for: brute-force/password-spray logon bursts,
privilege escalation following a suspicious logon, known-bad process
command lines, and the "create an account, immediately add it to Domain
Admins" persistence trick.

Built to go with real Active Directory administration experience (user
provisioning, account lifecycle, endpoint management) - this is the
detection side of that same coin: knowing what "wrong" looks like in the
logs those actions generate.

## Why these four detections

Rather than a large, shallow ruleset, this covers a small number of
patterns end-to-end, each mapped to a MITRE ATT&CK technique, each with a
plain-English reason an analyst could act on:

| Rule | ID | Detects | ATT&CK |
|---|---|---|---|
| Brute force / password spray | `BRUTE-001` | A burst of failed logons (4625) against one account or from one source IP, escalated to **critical** if a success follows shortly after | T1110 |
| Privilege escalation | `PRIVESC-001` | Special privileges assigned (4672) right after an interactive/RDP logon - escalated further if that logon was preceded by failed attempts | T1078 |
| Suspicious process | `PROC-001` | Process creation (4688 / Sysmon EventID 1) command lines matching known-bad patterns: encoded/hidden PowerShell, Mimikatz references, SAM hive dumps, certutil-as-downloader, `net user /add`, shadow-copy deletion, rundll32 proxying | T1059, T1003, T1105, T1136, T1490, T1218.011 |
| Admin persistence | `PERSIST-001` | An account created (4720) and added to a privileged group (4732/4728/4756) within minutes of each other | T1136, T1098 |

## Quick start

```bash
# No dependencies needed to run the tool itself
python -m winlog_threat_hunter.cli sample_logs/brute_force_attack.jsonl

# Write JSON/CSV reports too
python -m winlog_threat_hunter.cli sample_logs/persistence_attack.jsonl \
    --json-out findings.json --csv-out findings.csv

# CI-friendly: exit non-zero if anything high or above is found
python -m winlog_threat_hunter.cli sample_logs/brute_force_attack.jsonl --fail-on high
```

Point it at `sample_logs/normal_activity.jsonl` first - it should report
**zero findings**. That file exists specifically to prove the rules don't
fire on look-alike-but-benign activity (a single mistyped password, a
service account's routine 4672, a slow legitimate onboarding) - a
detection tool that only ever says "yes" isn't worth much.

## Bring your own data

The parser expects one JSON object per line (or a CSV with the same
columns) with these fields - extra fields are preserved but ignored:

```json
{"event_id": 4625, "timestamp": "2026-08-20T02:10:00Z", "host": "WIN-VPN01",
 "account_name": "svc_backup", "source_ip": "45.33.12.7", "logon_type": 10, "status": "failure"}
```

This shape lines up with `Get-WinEvent -FilterHashtable @{LogName='Security'}
| Select-Object ... | ConvertTo-Json` or a flattened Winlogbeat/Sysmon
export - reshaping a real log export into this format is a `ConvertTo-Json`
or a `jq` pass, not a rewrite.

## Project layout

```
winlog_threat_hunter/
  models.py     Event / Finding dataclasses
  parser.py     JSONL/CSV -> Event loader
  rules/        one file per detection rule
  engine.py     runs every rule, sorts findings by severity
  report.py     console (color-coded), JSON, and CSV output
  cli.py        entry point
sample_logs/    synthetic normal/brute-force/persistence datasets
scripts/generate_sample_logs.py   regenerates the sample data
tests/          pytest suite (25 tests)
```

## Testing

```bash
pip install -r requirements.txt
pytest -q
```

25 tests covering the parser (malformed JSON, blank lines, CSV, sort order)
and every rule (true positives, true negatives on look-alike benign
activity, and the severity-escalation logic).

**One real bug this testing caught, left in as a note rather than hidden:**
the first version of `BRUTE-001` used a naive sliding window that re-fired
every time an additional failed logon pushed the window back over the
threshold - a single 7-event burst produced 3 near-duplicate findings
instead of 1. Running it against the sample data during development
surfaced this immediately (`normal_activity.jsonl` staying at 0 findings
was the easy check; `brute_force_attack.jsonl` returning 7 findings for
what should have been one incident was the tell). Fixed by clustering
events into bursts first - a gap larger than the window starts a new
cluster - and evaluating each cluster once. `test_burst_reported_once_not_once_per_threshold_crossing`
in `tests/test_rules.py` is the regression test for it.

## Limitations (stated plainly)

- Detection thresholds (5 failed logons / 10-minute window, etc.) are
  reasonable starting points, not tuned against a real SIEM's baseline -
  in production these would be adjusted against actual traffic to control
  false-positive rate.
- The suspicious-process patterns are a small, illustrative set, not a
  Sigma-rule-equivalent ruleset.
- No live log ingestion (WinRM/Winlogbeat/Splunk forwarder) - this reads
  already-exported files. Wiring it to a live source is a parser change,
  not an architecture change.

## License

MIT - see [LICENSE](LICENSE).


---

*Built by [Hans Sai](https://builtbysai.com).*
