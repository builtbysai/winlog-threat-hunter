"""Tests for the HTML threat-board report generator."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from winlog_threat_hunter.engine import run_rules
from winlog_threat_hunter.html_report import render_html_report, write_html_report
from winlog_threat_hunter.models import Event, Finding
from winlog_threat_hunter.parser import load_events

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_logs"
BASE = datetime(2026, 8, 20, 2, 10, tzinfo=timezone.utc)


def _f(**kwargs) -> Finding:
    defaults = dict(
        rule_id="BRUTE-001",
        title="Repeated failed logons",
        severity="critical",
        mitre_technique="T1110 - Brute Force",
        description="7 failed logons followed by a success.",
        first_seen=BASE,
        last_seen=BASE,
        account_name="svc_backup",
        host="WIN-VPN01",
        source_ip="45.33.12.7",
        evidence_count=8,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _e(**kwargs) -> Event:
    defaults = dict(event_id=4625, timestamp=BASE, host="WIN-VPN01",
                    account_name="svc_backup", source_ip="45.33.12.7")
    defaults.update(kwargs)
    return Event(**defaults)


def test_write_html_report_creates_file(tmp_path: Path):
    out = tmp_path / "brief.html"
    write_html_report([_f()], [_e()], out, source_name="sample.jsonl")
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")


def test_report_contains_finding_details():
    html = render_html_report([_f()], [_e()], source_name="sample.jsonl")
    for token in ("BRUTE-001", "T1110", "svc_backup", "WIN-VPN01",
                  "45.33.12.7", "CRITICAL", "Why this matters",
                  "Recommended actions", "Raw evidence", "How it unfolded",
                  "Bottom line"):
        assert token in html, token


def test_report_escapes_user_controlled_content():
    f = _f(account_name='<script>alert("x")</script>')
    html = render_html_report([f], [_e()], source_name="sample.jsonl")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_report_is_self_contained():
    html = render_html_report([_f()], [_e()], source_name="sample.jsonl")
    assert "<style>" in html
    assert "http://" not in html and "https://" not in html


def test_no_em_dashes_in_generated_copy():
    html = render_html_report([_f()], [_e()], source_name="sample.jsonl")
    assert "\u2014" not in html


def test_zero_findings_renders_all_clear():
    html = render_html_report([], [_e()], source_name="normal.jsonl")
    assert "All clear" in html
    assert "How it unfolded" in html  # timeline still present


def test_brute_force_sample_report(tmp_path: Path):
    events = load_events(SAMPLE_DIR / "brute_force_attack.jsonl")
    findings = run_rules(events)
    out = tmp_path / "brief.html"
    write_html_report(findings, events, out, source_name="brute_force_attack.jsonl")
    text = out.read_text(encoding="utf-8")
    assert "Threat Board" in text
    assert "BRUTE-001" in text and "PRIVESC-001" in text
    assert "T1110" in text
    # severity summary chips carry the real counts
    assert "CRITICAL <b>2</b>" in text
    assert "HIGH <b>1</b>" in text


def test_persistence_sample_report():
    events = load_events(SAMPLE_DIR / "persistence_attack.jsonl")
    findings = run_rules(events)
    html = render_html_report(findings, events, source_name="persistence_attack.jsonl")
    assert "PERSIST-001" in html and "PROC-001" in html
    assert "Domain Admins" in html
    assert "T1136" in html
