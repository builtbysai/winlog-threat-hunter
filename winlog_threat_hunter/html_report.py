"""HTML report: a self-contained "Threat Board" threat-intel document.

The board is written for a SOC analyst on a night shift: near-black
surfaces for sustained monitoring, ember-red as the threat signature so
severity reads instantly, findings as intel cards (rule ID, ATT&CK
technique, plain-English reasoning, raw evidence in monospace) and an
event timeline showing how the attack unfolded.

Everything is inline (CSS, no CDN, no external assets) so the file can be
archived or emailed as a single artifact. Plain ASCII in all generated
copy: no em dashes, no emoji. Any SVG used is hand-authored.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .models import Event, Finding

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]

_SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}

# Threat-board severity palette: bright console chips, dark text.
_SEVERITY_INK = {
    "critical": "#f85149",
    "high": "#d29922",
    "medium": "#6cb6ff",
    "low": "#8b98a5",
}

_EVENT_SUMMARIES = {
    4624: "Logon success",
    4625: "Logon failure",
    4672: "Special privileges assigned",
    4688: "Process created",
    1: "Process created (Sysmon)",
    4720: "Account created",
    4728: "Member added to global group",
    4732: "Member added to local group",
    4756: "Member added to universal group",
}


def _fmt_time(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def _event_line(e: Event) -> str:
    """One-line plain-English summary of an event for the timeline."""
    label = _EVENT_SUMMARIES.get(e.event_id, f"Event {e.event_id}")
    who = e.account_name or e.target_account
    bits = [label]
    if who:
        bits.append(f"account {who}")
    if e.target_group:
        bits.append(f"group {e.target_group}")
    if e.host:
        bits.append(f"host {e.host}")
    if e.source_ip:
        bits.append(f"from {e.source_ip}")
    if e.logon_type is not None and e.event_id in (4624, 4625, 4672):
        bits.append(f"logon type {e.logon_type}")
    if e.process_name and e.is_process_creation:
        bits.append(f"process {e.process_name}")
    if e.command_line and e.is_process_creation and len(e.command_line) < 90:
        bits.append(f"cmd: {e.command_line}")
    return " | ".join(bits)


def _event_json(e: Event) -> str:
    d = {
        "event_id": e.event_id,
        "timestamp": e.timestamp.isoformat(),
    }
    for key in ("host", "account_name", "source_ip", "logon_type", "status",
                "process_name", "command_line", "target_account", "target_group"):
        v = getattr(e, key)
        if v not in ("", None):
            d[key] = v
    return json.dumps(d, ensure_ascii=True)


def _finding_events(f: Finding, events: list[Event], limit: int = 40) -> list[Event]:
    """Events that plausibly belong to a finding: inside its time window and
    sharing an identifier (account, target account, host, or source IP)."""
    out = []
    for e in events:
        if not (f.first_seen <= e.timestamp <= f.last_seen):
            continue
        if f.account_name and (e.account_name == f.account_name or e.target_account == f.account_name):
            out.append(e)
        elif f.source_ip and e.source_ip == f.source_ip:
            out.append(e)
        elif f.host and e.host == f.host:
            out.append(e)
    return sorted(out, key=lambda e: e.timestamp)[:limit]


def _analyst_note(rule_id: str) -> tuple[str, list[str]]:
    """Static analyst context per rule: why it matters and what to do next."""
    notes = {
        "BRUTE-001": (
            "A burst of failed logons that ends in a success almost always means "
            "the password was guessed or sprayed. Treat the account as compromised "
            "until proven otherwise, not as a blocked attempt.",
            [
                "Reset the account password and revoke its active sessions.",
                "Review what the account did after the successful logon.",
                "Investigate the source IP and check whether other accounts were targeted.",
            ],
        ),
        "PRIVESC-001": (
            "Special privileges granted right after a suspicious logon suggest the "
            "session is being armed with administrative power. A routine admin "
            "rarely needs this exact sequence, especially outside business hours.",
            [
                "Confirm the logon was expected and matches a ticketed change.",
                "Audit the privileged session: commands run and processes spawned.",
                "If the logon is unexplained, isolate the host and rotate credentials.",
            ],
        ),
        "PROC-001": (
            "Known-bad command lines are the fingerprints of credential theft, "
            "downloaders, and ransomware staging. Legitimate tooling can use the "
            "same utilities, so the user, the parent process, and the context "
            "decide whether it is malicious.",
            [
                "Identify the user and the parent process behind the command line.",
                "Look for related artifacts: new files, outbound connections, registry changes.",
                "If malicious, contain the host before the payload can finish.",
            ],
        ),
        "PERSIST-001": (
            "Creating an account and immediately placing it in a privileged group "
            "is the classic backdoor: it survives password resets and stays quiet "
            "until it is needed.",
            [
                "Confirm the onboarding was ticketed and expected.",
                "If it was not expected, disable the account and remove its group memberships.",
                "Hunt for other recent account and group changes on the same host.",
            ],
        ),
    }
    return notes.get(rule_id, (
        "Review this finding against your change records and baseline activity "
        "before closing it.",
        ["Verify the activity was expected.", "Scope any related hosts and accounts."],
    ))


def _esc(s: object) -> str:
    return html.escape(str(s), quote=True)


def _bottom_line(f: Finding) -> str:
    who = f.account_name or f.source_ip or f.host or "unknown scope"
    return f"{f.title} involving {who} ({f.rule_id}, {f.mitre_technique})."


def _shield_svg() -> str:
    return (
        '<svg width="34" height="40" viewBox="0 0 34 40" role="img" aria-label="Shield mark">'
        '<path d="M17 2 L30 8 V18 C30 29 24 35 17 38 C10 35 4 29 4 18 V8 Z" '
        'fill="none" stroke="#8b98a5" stroke-width="2.5"/>'
        '<path d="M11 17 L15.5 21.5 L23.5 12.5" fill="none" stroke="#ff5a52" '
        'stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>'
        "</svg>"
    )


_CSS = """\
* { box-sizing: border-box; }
:root { --bg: #0a0d12; --panel: #12161d; --panel-deep: #0d1117;
        --border: #222b36; --text: #e8eef4; --muted: #8b98a5;
        --ember: #ff5a52; --crit: #f85149; --high: #d29922;
        --med: #6cb6ff; --low: #8b98a5;
        --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, Helvetica, Arial, sans-serif;
        --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace; }
body { margin: 0; background: var(--bg); color: var(--text);
       font-family: var(--sans); line-height: 1.55; }
.mast { max-width: 960px; margin: 0 auto; padding: 44px 40px 0; }
.board-head { display: flex; gap: 18px; align-items: flex-start;
              border-bottom: 3px solid var(--ember); padding-bottom: 22px; }
.board-head .mark { flex: 0 0 auto; padding-top: 6px; }
.kicker { font-family: var(--sans); font-size: 12px; letter-spacing: 3px;
          color: var(--ember); text-transform: uppercase; margin: 0 0 8px;
          font-weight: 700; }
h1 { font-size: 40px; line-height: 1.1; margin: 0 0 10px; font-weight: 700;
     letter-spacing: 0.5px; }
.meta { font-family: var(--sans); font-size: 13.5px; color: var(--muted); margin: 0; }
.meta b { color: var(--text); font-weight: 600; }
.wrap { max-width: 960px; margin: 0 auto; padding: 0 40px 60px; }
h2 { font-size: 22px; margin: 44px 0 14px; letter-spacing: 0.5px;
     border-left: 3px solid var(--ember); padding-left: 12px; }
h3 { font-size: 17px; margin: 0 0 8px; }
p { margin: 0 0 12px; overflow-wrap: break-word; }
.summary { display: flex; gap: 12px; flex-wrap: wrap; margin: 26px 0 6px; }
.sev-chip { font-family: var(--sans); font-size: 12px; letter-spacing: 1.5px;
            text-transform: uppercase; border: 1.5px solid; border-radius: 3px;
            padding: 7px 14px; background: var(--panel); }
.sev-chip b { font-size: 16px; }
.bottom-line { background: var(--panel); border: 1px solid var(--border);
               border-left: 4px solid var(--ember); padding: 16px 20px;
               margin: 14px 0; font-size: 16px; }
.bottom-line .n { font-family: var(--sans); font-size: 12px; color: var(--muted);
                  letter-spacing: 1px; text-transform: uppercase; display: block;
                  margin-bottom: 6px; }
.all-clear { background: var(--panel); border: 1px solid var(--border);
             border-left: 4px solid var(--low); padding: 26px 24px;
             margin: 26px 0; font-size: 17px; }
.card { background: var(--panel); border: 1px solid var(--border);
        margin: 22px 0; border-radius: 4px; }
.card-top { padding: 18px 22px 14px; border-bottom: 1px solid var(--border); }
.card-tags { display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
             margin-bottom: 10px; }
.sev-tag { font-family: var(--sans); font-size: 11px; font-weight: 700;
           letter-spacing: 2px; text-transform: uppercase; color: #0a0d12;
           border-radius: 2px; padding: 4px 10px; }
.rule-tag { font-family: var(--mono); font-size: 12.5px;
            border: 1px solid var(--border); border-radius: 2px; padding: 3px 9px;
            color: var(--text); background: var(--bg); }
.attack-tag { font-family: var(--sans); font-size: 12px; color: var(--muted);
              border: 1px dashed #3a4450; border-radius: 2px; padding: 3px 9px; }
.card-title { font-size: 21px; margin: 0; line-height: 1.3; }
.card-body { padding: 18px 22px 20px; }
.facts { display: grid; grid-template-columns: 130px 1fr; gap: 6px 14px;
         font-family: var(--sans); font-size: 13.5px; margin: 0 0 16px;
         padding: 12px 14px; background: var(--bg); border: 1px solid var(--border);
         border-radius: 3px; }
.facts dt { color: var(--muted); text-transform: uppercase; font-size: 11px;
            letter-spacing: 1px; padding-top: 2px; }
.facts dd { margin: 0; }
.mono { font-family: var(--mono); }
.sect-label { font-family: var(--sans); font-size: 11.5px; font-weight: 700;
              letter-spacing: 2px; text-transform: uppercase; color: var(--muted);
              margin: 18px 0 8px; }
ul.actions { margin: 0 0 4px; padding-left: 20px; font-family: var(--sans);
             font-size: 14px; }
ul.actions li { margin-bottom: 6px; }
.evidence { background: #070a0e; color: #dfe7ef; border: 1px solid var(--border);
            border-radius: 3px; padding: 14px 16px; overflow-x: auto;
            margin: 8px 0 0; font-family: var(--mono); font-size: 12px;
            line-height: 1.6; }
.evidence .t { color: #6cb6ff; }
.evidence .id { color: #d29922; }
.timeline { list-style: none; margin: 6px 0 0; padding: 0 0 0 6px;
             position: relative; --tl-col: 118px; }
.timeline::before { content: ""; position: absolute; left: var(--tl-col); top: 8px;
                    bottom: 8px; width: 2px; background: var(--ember); opacity: 0.65; }
.tl-item { display: flex; gap: 16px; padding: 9px 0; position: relative; }
.tl-time { flex: 0 0 90px; text-align: right; white-space: nowrap;
           font-family: var(--mono); font-size: 12px; color: var(--muted);
           padding-top: 3px; }
.tl-dot { flex: 0 0 auto; width: 12px; height: 12px; border-radius: 50%;
          background: var(--bg); border: 2.5px solid #3a4450; margin-top: 5px;
          position: relative; z-index: 1; }
.tl-item.flagged .tl-dot { border-color: var(--dc, #f85149);
                           background: var(--dc, #f85149); }
.tl-item.flagged .tl-text { font-weight: 400; }
.tl-text { font-family: var(--sans); font-size: 13.5px; }
.tl-text .eid { font-family: var(--mono); font-size: 11.5px;
                background: var(--bg); border: 1px solid var(--border);
                border-radius: 2px; padding: 1px 6px; margin-right: 8px;
                white-space: nowrap; }
.tl-item.flagged .tl-text .eid { border-color: var(--dc, #f85149);
                                 color: var(--dc, #f85149); font-weight: 700; }
.coverage { font-family: var(--sans); font-size: 13px; color: var(--muted);
            border-top: 1px solid var(--border); margin-top: 40px; padding-top: 14px; }
.foot { font-family: var(--sans); font-size: 12px; color: var(--muted);
        text-align: center; margin: 34px 0 0; padding: 18px 0 8px;
        border-top: 3px solid var(--ember); }
@media print {
  body { background: #fff; color: #111; }
  .mast, .wrap { max-width: none; }
  .board-head, .foot { border-color: #111; }
  .kicker { color: #b3261e; }
  .card, .bottom-line, .all-clear, .facts, .sev-chip, .rule-tag, .tl-text .eid {
    background: #fff; color: #111; border-color: #999; }
  .meta, .meta b, .facts dt, .sect-label, .coverage, .foot, .tl-time, .attack-tag {
    color: #333; }
  .evidence { background: #111; color: #eee; border-color: #111; }
  .timeline::before { background: #b3261e; opacity: 1; }
  .tl-item.flagged .tl-text .eid { color: #b3261e; border-color: #b3261e; }
  .card, .bottom-line, .all-clear { break-inside: avoid; }
}
@media (max-width: 640px) {
  .mast { padding: 28px 20px 0; } .wrap { padding: 0 20px 40px; }
  h1 { font-size: 30px; }
  .timeline::before { left: 11px; } .tl-time { display: none; }
}
"""


def _finding_card(f: Finding, events: list[Event]) -> str:
    ink = _SEVERITY_INK.get(f.severity, "#e8eef4")
    tag_style = f"background:{ink};"
    why, actions = _analyst_note(f.rule_id)

    who = " / ".join(x for x in (f.account_name, f.host, f.source_ip) if x) or "not specified"
    ev = _finding_events(f, events)
    if ev:
        ev_lines = "\n".join(_event_json(e) for e in ev)
        evidence_html = f'<div class="sect-label">Raw evidence ({len(ev)} event(s) in scope)</div>\n<pre class="evidence">{_esc(ev_lines)}</pre>'
    else:
        evidence_html = (
            '<div class="sect-label">Raw evidence</div>\n'
            f'<p class="mono" style="font-size:13px;">{f.evidence_count} event(s) in scope; '
            "no matching records found in the loaded dataset.</p>"
        )

    actions_html = "\n".join(f"<li>{_esc(a)}</li>" for a in actions)

    return f"""\
<section class="card">
  <div class="card-top">
    <div class="card-tags">
      <span class="sev-tag" style="{tag_style}">{_esc(_SEVERITY_LABEL.get(f.severity, f.severity.upper()))}</span>
      <span class="rule-tag">{_esc(f.rule_id)}</span>
      <span class="attack-tag">MITRE ATT&amp;CK: {_esc(f.mitre_technique)}</span>
    </div>
    <h3 class="card-title">{_esc(f.title)}</h3>
  </div>
  <div class="card-body">
    <dl class="facts">
      <dt>Account</dt><dd class="mono">{_esc(f.account_name or "not specified")}</dd>
      <dt>Host</dt><dd class="mono">{_esc(f.host or "not specified")}</dd>
      <dt>Source IP</dt><dd class="mono">{_esc(f.source_ip or "not specified")}</dd>
      <dt>Window</dt><dd class="mono">{_esc(_fmt_time(f.first_seen))} to {_esc(_fmt_time(f.last_seen))}</dd>
      <dt>Events in scope</dt><dd class="mono">{f.evidence_count}</dd>
    </dl>
    <div class="sect-label">Analyst reasoning</div>
    <p>{_esc(f.description)}</p>
    <div class="sect-label">Why this matters</div>
    <p>{_esc(why)}</p>
    <div class="sect-label">Recommended actions</div>
    <ul class="actions">
{actions_html}
    </ul>
    {evidence_html}
  </div>
</section>"""


def _timeline_html(events: list[Event], findings: list[Finding]) -> tuple[str, str]:
    """Returns (caption_html, timeline_html)."""
    events = sorted(events, key=lambda e: e.timestamp)

    def flagged(e: Event) -> str:
        for f in findings:
            if f.first_seen <= e.timestamp <= f.last_seen:
                return _SEVERITY_INK.get(f.severity, "#f85149")
        return ""

    dates = sorted({e.timestamp.date().isoformat() for e in events})
    single_date = len(dates) == 1

    def tstr(e: Event) -> str:
        if single_date:
            return e.timestamp.strftime("%H:%M:%S")
        return e.timestamp.strftime("%m-%d %H:%M:%S")

    items = []
    for e in events:
        ink = flagged(e)
        cls = "tl-item flagged" if ink else "tl-item"
        style = f' style="--dc:{ink};"' if ink else ""
        items.append(
            f'<li class="{cls}"{style}>'
            f'<span class="tl-time">{_esc(tstr(e))}</span>'
            f'<span class="tl-dot"></span>'
            f'<span class="tl-text"><span class="eid">{e.event_id}</span>{_esc(_event_line(e))}</span>'
            "</li>"
        )
    timeline = '<ol class="timeline">\n' + "\n".join(items) + "\n</ol>"
    when = f"All times UTC on {dates[0]}." if single_date else "All times UTC."
    caption = (
        f"Every event in the export, in order. Highlighted entries fall inside a finding window. {when}"
    )
    return caption, timeline


def render_html_report(findings: list[Finding], events: list[Event], *, source_name: str = "") -> str:
    """Render the full threat board as a single self-contained HTML string."""
    counts = Counter(f.severity for f in findings)
    generated = _fmt_time(datetime.now(timezone.utc))

    chips = []
    for sev in _SEVERITY_ORDER:
        n = counts.get(sev, 0)
        ink = _SEVERITY_INK[sev]
        chips.append(
            f'<span class="sev-chip" style="color:{ink};border-color:{ink};">'
            f"{_SEVERITY_LABEL[sev]} <b>{n}</b></span>"
        )
    summary_html = '<div class="summary">\n' + "\n".join(chips) + "\n</div>"

    if findings:
        urgent = [f for f in findings if f.severity in ("critical", "high")]
        lines = []
        for i, f in enumerate(urgent, 1):
            lines.append(
                f'<div class="bottom-line"><span class="n">Priority {i}</span>'
                f"{_esc(_bottom_line(f))}</div>"
            )
        bottom = '<h2>Bottom line</h2>\n' + "\n".join(lines)
        cards = "\n".join(_finding_card(f, events) for f in findings)
        findings_html = f"{bottom}\n<h2>Findings</h2>\n{cards}"
    else:
        findings_html = (
            '<h2>Bottom line</h2>\n'
            '<div class="all-clear"><b>All clear.</b> No findings: nothing in this '
            "dataset matched a detection rule. The event timeline below is included "
            "so the coverage can be reviewed.</div>"
        )

    rules_run = sorted({f.rule_id for f in findings}) or ["BRUTE-001", "PRIVESC-001", "PROC-001", "PERSIST-001"]
    tl_caption, timeline = _timeline_html(sorted(events, key=lambda e: e.timestamp), findings)

    body = f"""\
<header class="mast">
  <div class="board-head">
    <div class="mark">{_shield_svg()}</div>
    <div>
      <p class="kicker">WinLog Threat Hunter</p>
      <h1>Threat Board</h1>
      <p class="meta">Source: <b>{_esc(source_name or "event export")}</b> &nbsp;|&nbsp;
      Events analyzed: <b>{len(events)}</b> &nbsp;|&nbsp;
      Findings: <b>{len(findings)}</b> &nbsp;|&nbsp;
      Generated: <b>{_esc(generated)}</b></p>
    </div>
  </div>
</header>
<main class="wrap">
  <h2>Summary</h2>
  {summary_html}
  {findings_html}
  <h2>How it unfolded</h2>
  <p style="font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;color:#8b98a5;">
  {_esc(tl_caption)}</p>
  {timeline}
  <div class="coverage">
    Coverage: rules {", ".join(_esc(r) for r in rules_run)} evaluated against
    {len(events)} normalized Windows Security/Sysmon events. This report reflects
    only the events in the loaded export; it is not a verdict on the whole environment.
  </div>
  <footer class="foot">Generated by WinLog Threat Hunter &middot; {_esc(generated)} &middot;
  Treat findings as leads, not conclusions: verify before acting.</footer>
</main>"""

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat Board - WinLog Threat Hunter</title>
<style>
{_CSS}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def write_html_report(findings: list[Finding], events: list[Event], path: str | Path, *,
                       source_name: str = "") -> None:
    path = Path(path)
    path.write_text(render_html_report(findings, events, source_name=source_name), encoding="utf-8")
