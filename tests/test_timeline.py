import csv
import io
import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest
from rich.console import Console

from vtl.cli import main
from vtl.correlate import collapse_bursts
from vtl.models import Event, Severity
from vtl.output import render
from vtl.timeline import Filters, build_timeline


@pytest.fixture
def timeline(samples):
    return build_timeline(
        [samples / "alerts.json"], [samples / "windows.xml"], [samples / "auth.log"], year=2026
    )


def test_merged_timeline_is_chronological(timeline):
    ts = [e.ts for e in timeline.events]
    assert ts == sorted(ts)
    sources = {e.source for e in timeline.events}
    assert sources == {"Wazuh", "Windows", "Linux"}


def test_attack_story_order(timeline):
    """The sample intrusion must read in the right order across all three sources."""
    milestones = [
        ("Linux", "SSH brute force"),
        ("Linux", "SSH login accepted: deploy"),
        ("Linux", "added to group sudo"),
        ("Windows", "Logon brute force"),
        ("Windows", "Service installed: BTOBTO"),
        ("Windows", "decoded: IEX"),
        ("Windows", "possible C2"),
        ("Windows", "LSASS memory access"),
        ("Windows", "Security audit log cleared"),
    ]
    positions = []
    for source, text in milestones:
        idx = next(
            i for i, e in enumerate(timeline.events) if e.source == source and text in e.summary
        )
        positions.append(idx)
    assert positions == sorted(positions)


def test_filters(samples):
    kwargs = dict(
        wazuh=[samples / "alerts.json"],
        windows=[samples / "windows.xml"],
        linux=[samples / "auth.log"],
        year=2026,
    )
    high = build_timeline(**kwargs, filters=Filters(min_severity=Severity.HIGH))
    assert high.events and all(e.severity >= Severity.HIGH for e in high.events)

    window = build_timeline(
        **kwargs,
        filters=Filters(
            since=datetime(2026, 9, 29, 10, 42, tzinfo=timezone.utc),
            until=datetime(2026, 9, 29, 10, 43, tzinfo=timezone.utc),
        ),
    )
    assert window.events and all(e.ts.minute == 42 for e in window.events)

    grep = build_timeline(**kwargs, filters=Filters(grep="203.0.113.47"))
    assert grep.events and all("203.0.113.47" in (e.summary + e.src_ip) for e in grep.events)

    hosts = build_timeline(**kwargs, filters=Filters(hosts=["web"]))
    assert {e.host for e in hosts.events} == {"web01"}


def test_duplicates_removed(samples):
    tl = build_timeline(linux=[samples / "auth.log", samples / "auth.log"], year=2026)
    single = build_timeline(linux=[samples / "auth.log"], year=2026)
    assert len(tl.events) == len(single.events)


def _ev(sec, summary, ip="1.2.3.4", code="f"):
    return Event(
        ts=datetime(2026, 1, 1, 0, 0, sec, tzinfo=timezone.utc),
        source="Linux",
        code=code,
        summary=summary,
        src_ip=ip,
        host="h",
        user=f"u{sec}",
    )


def test_collapse_bursts_threshold():
    fails = [_ev(i, "fail") for i in range(4)]
    kept = collapse_bursts(fails, lambda e: e.summary == "fail", lambda e: False, "BF", threshold=5)
    assert len(kept) == 4, "below threshold nothing is collapsed"
    fails.append(_ev(10, "fail"))
    fails.append(_ev(20, "ok"))
    out = collapse_bursts(
        fails, lambda e: e.summary == "fail", lambda e: e.summary == "ok", "BF", threshold=5
    )
    assert len(out) == 2
    assert out[0].summary.startswith("BF: 5 failed logons from 1.2.3.4")
    assert out[1].severity is Severity.HIGH


def test_collapse_bursts_other_ip_not_escalated():
    events = [_ev(i, "fail") for i in range(5)] + [_ev(30, "ok", ip="5.6.7.8")]
    out = collapse_bursts(events, lambda e: e.summary == "fail", lambda e: e.summary == "ok", "BF")
    assert out[-1].severity is Severity.INFO


def test_csv_json_markdown(timeline):
    utc = timezone.utc
    rows = list(csv.DictReader(io.StringIO(render(timeline, "csv", utc))))
    assert len(rows) == len(timeline.events)
    assert rows[0]["timestamp"].endswith("+00:00")

    data = json.loads(render(timeline, "json", utc))
    assert data["summary"]["events"] == len(timeline.events)
    assert data["summary"]["by_source"]["Wazuh"] == 7

    md = render(timeline, "md", utc)
    assert md.startswith("# Incident Timeline")
    assert "## Key events" in md
    assert "T1003.001" in md
    assert md.count("\n| 2026-09-29") == len(timeline.events)


def test_display_timezone(timeline):
    rows = list(csv.DictReader(io.StringIO(render(timeline, "csv", ZoneInfo("Asia/Tokyo")))))
    assert rows[0]["timestamp"].endswith("+09:00")


def test_table_output(timeline):
    console = Console(file=io.StringIO(), width=160, no_color=True)
    render(timeline, "table", timezone.utc, console)
    out = console.file.getvalue()
    assert "2026-09-29" in out and "SSH brute force" in out and "CRITICAL" in out


def test_cli(samples, tmp_path, capsys):
    args = [
        "--wazuh",
        str(samples / "alerts.json"),
        "--windows",
        str(samples / "windows.xml"),
        "--linux",
        str(samples / "auth.log"),
        "--year",
        "2026",
    ]
    assert main([*args, "--no-color"]) == 0
    assert "Security audit log cleared" in capsys.readouterr().out

    assert main([*args, "-f", "json", "--min-severity", "critical"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {e["severity"] for e in data["events"]} == {"CRITICAL"}

    out = tmp_path / "timeline.md"
    assert main([*args, "-f", "md", "-o", str(out)]) == 0
    assert out.read_text().startswith("# Incident Timeline")


def test_cli_requires_a_source(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2
    assert "at least one source" in capsys.readouterr().err


def test_cli_rejects_bad_timezone(samples):
    with pytest.raises(SystemExit):
        main(["--linux", str(samples / "auth.log"), "--tz", "Mars/Olympus"])
