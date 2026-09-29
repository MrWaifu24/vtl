"""Render a timeline as a terminal table, CSV, JSON or a Markdown report."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, tzinfo
from itertools import groupby
from typing import TextIO

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .models import Severity
from .timeline import Timeline

SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}
SOURCE_STYLE = {"Windows": "cyan", "Linux": "magenta", "Wazuh": "blue"}

CSV_FIELDS = [
    "timestamp",
    "source",
    "host",
    "code",
    "severity",
    "user",
    "src_ip",
    "summary",
    "tags",
    "origin",
]


def tz_label(tz: tzinfo, when: datetime | None = None) -> str:
    return str(
        getattr(tz, "key", None) or (when or datetime.now(tz)).astimezone(tz).tzname() or "UTC"
    )


def _summary_line(tl: Timeline, tz: tzinfo) -> str:
    if not tl.events:
        return "No events matched."
    sources, severities = tl.counts()
    start, end = tl.span
    by_source = ", ".join(f"{s} {n}" for s, n in sorted(sources.items()))
    by_sev = ", ".join(f"{s.name} {severities[s]}" for s in sorted(severities, reverse=True))
    return (
        f"{len(tl.events)} events ({by_source}) | "
        f"{start.astimezone(tz):%Y-%m-%d %H:%M:%S} -> {end.astimezone(tz):%Y-%m-%d %H:%M:%S} {tz_label(tz, start)} | "
        f"{by_sev}"
    )


def render_table(tl: Timeline, console: Console, tz: tzinfo) -> None:
    if not tl.events:
        console.print("[dim]No events matched.[/]")
        return

    host_width = max(4, min(18, max(len(e.host) for e in tl.events)))
    for day, day_events in groupby(tl.events, key=lambda e: e.ts.astimezone(tz).date()):
        console.rule(
            f"[bold]{day:%A %Y-%m-%d}[/] [dim]({tz_label(tz)})[/]", align="left", style="dim"
        )
        table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False, header_style="bold")
        table.add_column("TIME", no_wrap=True, width=8)
        table.add_column("SOURCE", no_wrap=True, width=7)
        table.add_column("HOST", no_wrap=True, width=host_width, overflow="ellipsis")
        table.add_column("CODE", no_wrap=True, width=7, overflow="ellipsis")
        table.add_column("SEV", no_wrap=True, width=8)
        table.add_column("SUMMARY", overflow="fold", ratio=1)
        for e in day_events:
            style = SEVERITY_STYLE[e.severity]
            table.add_row(
                e.ts.astimezone(tz).strftime("%H:%M:%S"),
                Text(e.source, style=SOURCE_STYLE.get(e.source, "")),
                e.host,
                e.code,
                Text(e.severity.name, style=style),
                Text(e.summary, style="bold" if e.severity >= Severity.HIGH else ""),
            )
        console.print(table)
    console.print(f"[dim]{_summary_line(tl, tz)}[/]")


def write_csv(tl: Timeline, out: TextIO, tz: tzinfo) -> None:
    writer = csv.DictWriter(out, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for e in tl.events:
        row = e.to_dict()
        row["timestamp"] = e.ts.astimezone(tz).isoformat()
        row["tags"] = " ".join(e.tags)
        writer.writerow(row)


def write_json(tl: Timeline, out: TextIO, tz: tzinfo) -> None:
    events = []
    for e in tl.events:
        d = e.to_dict()
        d["timestamp"] = e.ts.astimezone(tz).isoformat()
        events.append(d)
    sources, severities = tl.counts()
    payload = {
        "summary": {
            "events": len(tl.events),
            "start": tl.span[0].astimezone(tz).isoformat() if tl.span else None,
            "end": tl.span[1].astimezone(tz).isoformat() if tl.span else None,
            "by_source": dict(sources),
            "by_severity": {s.name: n for s, n in sorted(severities.items(), reverse=True)},
        },
        "events": events,
    }
    json.dump(payload, out, indent=2, ensure_ascii=False)
    out.write("\n")


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def write_markdown(tl: Timeline, out: TextIO, tz: tzinfo) -> None:
    label = tz_label(tz)
    out.write("# Incident Timeline\n\n")
    if not tl.events:
        out.write("_No events matched._\n")
        return
    sources, severities = tl.counts()
    start, end = tl.span
    out.write(
        f"- **Window:** {start.astimezone(tz):%Y-%m-%d %H:%M:%S} → {end.astimezone(tz):%Y-%m-%d %H:%M:%S} {label}\n"
    )
    out.write(
        f"- **Events:** {len(tl.events)} ("
        + ", ".join(f"{s}: {n}" for s, n in sorted(sources.items()))
        + ")\n"
    )
    out.write(
        "- **Severity:** "
        + ", ".join(f"{s.name} {severities[s]}" for s in sorted(severities, reverse=True))
        + "\n"
    )
    hosts = sorted({e.host for e in tl.events if e.host})
    if hosts:
        out.write(f"- **Hosts:** {', '.join(hosts)}\n")
    techniques = sorted({t for e in tl.events for t in e.tags})
    if techniques:
        out.write(f"- **ATT&CK techniques observed:** {', '.join(techniques)}\n")

    key = [e for e in tl.events if e.severity >= Severity.HIGH]
    if key:
        out.write("\n## Key events\n\n")
        for e in key:
            out.write(
                f"- `{e.ts.astimezone(tz):%H:%M:%S}` **{e.source}/{e.host}**: {_md_escape(e.summary)}\n"
            )

    out.write(
        f"\n## Full timeline\n\n| Time ({label}) | Source | Host | Code | Severity | Summary |\n"
    )
    out.write("|---|---|---|---|---|---|\n")
    for e in tl.events:
        sev = f"**{e.severity.name}**" if e.severity >= Severity.HIGH else e.severity.name
        out.write(
            f"| {e.ts.astimezone(tz):%Y-%m-%d %H:%M:%S} | {e.source} | {_md_escape(e.host)} | "
            f"{_md_escape(e.code)} | {sev} | {_md_escape(e.summary)} |\n"
        )


def render(tl: Timeline, fmt: str, tz: tzinfo, console: Console | None = None) -> str | None:
    """Render ``tl``. Table output goes to ``console``; other formats are returned as text."""
    if fmt == "table":
        render_table(tl, console or Console(), tz)
        return None
    buf = io.StringIO()
    {"csv": write_csv, "json": write_json, "md": write_markdown}[fmt](tl, buf, tz)
    return buf.getvalue()
