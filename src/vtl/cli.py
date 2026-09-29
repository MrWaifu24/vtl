"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import timezone, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from rich.console import Console

from . import __version__
from .models import Severity, parse_iso
from .output import render
from .timeline import Filters, build_timeline

# Width used when the table is piped or redirected (no terminal to measure).
PIPED_WIDTH = 160


def _tz(value: str) -> tzinfo:
    if value.upper() in ("UTC", "Z"):
        return timezone.utc
    try:
        return ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError):
        raise argparse.ArgumentTypeError(
            f"unknown time zone {value!r} (use e.g. UTC, Europe/Berlin)"
        ) from None


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vtl",
        description="Merge Wazuh alerts, Windows event logs and Linux auth logs into one "
        "chronological incident timeline.",
        epilog="example: vtl --wazuh alerts.json --windows security.evtx --linux auth.log",
    )
    src = p.add_argument_group("sources (each may be repeated)")
    src.add_argument(
        "--wazuh",
        action="append",
        type=Path,
        default=[],
        metavar="FILE",
        help="Wazuh alerts.json (NDJSON or JSON array)",
    )
    src.add_argument(
        "--windows",
        action="append",
        type=Path,
        default=[],
        metavar="FILE",
        help="Windows .evtx or XML export (wevtutil /f:xml, Get-WinEvent ToXml)",
    )
    src.add_argument(
        "--linux",
        action="append",
        type=Path,
        default=[],
        metavar="FILE",
        help="Linux auth.log / secure (plain or .gz)",
    )

    flt = p.add_argument_group("filters")
    flt.add_argument(
        "--since", metavar="TIME", help="only events at/after TIME (ISO 8601; naive times use --tz)"
    )
    flt.add_argument("--until", metavar="TIME", help="only events at/before TIME")
    flt.add_argument(
        "--min-severity",
        type=_severity,
        default=Severity.INFO,
        metavar="LEVEL",
        help="info, low, medium, high or critical (default: info)",
    )
    flt.add_argument(
        "--grep", metavar="TEXT", help="only events whose summary/host/user/IP/code contains TEXT"
    )
    flt.add_argument(
        "--host",
        action="append",
        default=[],
        metavar="NAME",
        help="only events from hosts containing NAME (repeatable)",
    )

    tim = p.add_argument_group("time handling")
    tim.add_argument(
        "--tz",
        type=_tz,
        default=timezone.utc,
        metavar="ZONE",
        help="display time zone (default: UTC)",
    )
    tim.add_argument(
        "--linux-tz",
        type=_tz,
        default=timezone.utc,
        metavar="ZONE",
        help="time zone of classic syslog timestamps (default: UTC)",
    )
    tim.add_argument(
        "--year", type=int, help="year for syslog timestamps without one (default: from file mtime)"
    )

    out = p.add_argument_group("output")
    out.add_argument(
        "-f",
        "--format",
        choices=["table", "csv", "json", "md"],
        default="table",
        help="output format (default: table)",
    )
    out.add_argument(
        "-o", "--output", type=Path, metavar="FILE", help="write to FILE instead of stdout"
    )
    out.add_argument(
        "--threshold",
        type=int,
        default=5,
        metavar="N",
        help="collapse >= N failed logons from one IP into a brute-force event; 0 disables (default: 5)",
    )
    out.add_argument("--no-color", action="store_true", help="disable colored output")
    out.add_argument("-q", "--quiet", action="store_true", help="suppress parser warnings")
    p.add_argument("-V", "--version", action="version", version=f"vtl {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    err = Console(stderr=True, no_color=args.no_color, highlight=False)

    if not (args.wazuh or args.windows or args.linux):
        parser.error("give at least one source: --wazuh, --windows or --linux")
    for path in (*args.wazuh, *args.windows, *args.linux):
        if not path.is_file():
            parser.error(f"{path}: no such file")

    try:
        filters = Filters(
            since=parse_iso(args.since, args.tz) if args.since else None,
            until=parse_iso(args.until, args.tz) if args.until else None,
            min_severity=args.min_severity,
            grep=args.grep,
            hosts=args.host,
        )
    except ValueError as exc:
        parser.error(f"invalid --since/--until: {exc}")

    tl = build_timeline(
        args.wazuh,
        args.windows,
        args.linux,
        filters=filters,
        linux_tz=args.linux_tz,
        year=args.year,
        threshold=args.threshold,
    )

    if not args.quiet:
        for path, st in tl.stats.items():
            if st.parsed == 0 and not st.warnings:
                err.print(f"[yellow]vtl: {path}: no recognizable events[/]")
            for w in st.warnings[:5]:
                err.print(f"[dim]vtl: warning: {w}[/]")
            if st.skipped > 5:
                err.print(f"[dim]vtl: {path}: {st.skipped} malformed record(s) skipped[/]")

    if args.output:
        with args.output.open("w", encoding="utf-8", newline="") as fh:
            if args.format == "table":
                render(
                    tl,
                    "table",
                    args.tz,
                    Console(file=fh, width=PIPED_WIDTH, no_color=True, force_terminal=False),
                )
            else:
                fh.write(render(tl, args.format, args.tz) or "")
        err.print(f"[green]vtl: wrote {len(tl.events)} events to {args.output}[/]")
    elif args.format == "table":
        # Without a TTY rich falls back to a narrow default and wraps every summary;
        # use a fixed wide layout unless the user set COLUMNS explicitly.
        piped = not sys.stdout.isatty() and "COLUMNS" not in os.environ
        width = PIPED_WIDTH if piped else None
        render(tl, "table", args.tz, Console(no_color=args.no_color, highlight=False, width=width))
    else:
        sys.stdout.write(render(tl, args.format, args.tz) or "")
    return 0


if __name__ == "__main__":
    sys.exit(main())
