"""Merge parsed events from every source into one filtered, ordered timeline."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from pathlib import Path

from .models import Event, Severity
from .parsers import ParseStats
from .parsers.linux import parse_linux
from .parsers.wazuh import parse_wazuh
from .parsers.windows import parse_windows

SOURCE_ORDER = {"Linux": 0, "Windows": 1, "Wazuh": 2}


@dataclass
class Filters:
    since: datetime | None = None
    until: datetime | None = None
    min_severity: Severity = Severity.INFO
    grep: str | None = None
    hosts: list[str] = field(default_factory=list)

    def match(self, e: Event) -> bool:
        if self.since and e.ts < self.since:
            return False
        if self.until and e.ts > self.until:
            return False
        if e.severity < self.min_severity:
            return False
        if self.hosts and not any(h.lower() in e.host.lower() for h in self.hosts):
            return False
        if self.grep:
            needle = self.grep.lower()
            hay = " ".join((e.summary, e.host, e.user, e.src_ip, e.code, *e.tags)).lower()
            if needle not in hay:
                return False
        return True


@dataclass
class Timeline:
    events: list[Event]
    stats: dict[str, ParseStats]

    @property
    def span(self) -> tuple[datetime, datetime] | None:
        if not self.events:
            return None
        return self.events[0].ts, self.events[-1].ts

    def counts(self) -> tuple[Counter, Counter]:
        return Counter(e.source for e in self.events), Counter(e.severity for e in self.events)


def build_timeline(
    wazuh: list[Path] | None = None,
    windows: list[Path] | None = None,
    linux: list[Path] | None = None,
    *,
    filters: Filters | None = None,
    linux_tz: tzinfo = timezone.utc,
    year: int | None = None,
    threshold: int = 5,
) -> Timeline:
    filters = filters or Filters()
    events: list[Event] = []
    stats: dict[str, ParseStats] = {}

    for path in wazuh or []:
        stats[str(path)] = st = ParseStats()
        events += parse_wazuh(path, st)
    for path in windows or []:
        stats[str(path)] = st = ParseStats()
        events += parse_windows(path, st, threshold=threshold)
    for path in linux or []:
        stats[str(path)] = st = ParseStats()
        events += parse_linux(path, st, year=year, tz=linux_tz, threshold=threshold)

    seen: set[tuple] = set()
    unique: list[Event] = []
    for e in events:
        k = e.key()
        if k not in seen:
            seen.add(k)
            unique.append(e)

    unique.sort(key=lambda e: (e.ts, SOURCE_ORDER.get(e.source, 9)))
    return Timeline([e for e in unique if filters.match(e)], stats)
