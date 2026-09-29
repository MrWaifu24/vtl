"""Collapse bursts of failed logons and flag successes that follow them."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta

from .models import Event, Severity

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = timedelta(minutes=10)


@dataclass
class _Burst:
    events: list[Event] = field(default_factory=list)

    @property
    def first(self) -> Event:
        return self.events[0]

    @property
    def last(self) -> Event:
        return self.events[-1]


def collapse_bursts(
    events: list[Event],
    is_failure: Callable[[Event], bool],
    is_success: Callable[[Event], bool],
    label: str,
    threshold: int = DEFAULT_THRESHOLD,
    window: timedelta = DEFAULT_WINDOW,
) -> list[Event]:
    """Replace runs of >= ``threshold`` failures from one source with one event.

    Failures are grouped per (host, src_ip) and split into bursts whenever the
    gap between two failures exceeds ``window``. A success from the same
    source within ``window`` after a burst is escalated to HIGH - the classic
    "brute force that worked" pattern.
    """
    if threshold <= 1:
        return events

    events = sorted(events, key=lambda e: e.ts)
    open_bursts: dict[tuple[str, str], _Burst] = {}
    bursts: list[_Burst] = []

    for e in events:
        if not is_failure(e) or not e.src_ip:
            continue
        k = (e.host, e.src_ip)
        burst = open_bursts.get(k)
        if burst is None or e.ts - burst.last.ts > window:
            burst = _Burst()
            open_bursts[k] = burst
            bursts.append(burst)
        burst.events.append(e)

    big = [b for b in bursts if len(b.events) >= threshold]
    collapsed = {id(e) for b in big for e in b.events}

    out: list[Event] = [e for e in events if id(e) not in collapsed]
    for b in big:
        users = sorted({e.user for e in b.events if e.user})
        user_part = f"{len(users)} account(s): {', '.join(users[:5])}" + (
            " ..." if len(users) > 5 else ""
        )
        out.append(
            Event(
                ts=b.first.ts,
                source=b.first.source,
                code=b.first.code,
                summary=(
                    f"{label}: {len(b.events)} failed logons from {b.first.src_ip} "
                    f"({b.first.ts:%H:%M:%S}-{b.last.ts:%H:%M:%S}) targeting {user_part}"
                ),
                severity=Severity.MEDIUM,
                host=b.first.host,
                user=users[0] if len(users) == 1 else "",
                src_ip=b.first.src_ip,
                tags=sorted({"T1110"} | {t for e in b.events for t in e.tags}),
                origin=b.first.origin,
            )
        )

    for e in out:
        if not is_success(e) or not e.src_ip:
            continue
        for b in big:
            if (
                (b.first.host, b.first.src_ip) == (e.host, e.src_ip)
                and b.first.ts <= e.ts
                and e.ts - b.last.ts <= window
            ):
                e.severity = max(e.severity, Severity.HIGH)
                e.summary += f" - after {len(b.events)} failed attempts from this IP"
                if "T1110" not in e.tags:
                    e.tags.append("T1110")
                break

    return sorted(out, key=lambda e: e.ts)
