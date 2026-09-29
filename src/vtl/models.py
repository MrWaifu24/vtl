"""Normalized event model shared by every parser."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown severity {value!r} (choose from {', '.join(s.name.lower() for s in cls)})"
            ) from None


@dataclass
class Event:
    """One line of the investigation timeline."""

    ts: datetime  # timezone-aware, UTC
    source: str  # Wazuh | Windows | Linux
    code: str  # rule ID, event ID or program name
    summary: str
    severity: Severity = Severity.INFO
    host: str = ""
    user: str = ""
    src_ip: str = ""
    tags: list[str] = field(default_factory=list)  # e.g. MITRE ATT&CK IDs
    origin: str = ""  # file the event came from

    def key(self) -> tuple:
        return (self.ts, self.source, self.host, self.code, self.summary)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.ts.isoformat(),
            "source": self.source,
            "host": self.host,
            "code": self.code,
            "severity": self.severity.name,
            "user": self.user,
            "src_ip": self.src_ip,
            "summary": self.summary,
            "tags": self.tags,
            "origin": self.origin,
        }


_FRACTION = re.compile(r"\.(\d+)")
_COMPACT_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_iso(value: str, default_tz=timezone.utc) -> datetime:
    """Parse ISO-8601 timestamps as written by Wazuh, Windows and rsyslog.

    Handles 'Z', compact offsets (+0000) and 7-digit Windows fractions
    (2026-09-29T10:42:11.1234567Z), which datetime.fromisoformat rejects on
    older Python versions. Naive timestamps get ``default_tz``.
    """
    s = value.strip().replace(" ", "T", 1)
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    s = _COMPACT_OFFSET.sub(r"\1:\2", s)
    s = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), s, count=1)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return dt.astimezone(timezone.utc)
