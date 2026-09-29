"""Log parsers. Each returns a list of normalized :class:`vtl.models.Event`."""

from __future__ import annotations

from dataclasses import dataclass, field

MAX_WARNINGS = 20


@dataclass
class ParseStats:
    """Counts of parsed and skipped records, plus a sample of warnings."""

    parsed: int = 0
    skipped: int = 0  # unreadable or malformed records
    filtered: int = 0  # valid records deliberately left out as noise
    warnings: list[str] = field(default_factory=list)

    def skip(self, reason: str) -> None:
        self.skipped += 1
        self.warn(reason)

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append(message)
