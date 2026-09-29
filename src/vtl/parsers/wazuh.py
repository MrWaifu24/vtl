"""Wazuh alerts (alerts.json): newline-delimited JSON, or a JSON array export."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from ..models import Event, Severity, parse_iso
from . import ParseStats


def level_to_severity(level: int) -> Severity:
    """Map Wazuh rule levels (0-15) onto timeline severities.

    Wazuh treats 12+ as high-importance events and 15 as severe attacks.
    """
    if level >= 15:
        return Severity.CRITICAL
    if level >= 12:
        return Severity.HIGH
    if level >= 8:
        return Severity.MEDIUM
    if level >= 4:
        return Severity.LOW
    return Severity.INFO


def _iter_alerts(path: Path, stats: ParseStats) -> Iterator[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            stats.warn(f"{path.name}: invalid JSON array: {exc}")
            return
        for item in data:
            # OpenSearch/Elasticsearch exports wrap the alert in _source
            yield item.get("_source", item) if isinstance(item, dict) else {}
        return

    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            stats.skip(f"{path.name}:{n}: not valid JSON")


def _first(d: dict, *paths: str) -> str:
    for p in paths:
        cur: object = d
        for part in p.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if cur:
            return str(cur)
    return ""


def parse_wazuh(path: Path, stats: ParseStats | None = None) -> list[Event]:
    stats = stats or ParseStats()
    events: list[Event] = []
    for alert in _iter_alerts(path, stats):
        rule = alert.get("rule") or {}
        ts_raw = alert.get("timestamp") or alert.get("@timestamp")
        if not ts_raw or not rule:
            stats.skip(f"{path.name}: alert without timestamp or rule")
            continue
        try:
            ts = parse_iso(str(ts_raw))
        except ValueError:
            stats.skip(f"{path.name}: bad timestamp {ts_raw!r}")
            continue

        try:
            level = int(rule.get("level", 0))
        except (TypeError, ValueError):
            level = 0
        src_ip = _first(alert, "data.srcip", "data.src_ip", "data.win.eventdata.ipAddress")
        user = _first(
            alert,
            "data.dstuser",
            "data.srcuser",
            "data.win.eventdata.targetUserName",
            "data.win.eventdata.subjectUserName",
            "data.win.eventdata.user",
        )
        summary = str(rule.get("description", "")).strip() or "Wazuh alert"
        context = []
        if user:
            context.append(f"user={user}")
        if src_ip:
            context.append(f"src={src_ip}")
        if context:
            summary += f" ({', '.join(context)})"

        mitre = rule.get("mitre") or {}
        events.append(
            Event(
                ts=ts,
                source="Wazuh",
                code=str(rule.get("id", "")),
                summary=summary,
                severity=level_to_severity(level),
                host=_first(alert, "agent.name", "manager.name"),
                user=user,
                src_ip=src_ip,
                tags=[str(t) for t in mitre.get("id", [])],
                origin=path.name,
            )
        )
        stats.parsed += 1
    return events
