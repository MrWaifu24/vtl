"""Linux authentication logs (/var/log/auth.log, /var/log/secure).

Supports both the classic syslog timestamp (``Sep 29 10:42:11``, no year, local
time) and the RFC 3339 format written by rsyslog on newer distributions
(``2026-09-29T10:42:11.123456+00:00``, default on Ubuntu 24.04+).
"""

from __future__ import annotations

import gzip
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

from ..correlate import collapse_bursts
from ..detections import SHELL_RULES, is_external, score, shorten
from ..models import Event, Severity, parse_iso
from . import ParseStats

MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}

CLASSIC = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
RFC3339 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "root", "adm", "docker", "lxd", "disk", "shadow"}


@dataclass
class Match:
    summary: str
    severity: Severity = Severity.INFO
    user: str = ""
    src_ip: str = ""
    code: str = ""
    tags: tuple[str, ...] = ()


Rule = tuple[str, re.Pattern[str], Callable[[re.Match[str]], Match | None]]


def _accepted(m: re.Match[str]) -> Match:
    user, ip, method = m["user"], m["ip"], m["method"]
    sev = Severity.MEDIUM if is_external(ip) else Severity.LOW
    if user == "root":
        sev = max(sev, Severity.MEDIUM)
    text = f"SSH login accepted: {user} from {ip} ({method})"
    if user == "root":
        text += "  [direct root login]"
    return Match(text, sev, user, ip, "sshd", ("T1078", "T1021.004"))


def _failed(m: re.Match[str]) -> Match:
    invalid = bool(m["invalid"])
    text = f"SSH failed password for {'invalid user ' if invalid else ''}{m['user']} from {m['ip']}"
    return Match(text, Severity.LOW, m["user"], m["ip"], "sshd", ("T1110",))


def _invalid_user(m: re.Match[str]) -> Match:
    return Match(
        f"SSH invalid user {m['user']} from {m['ip']}",
        Severity.LOW,
        m["user"],
        m["ip"],
        "sshd",
        ("T1110",),
    )


def _sudo(m: re.Match[str]) -> Match:
    cmd = m["cmd"].strip()
    v = score(cmd, SHELL_RULES)
    text = f"sudo: {m['user']} ran as {m['target']}: {shorten(cmd, 200)}"
    if v.labels:
        text += f"  [{', '.join(v.labels)}]"
    return Match(
        text, max(Severity.LOW, v.severity), m["user"], code="sudo", tags=("T1548.003", *v.tags)
    )


def _sudo_fail(m: re.Match[str]) -> Match:
    return Match(
        f"sudo authentication failure for {m['user']}",
        Severity.MEDIUM,
        m["user"],
        code="sudo",
        tags=("T1548.003",),
    )


def _su(m: re.Match[str]) -> Match:
    return Match(
        f"su session opened: {m['by']} -> {m['target']}",
        Severity.MEDIUM if m["target"] == "root" else Severity.LOW,
        m["by"],
        code="su",
    )


def _useradd(m: re.Match[str]) -> Match:
    return Match(
        f"User account created: {m['user']} (UID {m['uid']}, shell {m['shell'] or '?'})",
        Severity.MEDIUM,
        m["user"],
        code="useradd",
        tags=("T1136.001",),
    )


def _group_member(m: re.Match[str]) -> Match:
    group = m["group"]
    privileged = group in PRIVILEGED_GROUPS
    text = f"User {m['user']} added to group {group}"
    if privileged:
        text += "  [privileged group]"
    return Match(
        text,
        Severity.HIGH if privileged else Severity.LOW,
        m["user"],
        code="usermod",
        tags=("T1098",),
    )


def _userdel(m: re.Match[str]) -> Match:
    return Match(
        f"User account deleted: {m['user']}",
        Severity.MEDIUM,
        m["user"],
        code="userdel",
        tags=("T1531",),
    )


def _passwd(m: re.Match[str]) -> Match:
    return Match(
        f"Password changed for {m['user']}", Severity.LOW, m["user"], code="passwd", tags=("T1098",)
    )


def _max_auth(m: re.Match[str]) -> Match:
    return Match(
        f"SSH maximum authentication attempts exceeded for {m['user']} from {m['ip']}",
        Severity.LOW,
        m["user"],
        m["ip"],
        "sshd",
        ("T1110",),
    )


RULES: list[Rule] = [
    (
        "sshd",
        re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+"),
        _accepted,
    ),
    (
        "sshd",
        re.compile(
            r"^Failed (?:password|publickey|none) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
        ),
        _failed,
    ),
    ("sshd", re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)"), _invalid_user),
    (
        "sshd",
        re.compile(
            r"^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
        ),
        _max_auth,
    ),
    (
        "sudo",
        re.compile(
            r"^\s*(?P<user>\S+) : (?:TTY=\S+ ; )?PWD=\S+ ; USER=(?P<target>\S+) ; (?:ENV=.*? ; )?COMMAND=(?P<cmd>.*)$"
        ),
        _sudo,
    ),
    (
        "sudo",
        re.compile(
            r"^\s*(?P<user>\S+) : (?:\d+ incorrect password attempts?|a password is required)"
        ),
        _sudo_fail,
    ),
    (
        "sudo",
        re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*\buser=(?P<user>\S+)"),
        _sudo_fail,
    ),
    (
        "su",
        re.compile(
            r"pam_unix\(su(?:-l)?:session\): session opened for user (?P<target>[^\s(]+)(?:\(uid=\d+\))? by (?P<by>[^\s(]+)"
        ),
        _su,
    ),
    (
        "useradd",
        re.compile(
            r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)(?:, GID=\d+)?(?:, home=[^,]*)?(?:, shell=(?P<shell>[^,]+))?"
        ),
        _useradd,
    ),
    (
        "usermod",
        re.compile(r"^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'"),
        _group_member,
    ),
    (
        "gpasswd",
        re.compile(r"^user (?P<user>\S+) added by \S+ to group (?P<group>\S+)"),
        _group_member,
    ),
    ("userdel", re.compile(r"^delete user '(?P<user>[^']+)'"), _userdel),
    (
        "passwd",
        re.compile(r"pam_unix\(passwd:chauthtok\): password changed for (?P<user>\S+)"),
        _passwd,
    ),
    (
        "chpasswd",
        re.compile(r"pam_unix\(chpasswd:chauthtok\): password changed for (?P<user>\S+)"),
        _passwd,
    ),
]


def _open(path: Path) -> list[str]:
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":  # rotated auth.log.2.gz
        raw = gzip.decompress(raw)
    return raw.decode("utf-8", errors="replace").splitlines()


class _YearTracker:
    """Assigns years to classic syslog timestamps.

    With an explicit year, years advance when the month wraps (Dec -> Jan).
    Without one, the file's modification time anchors the *last* entry, and
    any timestamp that would land in the future is moved back a year.
    """

    def __init__(self, year: int | None, reference: datetime):
        self.explicit = year
        self.year = year or reference.year
        self.reference = reference
        self.last_month = 0

    def resolve(self, month: int, day: int, clock: str, tz: tzinfo) -> datetime:
        if self.explicit is not None:
            if self.last_month == 12 and month == 1:
                self.year += 1
            self.last_month = month
            year = self.year
        else:
            year = self.reference.year
        h, mi, s = (int(x) for x in clock.split(":"))
        dt = datetime(year, month, day, h, mi, s, tzinfo=tz)
        if self.explicit is None and dt > self.reference + timedelta(days=1):
            dt = dt.replace(year=year - 1)
        return dt.astimezone(timezone.utc)


def parse_linux(
    path: Path,
    stats: ParseStats | None = None,
    year: int | None = None,
    tz: tzinfo = timezone.utc,
    threshold: int = 5,
) -> list[Event]:
    stats = stats or ParseStats()
    reference = datetime.fromtimestamp(path.stat().st_mtime, tz)
    years = _YearTracker(year, reference)
    events: list[Event] = []

    for n, line in enumerate(_open(path), 1):
        if not line.strip():
            continue
        m = RFC3339.match(line)
        try:
            if m:
                ts = parse_iso(m["ts"], default_tz=tz)
            else:
                m = CLASSIC.match(line)
                if not m or m["mon"] not in MONTHS:
                    stats.skip(f"{path.name}:{n}: unrecognized line format")
                    continue
                ts = years.resolve(MONTHS[m["mon"]], int(m["day"]), m["time"], tz)
        except ValueError as exc:
            stats.skip(f"{path.name}:{n}: bad timestamp ({exc})")
            continue

        prog, msg = m["prog"], m["msg"]
        match = None
        for rule_prog, pattern, build in RULES:
            if prog != rule_prog:
                continue
            found = pattern.search(msg)
            if found:
                match = build(found)
                break
        if match is None:
            stats.filtered += 1
            continue

        events.append(
            Event(
                ts=ts,
                source="Linux",
                code=match.code or prog,
                summary=match.summary,
                severity=match.severity,
                host=m["host"],
                user=match.user,
                src_ip=match.src_ip,
                tags=list(match.tags),
                origin=path.name,
            )
        )
        stats.parsed += 1

    # "Invalid user X from IP" is usually followed by "Failed password for invalid user X
    # from IP"; keep only one of the two so bursts are not double counted.
    failed_invalid = {
        (e.user, e.src_ip)
        for e in events
        if e.summary.startswith("SSH failed password for invalid")
    }
    events = [
        e
        for e in events
        if not (e.summary.startswith("SSH invalid user") and (e.user, e.src_ip) in failed_invalid)
    ]
    return collapse_bursts(
        events,
        is_failure=lambda e: (
            e.code == "sshd" and e.summary.startswith(("SSH failed", "SSH invalid"))
        ),
        is_success=lambda e: e.code == "sshd" and e.summary.startswith("SSH login accepted"),
        label="SSH brute force",
        threshold=threshold,
    )
