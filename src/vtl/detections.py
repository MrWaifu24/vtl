"""Heuristics shared by parsers: suspicious command lines, encoded PowerShell, IP scope."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass, field

from .models import Severity


@dataclass
class Verdict:
    severity: Severity = Severity.INFO
    labels: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def add(self, severity: Severity, label: str, tag: str = "") -> None:
        self.severity = max(self.severity, severity)
        if label not in self.labels:
            self.labels.append(label)
        if tag and tag not in self.tags:
            self.tags.append(tag)

    def merge(self, other: Verdict) -> None:
        self.severity = max(self.severity, other.severity)
        self.labels += [label for label in other.labels if label not in self.labels]
        self.tags += [tag for tag in other.tags if tag not in self.tags]


# (pattern, label, severity, ATT&CK technique)
CMDLINE_RULES: list[tuple[re.Pattern[str], str, Severity, str]] = [
    (re.compile(p, re.IGNORECASE), label, sev, tag)
    for p, label, sev, tag in [
        (
            r"\s[-/](?:e|en|enc\w*|ec)\s+[A-Za-z0-9+/=]{16,}",
            "encoded PowerShell",
            Severity.HIGH,
            "T1027",
        ),
        (r"\b(?:iex|invoke-expression)\b", "Invoke-Expression", Severity.HIGH, "T1059.001"),
        (
            r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer",
            "download cradle",
            Severity.HIGH,
            "T1105",
        ),
        (r"frombase64string", "base64 decoding", Severity.MEDIUM, "T1140"),
        (r"\s-w(?:indowstyle)?\s+h(?:idden)?\b", "hidden window", Severity.MEDIUM, "T1564.003"),
        (
            r"certutil(?:\.exe)?\b.*\s[-/](?:urlcache|decode)",
            "certutil download/decode",
            Severity.HIGH,
            "T1105",
        ),
        (
            r"mshta(?:\.exe)?\s+[\"']?(?:https?|javascript|vbscript):",
            "mshta remote script",
            Severity.HIGH,
            "T1218.005",
        ),
        (r"rundll32(?:\.exe)?\b.*javascript:", "rundll32 javascript", Severity.HIGH, "T1218.011"),
        (
            r"comsvcs(?:\.dll)?\W+#?\+?(?:24|minidump)",
            "LSASS dump via comsvcs",
            Severity.CRITICAL,
            "T1003.001",
        ),
        (
            r"regsvr32(?:\.exe)?\b.*/i:\s*https?",
            "regsvr32 remote scriptlet",
            Severity.HIGH,
            "T1218.010",
        ),
        (r"bitsadmin(?:\.exe)?\b.*/transfer", "bitsadmin transfer", Severity.MEDIUM, "T1197"),
        (
            r"vssadmin(?:\.exe)?\b.*delete\s+shadows|wbadmin(?:\.exe)?\b.*delete|bcdedit(?:\.exe)?\b.*recoveryenabled\s+no",
            "backup/shadow copy deletion",
            Severity.CRITICAL,
            "T1490",
        ),
        (
            r"\bnet1?(?:\.exe)?\s+user\s+\S+\s+\S+\s+/add",
            "account created via net user",
            Severity.HIGH,
            "T1136.001",
        ),
        (
            r"\bnet1?(?:\.exe)?\s+(?:localgroup|group)\s+.*\s/add",
            "group membership change",
            Severity.HIGH,
            "T1098",
        ),
        (r"schtasks(?:\.exe)?\b.*/create", "scheduled task creation", Severity.MEDIUM, "T1053.005"),
        (
            r"\\\\127\.0\.0\.1\\(?:admin|c)\$",
            "Impacket-style output redirection",
            Severity.HIGH,
            "T1569.002",
        ),
        (r"mimikatz|sekurlsa|lsadump|invoke-mimikatz", "Mimikatz", Severity.CRITICAL, "T1003"),
        (
            r"add-mppreference\b.*-exclusion|set-mppreference\b.*-disable",
            "Defender tampering",
            Severity.HIGH,
            "T1562.001",
        ),
        (
            r"\bwevtutil(?:\.exe)?\s+cl\b|clear-eventlog",
            "event log clearing",
            Severity.HIGH,
            "T1070.001",
        ),
        (
            r"\b(?:whoami|nltest|systeminfo|ipconfig\s+/all|net1?(?:\.exe)?\s+(?:user|group|localgroup|view)|quser|query\s+user)\b",
            "discovery command",
            Severity.LOW,
            "T1087",
        ),
    ]
]

# Linux shell commands (sudo COMMAND=, etc.)
SHELL_RULES: list[tuple[re.Pattern[str], str, Severity, str]] = [
    (re.compile(p, re.IGNORECASE), label, sev, tag)
    for p, label, sev, tag in [
        (
            r"\b(?:curl|wget)\b.*\|\s*(?:ba|z|da)?sh\b",
            "download piped to shell",
            Severity.HIGH,
            "T1105",
        ),
        (r"\b(?:curl|wget)\b\s.*https?://", "file download", Severity.MEDIUM, "T1105"),
        (
            r"/(?:tmp|dev/shm|var/tmp)/\S+",
            "execution from world-writable directory",
            Severity.MEDIUM,
            "T1059.004",
        ),
        (r"\bbase64\s+(?:-d|--decode)\b", "base64 decoding", Severity.MEDIUM, "T1140"),
        (
            r"bash\s+-i\s+>&\s*/dev/tcp/|\bnc(?:at)?\b.*\s-e\s|socat\b.*exec",
            "reverse shell",
            Severity.CRITICAL,
            "T1059.004",
        ),
        (
            r"\b(?:useradd|adduser|usermod|passwd|chpasswd)\b",
            "account modification",
            Severity.MEDIUM,
            "T1098",
        ),
        (
            r"/etc/(?:shadow|sudoers)|visudo",
            "sensitive auth file access",
            Severity.HIGH,
            "T1003.008",
        ),
        (r"\bcrontab\b|/etc/cron", "cron modification", Severity.MEDIUM, "T1053.003"),
        (
            r"chmod\s+[0-7]*[4-7][0-7]{3}\b|chmod\s+[ug]?\+s\b",
            "setuid bit",
            Severity.HIGH,
            "T1548.001",
        ),
        (r"authorized_keys", "SSH key persistence", Severity.HIGH, "T1098.004"),
        (
            r"\b(?:history\s+-c|unset\s+HISTFILE)\b|shred\b.*\.log|rm\s+-[rf]+\s+/var/log",
            "log/history tampering",
            Severity.HIGH,
            "T1070",
        ),
    ]
]


def score(text: str, rules=CMDLINE_RULES) -> Verdict:
    v = Verdict()
    for pattern, label, severity, tag in rules:
        if pattern.search(text):
            v.add(severity, label, tag)
    return v


_ENC_ARG = re.compile(r"\s[-/](\w+)\s+([A-Za-z0-9+/=]{8,})")


def decode_powershell(cmdline: str) -> str | None:
    """Decode the argument of -EncodedCommand (or any accepted abbreviation)."""
    for flag, blob in _ENC_ARG.findall(" " + cmdline):
        f = flag.lower()
        if f == "ec" or (len(f) >= 1 and "encodedcommand".startswith(f)):
            try:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
                decoded = raw.decode("utf-16-le")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            decoded = decoded.replace("\x00", "").strip()
            if decoded.isprintable() or "\n" in decoded:
                return decoded
    return None


INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def is_external(ip: str) -> bool:
    """True for routable addresses outside RFC 1918 / loopback / link-local space.

    Documentation ranges (e.g. 203.0.113.0/24) count as external on purpose,
    so they can stand in for attacker infrastructure in samples and tests.
    """
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified:
        return False
    return not any(addr in net for net in INTERNAL_NETWORKS if net.version == addr.version)


def shorten(text: str, limit: int = 180) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
