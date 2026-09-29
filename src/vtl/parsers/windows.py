"""Windows event logs: binary .evtx files, or XML exports.

XML exports can come from ``wevtutil qe Security /f:xml`` (a stream of
<Event> elements without a root), ``wevtutil epl`` + conversion, or
``Get-WinEvent ... | ForEach-Object { $_.ToXml() }``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree

from ..correlate import collapse_bursts
from ..detections import decode_powershell, is_external, score, shorten
from ..models import Event, Severity, parse_iso
from . import ParseStats

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive/RDP",
    "11": "CachedInteractive",
}

FAILURE_REASONS = {
    "0xc0000064": "unknown user",
    "0xc000006a": "bad password",
    "0xc000006d": "bad username or password",
    "0xc000006f": "outside logon hours",
    "0xc0000070": "workstation restriction",
    "0xc0000071": "password expired",
    "0xc0000072": "account disabled",
    "0xc0000193": "account expired",
    "0xc0000234": "account locked out",
    "0xc000015b": "logon type not granted",
}

PRIVILEGED_GROUPS = {
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "backup operators",
    "account operators",
    "server operators",
    "remote desktop users",
    "dnsadmins",
    "group policy creator owners",
}

SUSPICIOUS_NETWORK_PROCS = re.compile(
    r"\\(?:powershell|pwsh|cmd|rundll32|regsvr32|mshta|certutil|wscript|cscript|bitsadmin|msbuild|installutil)\.exe$",
    re.IGNORECASE,
)

SERVICE_SUSPICIOUS = re.compile(
    r"%comspec%|cmd(?:\.exe)?\s+/[qcr]|powershell|\\\\127\.0\.0\.1\\|admin\$|\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\[^\\]+\.exe",
    re.IGNORECASE,
)

BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

SYSTEM_ACCOUNTS = {"system", "local service", "network service", "anonymous logon", "-", ""}


@dataclass
class WinRecord:
    event_id: int
    ts: datetime
    channel: str
    provider: str
    computer: str
    level: str
    data: dict[str, str] = field(default_factory=dict)

    def get(self, *names: str) -> str:
        for n in names:
            v = self.data.get(n)
            if v not in (None, "", "-"):
                return v
        return ""

    @property
    def family(self) -> str:
        c, p = self.channel.lower(), self.provider.lower()
        if "sysmon" in c or "sysmon" in p:
            return "sysmon"
        if "powershell" in c or "powershell" in p:
            return "powershell"
        if "windows defender" in c:
            return "defender"
        if "terminalservices" in c:
            return "rdp"
        if "taskscheduler" in c:
            return "taskscheduler"
        return c  # security, system, ...


@dataclass
class Summary:
    text: str
    severity: Severity = Severity.INFO
    user: str = ""
    src_ip: str = ""
    tags: list[str] = field(default_factory=list)


Handler = Callable[[WinRecord], Summary | None]
HANDLERS: dict[tuple[str, int], Handler] = {}


def handles(family: str, *ids: int) -> Callable[[Handler], Handler]:
    def register(fn: Handler) -> Handler:
        for i in ids:
            HANDLERS[(family, i)] = fn
        return fn

    return register


def _account(r: WinRecord, prefix: str = "Target") -> str:
    user = r.get(f"{prefix}UserName")
    domain = r.get(f"{prefix}DomainName")
    if not user:
        return ""
    return (
        f"{domain}\\{user}"
        if domain and domain.upper() not in ("NT AUTHORITY", "WORKGROUP")
        else user
    )


def _is_machine_or_system(user: str) -> bool:
    u = user.lower().rsplit("\\", 1)[-1]
    return u.endswith("$") or u in SYSTEM_ACCOUNTS or u.startswith(("dwm-", "umfd-"))


def _ip(r: WinRecord) -> str:
    ip = r.get("IpAddress", "SourceAddress", "ClientAddress")
    ip = ip.removeprefix("::ffff:")
    return "" if ip in ("-", "::1", "127.0.0.1") else ip


def _process(cmd_field: str, image: str, parent: str, user: str) -> Summary:
    cmd = cmd_field or image
    v = score(cmd)
    name = image.rsplit("\\", 1)[-1] if image else "?"
    text = f"Process {name}"
    if parent:
        text += f" (parent {parent.rsplit(chr(92), 1)[-1]})"
    decoded = decode_powershell(cmd)
    if cmd_field:
        shown = (
            BASE64_BLOB.sub(lambda m: f"<{len(m.group())} chars base64>", cmd_field)
            if decoded
            else cmd_field
        )
        text += f": {shorten(shown, 200)}"
    if decoded:
        text += f" | decoded: {shorten(decoded, 200)}"
        v.add(Severity.HIGH, "encoded PowerShell", "T1027")
        v.merge(score(decoded))
    if v.labels:
        text += f"  [{', '.join(v.labels)}]"
    return Summary(text, v.severity, user=user, tags=["T1059", *v.tags] if v.labels else [])


# --- Security ------------------------------------------------------------------------------


@handles("security", 4624)
def _logon(r: WinRecord) -> Summary | None:
    user = _account(r)
    ltype = r.get("LogonType")
    ip = _ip(r)
    pkg = r.get("AuthenticationPackageName")
    if pkg.lower() == "negotiate":
        pkg = r.get("LmPackageName") or pkg
    text = f"Successful logon: {user} (type {ltype} {LOGON_TYPES.get(ltype, '')})".replace(
        " )", ")"
    )
    if ip:
        text += f" from {ip}"
    if r.get("WorkstationName"):
        text += f" [{r.get('WorkstationName')}]"
    if pkg:
        text += f" via {pkg}"
    severity = Severity.INFO
    tags = ["T1078"]
    if not _is_machine_or_system(user):
        if ltype in ("3", "10") and ip:
            severity = Severity.LOW
        if ltype == "10":
            tags.append("T1021.001")
        if ltype == "9" and r.get("LogonProcessName").lower().startswith("seclogo"):
            severity = Severity.HIGH
            text += "  [NewCredentials via seclogo - possible pass-the-hash]"
            tags.append("T1550.002")
        if is_external(ip):
            severity = max(severity, Severity.MEDIUM)
            text += "  [external source]"
    return Summary(text, severity, user=user, src_ip=ip, tags=tags)


@handles("security", 4625)
def _logon_failed(r: WinRecord) -> Summary:
    user = _account(r)
    ltype = r.get("LogonType")
    ip = _ip(r)
    status = (
        r.get("SubStatus") if r.get("SubStatus") not in ("0x0", "") else r.get("Status")
    ).lower()
    reason = FAILURE_REASONS.get(status, status)
    text = f"Failed logon: {user} (type {ltype} {LOGON_TYPES.get(ltype, '')})".replace(" )", ")")
    if ip:
        text += f" from {ip}"
    if reason:
        text += f" - {reason}"
    return Summary(text, Severity.LOW, user=user, src_ip=ip, tags=["T1110"])


@handles("security", 4634, 4647)
def _logoff(r: WinRecord) -> Summary | None:
    user = _account(r)
    if _is_machine_or_system(user):
        return None
    return Summary(f"Logoff: {user}", user=user)


@handles("security", 4648)
def _explicit_creds(r: WinRecord) -> Summary:
    subject, target = _account(r, "Subject"), _account(r)
    server = r.get("TargetServerName")
    proc = r.get("ProcessName").rsplit("\\", 1)[-1]
    text = f"Explicit credentials: {subject} used {target}"
    if server and server.lower() not in ("localhost", "-"):
        text += f" for {server}"
    if proc:
        text += f" ({proc})"
    return Summary(text, Severity.LOW, user=target, src_ip=_ip(r), tags=["T1078"])


@handles("security", 4672)
def _special_privs(r: WinRecord) -> Summary | None:
    user = _account(r, "Subject")
    if _is_machine_or_system(user):
        return None
    return Summary(f"Admin-equivalent privileges assigned to {user}", Severity.INFO, user=user)


@handles("security", 4688)
def _proc_4688(r: WinRecord) -> Summary:
    return _process(
        r.get("CommandLine"),
        r.get("NewProcessName"),
        r.get("ParentProcessName"),
        _account(r, "Subject"),
    )


def _service(name: str, image: str, start: str, account: str) -> Summary:
    text = f"Service installed: {name} -> {shorten(image, 200)}"
    if start:
        text += f" ({start})"
    severity = Severity.MEDIUM
    tags = ["T1543.003"]
    if SERVICE_SUSPICIOUS.search(image) or re.fullmatch(r"[A-Za-z0-9]{4,8}", name or ""):
        severity = Severity.HIGH
        text += "  [suspicious service - remote execution tooling?]"
        tags.append("T1569.002")
    return Summary(text, severity, user=account, tags=tags)


@handles("security", 4697)
def _service_4697(r: WinRecord) -> Summary:
    return _service(
        r.get("ServiceName"),
        r.get("ServiceFileName"),
        r.get("ServiceStartType"),
        _account(r, "Subject"),
    )


@handles("security", 4698, 4702)
def _task(r: WinRecord) -> Summary:
    name = r.get("TaskName")
    content = r.get("TaskContent", "TaskContentNew")
    command = ""
    if content:
        cmd = re.search(r"<Command>(.*?)</Command>", content, re.S)
        args = re.search(r"<Arguments>(.*?)</Arguments>", content, re.S)
        command = " ".join(m.group(1).strip() for m in (cmd, args) if m)
    verb = "created" if r.event_id == 4698 else "updated"
    text = f"Scheduled task {verb}: {name}"
    v = score(command)
    if command:
        text += f" -> {shorten(command, 160)}"
    severity = max(Severity.MEDIUM, v.severity)
    if v.labels:
        text += f"  [{', '.join(v.labels)}]"
    return Summary(text, severity, user=_account(r, "Subject"), tags=["T1053.005", *v.tags])


@handles("security", 4720)
def _user_created(r: WinRecord) -> Summary:
    return Summary(
        f"User account created: {_account(r)} by {_account(r, 'Subject')}",
        Severity.MEDIUM,
        user=_account(r, "Subject"),
        tags=["T1136"],
    )


@handles("security", 4722, 4724, 4725, 4726, 4738, 4740, 4767)
def _account_change(r: WinRecord) -> Summary:
    verbs = {
        4722: ("enabled", Severity.LOW),
        4724: ("password reset", Severity.LOW),
        4725: ("disabled", Severity.LOW),
        4726: ("deleted", Severity.MEDIUM),
        4738: ("changed", Severity.INFO),
        4740: ("locked out", Severity.MEDIUM),
        4767: ("unlocked", Severity.INFO),
    }
    verb, severity = verbs[r.event_id]
    text = f"User account {verb}: {_account(r)}"
    if r.event_id == 4740 and r.get("TargetDomainName"):
        text = f"User account locked out: {r.get('TargetUserName')} (caller {r.get('TargetDomainName')})"
    elif _account(r, "Subject"):
        text += f" by {_account(r, 'Subject')}"
    return Summary(text, severity, user=r.get("TargetUserName"), tags=["T1098"])


@handles("security", 4728, 4732, 4756)
def _group_add(r: WinRecord) -> Summary:
    group = r.get("TargetUserName")
    member = r.get("MemberName")
    # MemberName is a DN (CN=eve,OU=...) for domain accounts and empty for local ones
    member = member.split(",", 1)[0].removeprefix("CN=") if member else r.get("MemberSid")
    privileged = group.lower() in PRIVILEGED_GROUPS
    text = f"Added {member} to group {group} by {_account(r, 'Subject')}"
    if privileged:
        text += "  [privileged group]"
    return Summary(
        text,
        Severity.HIGH if privileged else Severity.MEDIUM,
        user=_account(r, "Subject"),
        tags=["T1098"],
    )


@handles("security", 4768)
def _tgt(r: WinRecord) -> Summary | None:
    user, ip = r.get("TargetUserName"), _ip(r)
    if r.get("PreAuthType") == "0" and r.get("Status") == "0x0":
        return Summary(
            f"Kerberos TGT without pre-authentication for {user} from {ip}  [AS-REP roasting?]",
            Severity.MEDIUM,
            user=user,
            src_ip=ip,
            tags=["T1558.004"],
        )
    if r.get("Status") not in ("0x0", ""):
        return Summary(
            f"Kerberos TGT request failed for {user} from {ip} ({r.get('Status')})",
            Severity.LOW,
            user=user,
            src_ip=ip,
        )
    return (
        None
        if _is_machine_or_system(user)
        else Summary(f"Kerberos TGT issued to {user} from {ip}", user=user, src_ip=ip)
    )


@handles("security", 4769)
def _tgs(r: WinRecord) -> Summary | None:
    user, ip, svc = r.get("TargetUserName"), _ip(r), r.get("ServiceName")
    if (
        r.get("TicketEncryptionType").lower() == "0x17"
        and not svc.endswith("$")
        and svc.lower() != "krbtgt"
    ):
        return Summary(
            f"RC4 Kerberos service ticket for {svc} requested by {user} from {ip}  [Kerberoasting?]",
            Severity.MEDIUM,
            user=user,
            src_ip=ip,
            tags=["T1558.003"],
        )
    return None


@handles("security", 4771)
def _preauth_failed(r: WinRecord) -> Summary:
    user, ip = r.get("TargetUserName"), _ip(r)
    return Summary(
        f"Kerberos pre-auth failed: {user} from {ip} ({r.get('Status')})",
        Severity.LOW,
        user=user,
        src_ip=ip,
        tags=["T1110"],
    )


@handles("security", 4776)
def _ntlm(r: WinRecord) -> Summary | None:
    status = r.get("Status").lower()
    if status in ("0x0", ""):
        return None
    user = r.get("TargetUserName")
    return Summary(
        f"NTLM validation failed: {user} from {r.get('Workstation')} - {FAILURE_REASONS.get(status, status)}",
        Severity.LOW,
        user=user,
        tags=["T1110"],
    )


@handles("security", 1102)
def _log_cleared(r: WinRecord) -> Summary:
    user = _account(r, "Subject")
    return Summary(
        f"Security audit log cleared by {user or 'unknown'}",
        Severity.HIGH,
        user=user,
        tags=["T1070.001"],
    )


@handles("system", 104)
def _other_log_cleared(r: WinRecord) -> Summary:
    user = _account(r, "Subject")
    channel = r.get("Channel")
    return Summary(
        f"Event log '{channel}' cleared by {user or 'unknown'}",
        Severity.HIGH,
        user=user,
        tags=["T1070.001"],
    )


@handles("security", 4719)
def _audit_policy(r: WinRecord) -> Summary:
    return Summary(
        f"Audit policy changed ({r.get('SubcategoryGuid') or r.get('SubcategoryId')}): {r.get('AuditPolicyChanges')}",
        Severity.HIGH,
        user=_account(r, "Subject"),
        tags=["T1562.002"],
    )


@handles("security", 5140)
def _share(r: WinRecord) -> Summary:
    share, ip, user = r.get("ShareName"), _ip(r), _account(r, "Subject")
    admin = bool(re.search(r"\\(?:ADMIN|[A-Z])\$$", share, re.I))
    text = f"Network share {share} accessed by {user} from {ip}"
    return Summary(
        text,
        Severity.MEDIUM if admin else Severity.INFO,
        user=user,
        src_ip=ip,
        tags=["T1021.002"] if admin else [],
    )


# --- System / other channels ----------------------------------------------------------------


@handles("system", 7045)
def _service_7045(r: WinRecord) -> Summary:
    return _service(
        r.get("ServiceName"), r.get("ImagePath"), r.get("StartType"), r.get("AccountName")
    )


@handles("powershell", 4104)
def _scriptblock(r: WinRecord) -> Summary | None:
    text = r.get("ScriptBlockText")
    if not text:
        return None
    v = score(text)
    severity = v.severity
    if r.level == "3":  # Warning: PowerShell's own suspicious-content detection fired
        severity = max(severity, Severity.MEDIUM)
        v.labels.append("flagged by PowerShell")
    summary = f"PowerShell script block: {shorten(text, 200)}"
    if v.labels:
        summary += f"  [{', '.join(v.labels)}]"
    return Summary(summary, severity, tags=["T1059.001", *v.tags] if v.labels else ["T1059.001"])


@handles("powershell", 400)
def _ps_engine(r: WinRecord) -> Summary | None:
    host_app = r.get("HostApplication")
    if not host_app:
        m = re.search(r"HostApplication=(.*?)(?:\r?\n|$)", r.get("param3"))
        host_app = m.group(1) if m else ""
    version = r.get("EngineVersion")
    if not version:
        m = re.search(r"EngineVersion=([\d.]+)", r.get("param3"))
        version = m.group(1) if m else ""
    if version.startswith("2."):
        return Summary(
            f"PowerShell v2 engine started (downgrade attack?): {shorten(host_app)}",
            Severity.HIGH,
            tags=["T1562.010"],
        )
    if not host_app:
        return None
    s = _process(host_app, "powershell.exe", "", "")
    s.text = s.text.replace("Process powershell.exe", "PowerShell engine started", 1)
    return s


@handles("sysmon", 1)
def _proc_sysmon(r: WinRecord) -> Summary:
    return _process(r.get("CommandLine"), r.get("Image"), r.get("ParentImage"), r.get("User"))


@handles("sysmon", 3)
def _net(r: WinRecord) -> Summary | None:
    image, dst, port = r.get("Image"), r.get("DestinationIp"), r.get("DestinationPort")
    host = r.get("DestinationHostname")
    name = image.rsplit("\\", 1)[-1]
    target = f"{dst}:{port}" + (f" ({host})" if host else "")
    external = is_external(dst)
    severity = Severity.INFO
    text = f"Network connection: {name} -> {target}"
    if external and SUSPICIOUS_NETWORK_PROCS.search(image):
        severity = Severity.HIGH
        text += "  [scripting/LOLBin process to external host - possible C2]"
    elif external:
        severity = Severity.LOW
    return Summary(
        text,
        severity,
        user=r.get("User"),
        src_ip=r.get("SourceIp"),
        tags=["T1071"] if severity >= Severity.HIGH else [],
    )


@handles("sysmon", 10)
def _proc_access(r: WinRecord) -> Summary | None:
    target = r.get("TargetImage")
    if not target.lower().endswith("\\lsass.exe"):
        return None
    src = r.get("SourceImage").rsplit("\\", 1)[-1]
    return Summary(
        f"LSASS memory access by {src} (GrantedAccess {r.get('GrantedAccess')})  [credential dumping?]",
        Severity.CRITICAL,
        user=r.get("SourceUser"),
        tags=["T1003.001"],
    )


@handles("sysmon", 11)
def _file_created(r: WinRecord) -> Summary | None:
    path = r.get("TargetFilename")
    if not re.search(r"\.(exe|dll|ps1|bat|vbs|js|hta|scr|dmp)$", path, re.I):
        return None
    severity = (
        Severity.MEDIUM
        if re.search(r"\\(temp|appdata|public|programdata)\\", path, re.I)
        else Severity.LOW
    )
    return Summary(
        f"File created by {r.get('Image').rsplit(chr(92), 1)[-1]}: {path}",
        severity,
        user=r.get("User"),
        tags=["T1105"],
    )


@handles("sysmon", 13)
def _registry(r: WinRecord) -> Summary | None:
    key = r.get("TargetObject")
    if not re.search(
        r"\\CurrentVersion\\(Run|RunOnce)\\|\\Winlogon\\(Shell|Userinit)|\\Services\\[^\\]+\\ImagePath",
        key,
        re.I,
    ):
        return None
    return Summary(
        f"Autostart registry value set: {key} = {shorten(r.get('Details'), 120)}",
        Severity.MEDIUM,
        tags=["T1547.001"],
    )


@handles("sysmon", 22)
def _dns(r: WinRecord) -> Summary:
    return Summary(f"DNS query by {r.get('Image').rsplit(chr(92), 1)[-1]}: {r.get('QueryName')}")


@handles("defender", 1116, 1117)
def _defender(r: WinRecord) -> Summary:
    what = "Malware detected" if r.event_id == 1116 else "Defender action taken"
    return Summary(
        f"{what}: {r.get('Threat Name')} in {r.get('Path')}",
        Severity.HIGH,
        user=r.get("Detection User"),
    )


@handles("defender", 5001)
def _defender_off(r: WinRecord) -> Summary:
    return Summary("Defender real-time protection disabled", Severity.HIGH, tags=["T1562.001"])


@handles("rdp", 1149)
def _rdp_auth(r: WinRecord) -> Summary:
    user, ip = r.get("Param1"), r.get("Param3")
    return Summary(
        f"RDP connection authenticated: {user} from {ip}",
        Severity.LOW,
        user=user,
        src_ip=ip,
        tags=["T1021.001"],
    )


@handles("taskscheduler", 106)
def _task_registered(r: WinRecord) -> Summary:
    return Summary(
        f"Scheduled task registered: {r.get('TaskName')} by {r.get('UserContext')}",
        Severity.MEDIUM,
        tags=["T1053.005"],
    )


def _generic(r: WinRecord) -> Summary:
    pairs = [
        f"{k}={shorten(v, 40)}"
        for k, v in r.data.items()
        if v and v != "-" and not k.startswith("_")
    ][:4]
    return Summary(
        f"Event {r.event_id} ({r.provider})" + (f": {', '.join(pairs)}" if pairs else "")
    )


# --- Parsing ----------------------------------------------------------------------------------


def _record_from_xml(elem: ElementTree.Element) -> WinRecord | None:
    system = elem.find(f"{NS}System")
    if system is None:
        return None
    eid = system.find(f"{NS}EventID")
    created = system.find(f"{NS}TimeCreated")
    if eid is None or eid.text is None or created is None or not created.get("SystemTime"):
        return None

    data: dict[str, str] = {}
    event_data = elem.find(f"{NS}EventData")
    if event_data is not None:
        for i, d in enumerate(event_data.findall(f"{NS}Data")):
            data[d.get("Name") or f"param{i + 1}"] = (d.text or "").strip()
    user_data = elem.find(f"{NS}UserData")
    if user_data is not None:
        for leaf in user_data.iter():
            if len(leaf) == 0 and leaf.text and leaf.text.strip():
                data[leaf.tag.rsplit("}", 1)[-1]] = leaf.text.strip()

    provider = system.find(f"{NS}Provider")
    level = system.find(f"{NS}Level")
    return WinRecord(
        event_id=int(eid.text),
        ts=parse_iso(created.get("SystemTime")),
        channel=(system.findtext(f"{NS}Channel") or "").strip(),
        provider=provider.get("Name", "") if provider is not None else "",
        computer=(system.findtext(f"{NS}Computer") or "").strip(),
        level=(level.text or "").strip() if level is not None else "",
        data=data,
    )


_XML_DECL = re.compile(r"<\?xml[^>]*\?>")


def _iter_xml(path: Path, stats: ParseStats) -> Iterator[WinRecord]:
    text = _XML_DECL.sub("", path.read_text(encoding="utf-8-sig", errors="replace"))
    try:
        root = ElementTree.fromstring(f"<vtlroot>{text}</vtlroot>")
    except ElementTree.ParseError as exc:
        stats.warn(f"{path.name}: invalid XML: {exc}")
        return
    for elem in root.iter(f"{NS}Event"):
        rec = _record_from_xml(elem)
        if rec is None:
            stats.skip(f"{path.name}: <Event> without EventID/TimeCreated")
            continue
        yield rec


def _iter_evtx(path: Path, stats: ParseStats) -> Iterator[WinRecord]:
    from Evtx.Evtx import Evtx  # imported lazily: only needed for binary logs

    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                elem = ElementTree.fromstring(record.xml())
                rec = _record_from_xml(elem)
            except Exception as exc:  # corrupt records in carved/dirty logs
                stats.skip(f"{path.name}: unreadable record: {exc}")
                continue
            if rec is not None:
                yield rec


def to_event(rec: WinRecord, origin: str) -> Event | None:
    handler = HANDLERS.get((rec.family, rec.event_id), _generic)
    s = handler(rec)
    if s is None:
        return None
    return Event(
        ts=rec.ts,
        source="Windows",
        code=str(rec.event_id),
        summary=s.text,
        severity=s.severity,
        host=rec.computer.split(".", 1)[0],
        user=s.user,
        src_ip=s.src_ip,
        tags=s.tags,
        origin=origin,
    )


def parse_windows(
    path: Path,
    stats: ParseStats | None = None,
    threshold: int = 5,
) -> list[Event]:
    stats = stats or ParseStats()
    with path.open("rb") as fh:
        magic = fh.read(8)
    records = _iter_evtx(path, stats) if magic.startswith(b"ElfFile") else _iter_xml(path, stats)

    events: list[Event] = []
    for rec in records:
        ev = to_event(rec, path.name)
        if ev is None:
            stats.filtered += 1
            continue
        events.append(ev)
        stats.parsed += 1

    return collapse_bursts(
        events,
        is_failure=lambda e: e.code == "4625",
        is_success=lambda e: e.code == "4624",
        label="Logon brute force",
        threshold=threshold,
    )
