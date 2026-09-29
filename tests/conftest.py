from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def samples() -> Path:
    return SAMPLES


def win_event(
    eid,
    ts,
    data=None,
    channel="Security",
    provider="Microsoft-Windows-Security-Auditing",
    level=0,
    computer="HOST1.corp.local",
):
    """Build one Windows <Event> XML element as exported by wevtutil."""
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in (data or {}).items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        f"<Provider Name='{provider}'/><EventID>{eid}</EventID><Level>{level}</Level>"
        f"<TimeCreated SystemTime='{ts}'/><Channel>{channel}</Channel><Computer>{computer}</Computer>"
        f"</System><EventData>{fields}</EventData></Event>"
    )
