# Active Directory Enumeration — Fundamentals, Ports & Manual Techniques

**Track:** Mastering OSCP
**Section:** Active Directory — 018
**Topics:** AD Architecture Recap, Privilege Groups, Critical Ports & Nmap Scanning, Tool Arsenal, LDAP Enumeration, SMB Enumeration, Legacy `net` Commands, PowerShell/.NET Directory Queries

---

## 1. Active Directory in One Picture

Picture a large corporate building with hundreds of employees, meeting rooms, server closets, and restricted labs. Instead of handing out physical keys to everyone, the company runs a centralized digital security system:

- A **master directory** knows every employee, their department, and their clearance level.
- **Keycards** are issued based on role — receptionist, IT admin, CEO.
- **Doors** only open if a keycard matches that room's access list.
- **Security guards** — the Domain Controllers — verify every entry request.

**Active Directory (AD)** is exactly this, but for Windows networks. It's Microsoft's directory service, managing:

- User accounts & passwords
- Computers & servers
- Permissions & access controls
- Network resources (shares, printers, applications)
- Authentication & authorization policies

Think of AD as the "brain" of a Windows network — control AD, and you control the organization's entire digital infrastructure.

### 1.1 Core Architecture Concepts

| Concept | Definition | Real-World Analogy |
|---|---|---|
| **Forest** | Top-level container holding one or more domains that share a common schema and configuration | An entire corporation, worldwide |
| **Domain** | A logical grouping of users, computers, and policies under a single namespace (e.g. `corp.local`) | A regional branch office |
| **Tree** | A hierarchy of domains sharing a contiguous DNS namespace | Departmental subdivisions |
| **Organizational Unit (OU)** | A container within a domain used to organize objects and apply Group Policy | Folders in a filing cabinet |
| **Share** | A network-accessible folder exported over SMB | A locked cabinet with a shared key |
| **Domain Controller (DC)** | The server running AD DS — authenticates users and stores the directory database | The security desk plus the master key vault |

### 1.2 Local Groups vs. Domain Groups

| Feature | Local Group | Domain Group |
|---|---|---|
| **Scope** | Exists only on a single machine | Exists across the entire domain |
| **Management** | `lusrmgr.msc` or the local SAM database | ADUC or PowerShell |
| **Authentication** | Validated against the local SAM database | Validated against the Domain Controller |
| **Use Case** | Local admin rights, machine-specific tasks | Cross-machine access, enterprise-wide policy |
| **Example** | `BUILTIN\Administrators` | `CORP\Domain Admins` |

### 1.3 Critical AD Privilege Groups

| Group | Grants |
|---|---|
| **Domain Admins** | Full control of the domain |
| **Enterprise Admins** | Full control of the entire forest |
| **Schema Admins** | Ability to modify the AD schema |
| **Backup Operators** | Backup/restore rights on Domain Controllers — can be abused for a **DCSync** attack |
| **Server Operators** | Manage services running on Domain Controllers |
| **Account Operators** | Create and modify user accounts |
| **Print Operators** | Manage printers, load drivers |

**Domain Admins** is effectively "god mode" for the domain; **Enterprise Admins** is "god mode" for the entire forest. **Backup Operators** deserves special attention from an attacker's perspective — that group's backup rights are sufficient to pull every password hash in the domain via DCSync.

---

## 2. Critical Ports & Nmap Scanning

Active Directory depends on a specific set of ports for authentication, directory queries, file sharing, and remote management.

### 2.1 Essential AD Ports

| Port | Protocol | Service | Purpose |
|---|---|---|---|
| 53 | TCP/UDP | DNS | Domain name resolution |
| 88 | TCP/UDP | Kerberos | Authentication ticketing |
| 135 | TCP | RPC | Remote procedure calls |
| 139 | TCP | NetBIOS | Legacy file/printer sharing |
| 389 | TCP/UDP | LDAP | Directory queries & authentication |
| 445 | TCP | SMB | File sharing, admin shares, RPC over SMB |
| 3268 / 3269 | TCP | Global Catalog | Forest-wide directory searches |
| 5985 / 5986 | TCP | WinRM | PowerShell remoting |

### 2.2 A Targeted AD Discovery Scan

```bash
nmap -sV -sC -p 53,88,135,139,389,445,3268,5985 -oN ad_scan.txt 10.10.10.0/24
```
```
Nmap scan report for dc01.corp.local (10.10.10.10)
Host is up (0.0023s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-01 10:15:22Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows AD LDAP (Domain: CORP.LOCAL, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
3268/tcp open  ldap          Microsoft Windows AD LDAP (Global Catalog)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Ports 389 (LDAP) and 445 (SMB) are the primary enumeration targets.** LDAP reveals the directory structure, users, groups, and policies; SMB reveals shares, admin access, and opens the door to credential relay and Pass-the-Hash attacks.

---

## 3. Tool Arsenal for AD Enumeration

| Tool | Purpose | Installation |
|---|---|---|
| **Nmap** | Network discovery & port scanning | `apt install nmap` |
| **ldapsearch** | LDAP directory queries | `apt install ldap-utils` |
| **smbclient** | SMB share enumeration & access | `apt install smbclient` |
| **NetExec** (formerly CrackMapExec) | AD enumeration, credential spraying, module execution | `pipx install netexec` |
| **PowerView** | PowerShell-based AD reconnaissance | Built into PowerSploit / the AD module |
| **BloodHound** | AD attack path mapping | `apt install bloodhound` + the SharpHound collector |
| **Impacket** | Python AD protocol exploitation | `pipx install impacket` |
| **enum4linux-ng** | SMB/LDAP enumeration wrapper | `apt install enum4linux-ng` |

> **Note:** don't try to memorize every command in this track — there's a genuinely large surface area between Windows and Linux tooling. Save and reference this instead.

---

## 4. A Practical Initial Recon Workflow

Before diving into any single tool, a reliable general sequence for approaching an unknown AD target looks like this:

1. Run **nmap** and check the open ports — **SMB (445)** is the most important one to confirm first.
2. If SMB is open, run **NetExec** against it and check whether any shares are readable.
3. If nothing useful turns up there, check whether **LDAP (389)** is open.
4. If LDAP is open, enumerate domain users through NetExec's SMB module.
5. Take the discovered domain name and add it to `/etc/hosts`, so tools that expect a resolvable domain name work correctly.
6. Use `ldapsearch` to enumerate users, or search for groups directly.

### 4.1 Discovering the Domain Name

```bash
netexec smb <ip> -u Guest -p ''
```

This anonymous/guest authentication attempt against SMB typically reveals the domain name in its banner output, which can then be added to `/etc/hosts`.

---

## 5. LDAP Enumeration (Port 389)

LDAP (Lightweight Directory Access Protocol) is the query language of Active Directory — it allows reading users, groups, OUs, computers, and policies directly.

### 5.1 Anonymous Bind & Base DN Discovery

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base namingContexts
```
```
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectclass=*)
# requesting: namingContexts

dn:
namingContexts: DC=corp,DC=local
namingContexts: CN=Configuration,DC=corp,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=corp,DC=local
namingContexts: DC=DomainDnsZones,DC=corp,DC=local
namingContexts: DC=ForestDnsZones,DC=corp,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 6
# numEntries: 1
```

### 5.2 Enumerating All Users

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```
```
# jdoe, Users, corp.local
dn: CN=jdoe,CN=Users,DC=corp,DC=local
sAMAccountName: jdoe

# asmith, IT, corp.local
dn: CN=asmith,OU=IT,DC=corp,DC=local
sAMAccountName: asmith

# svc_backup, ServiceAccounts, corp.local
dn: CN=svc_backup,OU=ServiceAccounts,DC=corp,DC=local
sAMAccountName: svc_backup

# Administrator, Users, corp.local
dn: CN=Administrator,CN=Users,DC=corp,DC=local
sAMAccountName: Administrator

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 4
```

### 5.3 Enumerating Domain Groups & Members

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=local" "(objectClass=group)" cn member
```
```
# Domain Admins, Users, corp.local
dn: CN=Domain Admins,CN=Users,DC=corp,DC=local
cn: Domain Admins
member: CN=Administrator,CN=Users,DC=corp,DC=local
member: CN=asmith,OU=IT,DC=corp,DC=local

# IT_Support, IT, corp.local
dn: CN=IT_Support,OU=IT,DC=corp,DC=local
cn: IT_Support
member: CN=asmith,OU=IT,DC=corp,DC=local
member: CN=jdoe,CN=Users,DC=corp,DC=local
```

> LDAP enumeration is passive and rarely triggers alerts. Always check for `servicePrincipalName` attributes to spot Kerberoastable accounts, and `userAccountControl` flags to find accounts with `DONT_REQ_PREAUTH` set — a direct path to AS-REP Roasting.

### 5.4 Enumerating Users Without Credentials via NetExec

If a straightforward user enumeration attempt fails to retrieve anything:

```bash
netexec smb <ip> -u Guest -p '' --users
```

If that returns nothing useful, fall back to RID brute-forcing, which walks numeric Relative IDs directly rather than relying on a working enumeration query:

```bash
netexec smb <ip> -u Guest -p '' --rid-brute 10000
```

```
SMB    10.129.228.253    445    DC    498: sequel\Enterprise Read-only Domain Controllers
SMB    10.129.228.253    445    DC    500: sequel\Administrator (SidTypeUser)
SMB    10.129.228.253    445    DC    501: sequel\Guest (SidTypeUser)
SMB    10.129.228.253    445    AC    502: sequel\krbtgt (SidTypeUser)
SMB    10.129.228.253    445    DC    512: sequel\Domain Admins (SidTypeGroup)
SMB    10.129.228.253    445    DC    513: sequel\Domain Users (SidTypeGroup)
SMB    10.129.228.253    445    AC    514: sequel\Domain Guests (SidTypeGroup)
SMB    10.129.228.253    445    DC    515: sequel\Domain Computers (SidTypeGroup)
SMB    10.129.228.253    445    AC    516: sequel\Domain Controllers (SidTypeGroup)
SMB    10.129.228.253    445    DC    517: sequel\Cert Publishers (SidTypeAlias)
SMB    10.129.228.253    445    DC    518: sequel\Schema Admins (SidTypeGroup)
SMB    10.129.228.253    445    DC    519: sequel\Enterprise Admins (SidTypeGroup)
SMB    10.129.228.253    445    DC    520: sequel\Group Policy Creator Owners (SidTypeGroup)
SMB    10.129.228.253    445    DC    521: sequel\Read-only Domain Controllers (SidTypeGroup)
```

`--rid-brute 10000` brute-forces the first 10,000 RIDs, returning every user, group, and built-in account the domain controller will disclose — including the ever-important `krbtgt` account.

---

## 6. SMB Enumeration (Port 445)

SMB (Server Message Block) handles file sharing, admin shares (`C$`, `ADMIN$`), and RPC — it's the backbone of Windows lateral movement.

### 6.1 `smbclient` — Listing Shares

```bash
smbclient -L //10.10.10.15 -N
```
```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Public          Disk      Company shared files
        SYSVOL          Disk      Logon server share
        Backups         Disk      Weekly server backups
SMB1 disabled -- no workgroup available
```

### 6.2 `smbclient` — Accessing a Share

```bash
smbclient //10.10.10.15/Public -N
```
```
smb: \> ls
  .                                   D        0  Wed Feb  1 08:12:33 2024
  ..                                  D        0  Wed Feb  1 08:12:33 2024
  company_policy.pdf                  A   245760  Mon Jan 15 14:22:10 2024
  network_diagram.png                 A   1048576 Tue Jan 23 09:45:12 2024
  credentials.txt.bak                 A      512  Thu Jan 18 11:30:05 2024

smb: \> get credentials.txt.bak
getting file \credentials.txt.bak of size 512 as credentials.txt.bak (1.2 KiloBytes/sec)
smb: \> exit
```

Backup files, old configs, and misplaced text files sitting on open shares are a classic — and frequent — source of plaintext credentials.

### 6.3 NetExec — Enumerating Domain Users via SMB

```bash
netexec smb 10.10.10.0/24 --users
```
```
SMB    10.10.10.10    445    DC01    [*] Windows Server 2019 Standard 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB    10.10.10.15    445    FILE01  [*] Windows Server 2019 Standard 17763 x64 (name:FILE01) (domain:corp.local) (signing:False) (SMBv1:False)
SMB    10.10.10.10    445    DC01    [+] corp.local\jdoe:Password123! (Pwn3d!)
SMB    10.10.10.10    445    DC01    [*] Enumerating domain users
SMB    10.10.10.10    445    DC01    [+] corp.local\administrator
SMB    10.10.10.10    445    DC01    [+] corp.local\jdoe
SMB    10.10.10.10    445    DC01    [+] corp.local\asmith
SMB    10.10.10.10    445    DC01    [+] corp.local\svc_backup
SMB    10.10.10.10    445    DC01    [+] corp.local\krbtgt
```

### 6.4 NetExec — Share & Local Admin Enumeration

```bash
netexec smb 10.10.10.0/24 -u jdoe -p 'Password123!' --shares
```
```
SMB    10.10.10.10    445    DC01    [+] corp.local\jdoe:Password123! (Pwn3d!)
SMB    10.10.10.10    445    DC01    [+] Read: ADMIN$, C$, IPC$, NETLOGON, SYSVOL
SMB    10.10.10.15    445    FILE01  [+] Read: ADMIN$, C$, IPC$, Public, Backups, NETLOGON, SYSVOL
SMB    10.10.10.15    445    FILE01  [+] Write: Public, Backups
```

> NetExec has effectively replaced CrackMapExec and is the modern standard for AD enumeration. Always check `--local-admin` to find machines where the current user already has administrative rights — that's the pivot point for lateral movement.

---

## 7. Legacy Windows `net` Commands

The older, built-in `net` commands provide a fast, low-friction way to pull basic domain information once logged into a domain-joined machine.

```bash
xfreerdp /u:stephanie /d:corp.com /v:192.168.50.75
net user /domain
net user jeffadmin /domain
net group /domain
net group "Sales Department" /domain
```

| Command | What It Shows |
|---|---|
| `net user /domain` | Every user in the domain |
| `net user jeffadmin /domain` | Detailed information about the user `jeffadmin` |
| `net group /domain` | Every group in the domain |
| `net group "Sales Department" /domain` | The members of the "Sales Department" group |

---

## 8. Enumeration with PowerShell & .NET Directly

Beyond dedicated tools, PowerShell's own `.NET` classes can query AD directly — useful in environments where dropping a third-party script isn't practical.

### 8.1 `samAccountType` Reference

The `samAccountType` attribute classifies AD objects — knowing these values lets you filter for specific object types during a raw LDAP query.

| Value | Object Type | Description |
|---|---|---|
| `268435456` | SAM_GROUP_OBJECT | A security group, used to grant permissions to resources |
| `268435457` | SAM_NON_SECURITY_GROUP_OBJECT | A distribution group, used for email distribution lists |
| `805306368` | SAM_USER_OBJECT | A user account |
| `805306369` | SAM_MACHINE_ACCOUNT | A computer account |
| `805306370` | SAM_TRUST_ACCOUNT | A domain trust account, used for inter-domain trust relationships |

### 8.2 Getting the Current Domain

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainObj
```

### 8.3 Identifying the Primary Domain Controller (PDC)

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$PDC
```

### 8.4 Retrieving the Distinguished Name via ADSI

```powershell
([adsi]'').distinguishedName
```

### 8.5 Building a Full LDAP Path

```powershell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```

```
PS C:\Users\stephanie> .\enumeration.ps1
LDAP://DC1.corp.com/DC=corp,DC=com
```

### 8.6 Querying with `DirectoryEntry` & `DirectorySearcher`

```powershell
$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
```

Filtering specifically for user objects with `samAccountType`:

```powershell
$dirsearcher.filter = "samAccountType=805306368"
$dirsearcher.FindAll()
```

### 8.7 Iterating Over Every Property of a Result

```powershell
$result = $dirsearcher.FindAll()

Foreach ($obj in $result) {
    Foreach ($prop in $obj.Properties) {
        $prop
    }
    Write-Host "-------------------------------"
}
```

### 8.8 Displaying a Specific User's Group Memberships

```powershell
$dirsearcher.filter = "name=jeffadmin"
$result = $dirsearcher.FindAll()

Foreach ($obj in $result) {
    Foreach ($prop in $obj.Properties) {
        $prop.memberof
    }
    Write-Host "-------------------------------"
}
```

### 8.9 Wrapping the Logic in a Reusable Function

```powershell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()
}
```

```powershell
Import-Module .\function.ps1

LDAPSearch -LDAPQuery "(samAccountType=805306368)"
LDAPSearch -LDAPQuery "(objectclass=group)"
```

**Searching for members of a specific group:**

```powershell
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
$sales.properties.member
```

If nested groups are found, the same query pattern can be repeated against each nested group to walk the full membership chain.
