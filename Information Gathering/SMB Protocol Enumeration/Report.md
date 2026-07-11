# Information Gathering — SMB Enumeration

> **Track:** Mastering OSCP
> **Section:** Information Gathering — 002
> **Topics:** SMB Protocol, Samba/CIFS, Configuration Risks, Footprinting, `rpcclient`, User/RID Enumeration

---

## Introduction

The OSCP syllabus touches on SMB only briefly, but it's a protocol worth understanding in depth — misconfigured SMB shares and anonymous access are among the most common real-world footholds in Windows-heavy environments.

---

## 1. What is SMB?

**SMB (Server Message Block)** is a client-server protocol used to share files, folders, printers, and other resources across a network — primarily on **Windows** systems. Enumerating SMB can reveal hostnames, domain names, usernames, and available shares.

**How it works:**
- The client connects to an SMB server.
- A connection is established and messages are exchanged.
- Over IP networks, SMB runs on top of **TCP**, beginning with a standard **TCP three-way handshake**.

**Permissions:**
SMB relies on **Access Control Lists (ACLs)** to define share-level permissions (Read, Execute, Full Control, etc.).

> ⚠️ Share-level permissions can differ from the local filesystem permissions on the server itself — a share can appear more (or less) permissive than the underlying files actually are.

---

## 2. Samba & CIFS

| Term | Description |
|---|---|
| **Samba** | The implementation of the SMB protocol on Linux/Unix systems, enabling interoperability between Linux and Windows. |
| **CIFS** | A specific dialect of SMB introduced by Microsoft, most closely associated with **SMBv1**. Functions as a "share" service within Samba. |

### Ports Used

| Port | Purpose |
|---|---|
| TCP/137 | NetBIOS Name Service |
| TCP/138 | NetBIOS Datagram Service |
| TCP/139 | NetBIOS Session Service |
| TCP/445 | SMB over TCP (modern SMB/CIFS) |

### SMB Versions

| Version | Supported OS | Key Features |
|---|---|---|
| CIFS | Windows NT 4.0 | Communication via NetBIOS interface |
| SMB 1.0 | Windows 2000 | Communication via NetBIOS interface |
| SMB 2.0 | Windows Vista, Server 2008 | Direct connection via TCP |
| SMB 2.1 | Windows 7, Server 2008 R2 | Performance upgrades, improved message signing, caching |
| SMB 3.0 | Windows 8, Server 2012 | Locking mechanisms |
| SMB 3.0.2 | Windows 8.1, Server 2012 R2 | Multichannel connections, end-to-end encryption, remote storage access |
| SMB 3.1.1 | Windows 10, Server 2016 | Integrity checking, AES-128 encryption |

> SMB1 is legacy and considered relatively insecure; SMB3 is the current recommended standard.

---

## 3. Evolution of Samba

| Version | Capability |
|---|---|
| **Samba 3** | Can join an Active Directory domain as a member. |
| **Samba 4** | Can function as a full **Active Directory Domain Controller**. |

---

## 4. Samba Daemons

| Daemon | Responsible For |
|---|---|
| `smbd` | File sharing, printer sharing, SMB session management |
| `nmbd` | NetBIOS services, device discovery, network integration |

---

## 5. Workgroups & NetBIOS

- **Workgroup** — a group of machines that share resources with each other over SMB. Multiple workgroups can coexist on the same network.
- **NetBIOS** — a legacy communication interface (developed by IBM) that lets machines register hostnames and discover one another. It relies on **NBNS (NetBIOS Name Service)**, which later evolved into **WINS (Windows Internet Name Service)**.

---

## 6. Samba Configuration

Samba has a **Global Configuration** section that applies to all shares, but individual shares can override these settings — and misconfigured overrides are a common source of vulnerabilities.

### Example default configuration

```bash
cat /etc/samba/smb.conf | grep -v "#\|\;"
```

```ini
[global]
    workgroup = DEV.INFREIGHT.HTB
    server string = DEVSMB
    log file = /var/log/samba/log.%m
    max log size = 1000
    logging = file
    panic action = /usr/share/samba/panic-action %d

    server role = standalone server
    obey pam restrictions = yes
```

### Common configuration directives

| Directive | Description | Example |
|---|---|---|
| `[sharename]` | Name of the share as it appears on the network | `[share]` |
| `workgroup` | Workgroup/domain shown when users browse for the share | `WORKGROUP/DOMAIN` |
| `/path` | Server-side path the share exposes | `/path/here` |
| `server string` | Descriptive text shown when connecting to the server | `STRING` |
| `unix password sync` | Whether to sync the Linux system password with the SMB password | `yes` |
| `usershare allow guests` | Allow guest (unauthenticated) users to access the share | `yes` |
| `map to guest` | Automatically map failed logins (unknown username) to the guest account | `bad user` |
| `browseable` | Whether the share appears in the list of available shares | `yes` |
| `guest ok` | Allow connecting without a password | `yes` |
| `read only` | Restrict users to read-only access | `yes` |
| `create mask` | Default permissions for newly created files | `0700` |

### Dangerous configuration values

| Setting | Meaning |
|---|---|
| `browseable = yes` | Allows listing all available shares |
| `read only = no` | Permits creating/modifying files |
| `writable = yes` | Allows users to create/modify files |
| `guest ok = yes` | Allows connecting without a password |
| `enable privileges = yes` | Honors privileges assigned to a specific SID |
| `create mask = 0777` | New files get full read/write/execute permissions for everyone |
| `directory mask = 0777` | New directories get full permissions for everyone |
| `logon script = script.sh` | Script executed automatically on user login |
| `magic script = script.sh` | Script executed when a designated file is closed |
| `magic output = script.out` | Where the "magic script" output gets stored |

> A setting that makes a share more convenient to use (`browseable = yes`, `guest ok = yes`) almost always increases the attack surface. If an attacker gains any foothold, an overly-browseable, guest-accessible share hands them easy reconnaissance.

---

## 7. Footprinting SMB

### Nmap — initial discovery

```bash
# Scan an IP range for common SMB ports
nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
```

This scans TCP/139 (NetBIOS Session Service) and TCP/445 (SMB over TCP) across the range.

```bash
# UDP 137 (NetBIOS Name Service) enumeration
sudo nbtscan -r 192.168.50.0/24
```

```bash
# List available Nmap SMB scripts
ls -1 /usr/share/nmap/scripts/smb*
```

```bash
# Identify the OS and other host details
nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
```

```bash
# List available shares on a target (from Windows)
net view \\dc01 /all
```

> Nmap is a great starting point, but it won't surface everything — manual enumeration is still necessary for a complete picture.

---

## 8. `rpcclient` — MS-RPC Interaction

`rpcclient` interacts with SMB's **MS-RPC** services, allowing you to pull:
- Usernames
- Groups
- SIDs
- RIDs
- Domain information
- System settings

---

## 9. Risks of Anonymous Access

If a server permits **anonymous access**, an attacker may be able to extract:
- Usernames
- Domain information
- RIDs (Relative Identifiers)
- Network details

This information directly enables follow-up attacks such as:
- Brute-forcing
- Password spraying
- Credential attacks

---

## 10. User Enumeration via `rpcclient`

Some `rpcclient` commands require authentication, but the following often works even with limited access:

```
queryuser <RID>
```

Example:
```
rpcclient $> queryuser 0x3e8
```

This returns user details based on the RID.

---

## 11. Brute-Forcing RIDs

A Bash script can automate trying a large range of RID values:

1. Try one RID after another.
2. Send a `queryuser` request for each.
3. Extract any valid usernames returned.

**Example results:**
- `sambauser`
- `mrb3n`
- `cry0l1t3`

This is one of the most common **user enumeration** techniques when anonymous access is permitted.

---

## 12. `enum4linux-ng`

Built on the older **enum4linux**, this tool automates the SMB enumeration process, collecting:

- Users
- Groups
- Shares
- SID
- RIDs
- Domain information
- OS information

> It saves significant time by automatically running many of the same `rpcclient`, `smbclient`, and `net` commands you'd otherwise run manually — but it doesn't cover every scenario, so manual verification is still valuable.

---

## 13. Manual SMB Enumeration Walkthrough

A practical step-by-step approach:

1. Run a standard Nmap scan against the target looking for ports **445**, **139**, or **137**.
2. Run Nmap's SMB discovery script to pull the hostname:
   ```bash
   nmap -p 445 --script smb-os-discovery <target>
   ```
3. List available shares. If you have valid credentials, authenticate; otherwise try anonymous (`-N`):
   ```bash
   smbclient -N -L //<target-ip>
   ```
4. If shares are returned, connect to one of them:
   ```bash
   smbclient -N //<target-ip>/<share-name>
   ```
5. Once inside a session, type `help` to see the available commands (`get`, `put`, `ls`, `cd`, etc.).
