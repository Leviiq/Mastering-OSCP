# Metasploit — Fundamentals & Auxiliary Modules

> **Track:** Mastering OSCP
> **Section:** Metasploit — 001
> **Topics:** Database Setup, `msfconsole` Basics, Workspaces, `db_nmap`, Auxiliary Modules (SMB, SSH), Vulnerabilities & Credentials

---

## Learning Units Covered

- Getting Familiar with Metasploit
- Using Metasploit Payloads
- Performing Post-Exploitation with Metasploit
- Automating Metasploit

**Metasploit** is a framework bundling exploits, payloads, and much more into a single, standardized toolset for developing and executing attacks against vulnerable systems.

---

## 1. Setting Up the Metasploit Database

Metasploit comes preinstalled on Kali Linux, but its database service doesn't start by default. While a database isn't strictly required to run Metasploit, it's genuinely useful — storing target host information and tracking successful exploitation attempts across an entire engagement.

Metasploit uses **PostgreSQL** as its backend database, which is neither active nor enabled at boot time on Kali by default.

### Initializing the Database

```bash
sudo msfdb init
```

```
[+] Starting database
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
```

### Enabling PostgreSQL at Boot

```bash
sudo systemctl enable postgresql
```

```
Synchronizing state of postgresql.service with SysV service script with /lib/systemd/system-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable postgresql
Created symlink /etc/systemd/system/multi-user.target.wants/postgresql.service → /lib/systemd/system/postgresql.service.
```

---

## 2. Launching `msfconsole`

```bash
sudo msfconsole
```

```
=[ metasploit v6.2.20-dev                          ]
+ -- --=[ 2251 exploits - 1187 auxiliary - 399 post ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops       ]
+ -- --=[ 9 evasion                                  ]

Metasploit tip: Use help <command> to learn more about any command
Metasploit Documentation: https://docs.metasploit.com/

msf6 >
```

### Verifying Database Connectivity

```
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
```

### Getting Help

```
msf6 > help
```

Displays the full list of **Core Commands** and **Module Commands** available in the current context.

---

## 3. Workspaces

Workspaces let you keep results from different engagements (or different phases of the same one) neatly separated.

```
msf6 > workspace
```
```
default
```

**Creating a new workspace** (using `-a`):

```
msf6 > workspace -a pen200
[*] Added workspace: pen200
[*] Workspace: pen200
```

---

## 4. Populating the Database with `db_nmap`

`db_nmap` is a wrapper around Nmap that runs directly inside Metasploit and automatically saves the results into the active workspace's database — using the exact same syntax as standalone Nmap.

```
msf6 > db_nmap -A 192.168.50.202
[*] Nmap: Starting Nmap 7.92 (https://nmap.org) at 2022-07-28 03:48 EDT
[*] Nmap: Nmap scan report for 192.168.50.202
[*] Nmap: Host is up (0.11s latency).
[*] Nmap: Not shown: 993 closed tcp ports (reset)
[*] Nmap: PORT   STATE SERVICE VERSION
[*] Nmap: 21/tcp open  ftp?
```

### Reviewing Discovered Hosts

```
msf6 > hosts
```

```
Hosts
=====
address          mac  name  os_name         os_flavor  os_sp  purpose  info  comments
192.168.50.202                Windows              2016 server
```

### Reviewing Discovered Services

```
msf6 > services
```

```
Services
========
host             port  proto  name           state  info
192.168.50.202   21    tcp    ftp            open
192.168.50.202   135   tcp    msrpc          open   Microsoft Windows RPC
192.168.50.202   139   tcp    netbios-ssn    open   Microsoft Windows netbios-ssn
192.168.50.202   445   tcp    microsoft-ds   open
192.168.50.202   3389  tcp    ms-wbt-server  open   Microsoft Terminal Services
192.168.50.202   5357  tcp    http           open   Microsoft HTTPAPI httpd 2.0 (SSDP)
```

> Both `hosts` and `services` support filtering (e.g., `-p` for a specific port), which becomes very useful once a database has accumulated results from many targets.

---

## 5. Auxiliary Modules

Metasploit ships with hundreds of **auxiliary modules** covering protocol enumeration, port scanning, fuzzing, sniffing, and more — organized under hierarchies like `gather/` (information gathering) and `scanner/` (scanning/enumeration of services).

### Listing All Auxiliary Modules

```
msf6 > show auxiliary
```

Returns a very long list — narrowing it down with `search` is essential in practice.

### Searching for Specific Modules

```
msf6 > search type:auxiliary smb
```

```
#   Name                              Disclosure Date  Rank    Check  Description
52  auxiliary/scanner/smb/smb_enumshares                normal  No     SMB Share Enumeration
53  auxiliary/fuzzers/smb/smb_tree_connect_corrupt       normal  No     SMB Tree Connect Request Corruption
54  auxiliary/fuzzers/smb/smb_tree_connect               normal  No     SMB Tree Connect Request Fuzzer
55  auxiliary/scanner/smb/smb_enumusers                  normal  No     SMB User Enumeration (SAM EnumUsers)
56  auxiliary/scanner/smb/smb_version
```

### Activating a Module

A module can be activated either by its full name or by the index number shown in `search` results:

```
msf6 > use 56
msf6 auxiliary(scanner/smb/smb_version) >
```

### Getting Module Info & Options

```
msf6 auxiliary(scanner/smb/smb_version) > info
```

```
Name: SMB Version Detection
Module: auxiliary/scanner/smb/smb_version
License: Metasploit Framework License (BSD)
Rank: Normal

Basic options:
Name      Current Setting  Required  Description
RHOSTS                     yes       The target host(s)
THREADS   1                yes       The number of concurrent threads (max one per host)
```

```
msf6 auxiliary(scanner/smb/smb_version) > show options
```

### Setting & Unsetting Options

```
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.50.202
RHOSTS => 192.168.50.202
```

**Automating option values from the database** — instead of setting `RHOSTS` manually, populate it directly from prior scan results (every host with port 445 open):

```
msf6 auxiliary(scanner/smb/smb_version) > unset RHOSTS
Unsetting RHOSTS...

msf6 auxiliary(scanner/smb/smb_version) > services -p 445 --rhosts
Services
========
host            port  proto  name          state  info
192.168.50.202  445   tcp    microsoft-ds  open

RHOSTS => 192.168.50.202
```

### Running the Module

```
msf6 auxiliary(scanner/smb/smb_version) > run
```

```
[*] 192.168.50.202:445 - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.1.1)
    (compression capabilities:LZNT1, Pattern_V1) (encryption capabilities:AES-256-GCM)
    (signatures:optional) (guid:{e09176d2-9a06-427d-9b70-f08719643f4d}) (authentication domain:BRUTE2)
[*] 192.168.50.202: - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Checking Automatically Detected Vulnerabilities

```
msf6 auxiliary(scanner/smb/smb_version) > vulns
```

```
Vulnerabilities
===============
Timestamp                Host            Name                            References
2022-07-28 10:17:41 UTC  192.168.50.202  SMB Signing Is Not Required     server-message-block-signing
```

> Metasploit automatically cross-references certain scan results against known weaknesses (like SMB signing not being enforced) and logs them under `vulns` — worth checking after every auxiliary scan.

---

## 6. Brute-Forcing SSH with an Auxiliary Module

As an alternative to Hydra (covered in password attacks), Metasploit can run the same kind of dictionary attack natively.

### Finding the Right Module

```
msf6 > search type:auxiliary ssh
```

```
Matching Modules
================
#   Name                                       Disclosure Date  Rank    Check  Description
15  auxiliary/scanner/ssh/ssh_login                              normal  No     SSH Login Check Scanner
16  auxiliary/scanner/ssh/ssh_identify_pubkeys                    normal  No     SSH Public Key Acceptance Scanner
17  auxiliary/scanner/ssh/ssh_login_pubkey                        normal  No     SSH Login Public Key Scanner
```

### Configuring the Module

```
msf6 > use 15
msf6 auxiliary(scanner/ssh/ssh_login) > show options
```

Assuming the username `george` was already identified beforehand:

```
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
PASS_FILE => /usr/share/wordlists/rockyou.txt

msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME george
USERNAME => george

msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.50.201
RHOSTS => 192.168.50.201

msf6 auxiliary(scanner/ssh/ssh_login) > set RPORT 2222
RPORT => 2222
```

### Reviewing Captured Credentials

```
msf6 auxiliary(scanner/ssh/ssh_login) > creds
```

```
Credentials
===========
host            origin          service      public  private     realm  private_type  JtR Format
192.168.50.201  192.168.50.201  2222/tcp (ssh)  george  chocolate          Password
```

> Metasploit automatically stores every valid credential it finds directly in the database, along with the associated host, service, and credential type — no manual note-taking required.

---

## Next Steps

With database setup, workspaces, and auxiliary modules covered, the next part moves into Metasploit's core purpose: **exploit modules**, **sessions**, **payloads** (staged vs. non-staged), the **Meterpreter** payload, and the difference between bind and reverse shells.
