# Information Gathering — SNMP Enumeration

> **Track:** Mastering OSCP
> **Section:** Information Gathering — 005
> **Topics:** SNMP Fundamentals, MIBs & OIDs, SNMP Versions, Community Strings, Enumeration Tools, Detection & Mitigation

---

## Introduction

SNMP (Simple Network Management Protocol) enumeration is a critical phase of information gathering during a penetration test. SNMP is the standard protocol for managing network-connected devices — routers, switches, servers, printers — letting administrators monitor performance, identify connected devices, and collect configuration/statistical data.

When SNMP isn't properly secured, attackers can abuse it to enumerate sensitive information about a target system: OS details, running services, user accounts, installed software, and even a map of the internal network. This is most commonly possible because of weak or default **community strings** (like `public` or `private`) left in place.

This guide covers SNMP enumeration techniques end-to-end: the common tools and commands, the types of information that can be extracted, and effective detection/mitigation strategies.

---

## 1. SNMP & MIB Fundamentals

SNMP operates on a **client/server model**. An **SNMP agent** runs on the managed device, and an **SNMP manager** queries that agent to collect information. The retrievable information is organized into **Management Information Bases (MIBs)** — structured collections of manageable objects. Each object within a MIB is identified by a unique **Object Identifier (OID)**.

During enumeration, an attacker typically uses **community strings** to access MIB data. `public` and `private` are the two most common — and most dangerous — community strings when left at their defaults.

### 1.1. Object Identifiers (OIDs)

An OID represents a node in a hierarchical namespace. A sequence of numbers uniquely identifies each node, pinpointing its location within the tree — the longer the sequence, the more specific the information. Many nodes higher up the tree contain nothing but references to the nodes beneath them. OIDs are made up of integers, conventionally linked using dot notation. Many MIBs and their associated OIDs can be looked up in the **Object Identifier Registry**.

OIDs function as unique addresses for retrieving specific pieces of information from a MIB. Below are common OIDs that can expose sensitive data on Windows systems:

| OID | Description | Information Exposed |
|---|---|---|
| `1.3.6.1.2.1.1.1.0` | System Description | OS, kernel version, hardware info |
| `1.3.6.1.2.1.1.5.0` | System Name | Device hostname |
| `1.3.6.1.2.1.1.6.0` | System Location | Physical location (if configured) |
| `1.3.6.1.2.1.25.1.6.0` | System Processes | List of all running processes |
| `1.3.6.1.2.1.25.4.2.1.2` | Running Programs | PIDs and names of running programs |
| `1.3.6.1.2.1.25.4.2.1.4` | Process Path | File paths of running executables |
| `1.3.6.1.2.1.25.2.3.1.4` | Storage Units | Drive/storage info (size, free space) |
| `1.3.6.1.2.1.25.6.3.1.2` | Software Name | List of installed software |
| `1.3.6.1.4.1.77.1.2.25` | User Accounts | Local user account names |
| `1.3.6.1.2.1.6.13.1.3` | TCP Local Ports | Local TCP ports the system is listening on |
| `1.3.6.1.2.1.4.20.1.3` | IP Address Table | Configured IP addresses on interfaces |
| `1.3.6.1.2.1.2.2.1.6` | MAC Addresses | MAC addresses of network interfaces |
| `1.3.6.1.2.1.25.3.2.1.3` | Installed Software Description | Detailed descriptions of installed software |

**Potential attack scenarios using OIDs:**

- **Vulnerability discovery from software versions** — OIDs `1.3.6.1.2.1.25.6.3.1.2` and `1.3.6.1.2.1.25.3.2.1.3` reveal installed software and versions. Finding an outdated version with a known CVE opens the door to exploitation.
- **Username harvesting for brute-force/spraying** — OID `1.3.6.1.4.1.77.1.2.25` exposes user account names, which can be used to build a username list for brute-force or password-spraying attacks against other services (SSH, RDP, SMB).
- **Internal network mapping** — OIDs like `1.3.6.1.2.1.4.20.1.3` (IP address table) and `1.3.6.1.2.1.2.2.1.6` (MAC addresses) help build a picture of the internal network layout, identify subnets and connected hosts, and support lateral movement.
- **Identifying sensitive services** — OID `1.3.6.1.2.1.6.13.1.3` exposes open ports, helping an attacker spot listening services (databases, web servers, management interfaces) worth targeting.
- **Sensitive system disclosure** — OIDs like `1.3.6.1.2.1.1.1.0` (system description) reveal OS and kernel details, useful for selecting appropriate privilege escalation exploits.

### 1.2. SNMP Versions

SNMP has evolved through several versions, each improving on security.

#### SNMPv1

The original version of the protocol, still in use on many small networks today. It supports retrieving information from network devices, allows device configuration, and provides **traps** (event notifications). However, SNMPv1 has **no built-in authentication mechanism** — anyone with network access can read and modify network data — and **no encryption**, meaning everything is sent in plaintext and easily intercepted.

**Potential attack scenario (SNMPv1):**
- **Intercepting community strings** — with no encryption, tools like Wireshark can capture SNMP traffic. A captured valid community string (e.g., `public`/`private`) grants the attacker device access.
- **Remote configuration tampering** — with a write-capable community string (`private` or a custom one), attackers can remotely modify device configuration — potentially disrupting service or altering firewall rules.

#### SNMPv2c

An extension building on earlier SNMPv2 variants. The "c" stands for **community-based SNMP**. Security-wise, SNMPv2c is on par with SNMPv1, extended with functionality from the now-obsolete party-based SNMP. The core weakness carries over: the community string that provides "security" is still transmitted in plaintext, with no built-in encryption.

**Potential attack scenario (SNMPv2c):**
- **Same exposure as SNMPv1** — no encryption or strong authentication means the same interception and configuration-tampering attacks apply.
- **Exploiting weak community strings** — still the primary weak point; attackers can brute-force or dictionary-attack weak community strings.

#### SNMPv3

Security was significantly improved in SNMPv3 with username/password authentication and encrypted data transport (via a pre-shared key). The trade-off is considerably more configuration complexity compared to v2c.

**Potential attack scenario (SNMPv3 — if misconfigured):**
- **Guessing weak credentials** — default or weak SNMPv3 usernames/passwords can still be guessed.
- **Exploiting implementation flaws** — vulnerabilities in the SNMPv3 agent software itself may be exploitable even with strong configuration.
- **Pre-shared key theft** — if an attacker gains access to the host running the SNMPv3 agent, they may be able to extract the pre-shared key used for encryption/authentication.

### 1.3. Community Strings

Community strings function essentially as passwords, determining whether requested information can be viewed. Many organizations still rely on SNMPv2 because migrating to SNMPv3 is often considered too complex, while the service still needs to remain active — a tension that creates ongoing risk. A lack of awareness among administrators about how this information can be retrieved and abused only compounds the problem. And since the data itself isn't encrypted in transit, any community string sent across the network can be intercepted and read.

#### 1.3.1. Dangerous Settings

| Setting | Description | Attack Scenario |
|---|---|---|
| `rwuser noauth` | Grants access to the full OID tree with no authentication required | Any attacker with network access can query the device and modify its configuration without credentials — full control via SNMP |
| `rwcommunity <string>` | Grants full OID tree access regardless of request origin, but restricted to a specific IPv4 address | If an attacker can spoof that IP (or pivot through a host with it), they gain full read/write access via the community string |
| `rwcommunity6 <string>` | Same as `rwcommunity`, but for IPv6 | Same scenario, targeting IPv6 environments — attackers with IPv6 network access or spoofing capability can exploit this |

---

## 2. SNMP Enumeration Techniques

### 2.1. Nmap Scan for UDP Port 161

SNMP typically runs on **UDP port 161**. Nmap can identify hosts with this port open, indicating an active SNMP agent.

```bash
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
```

| Flag | Purpose |
|---|---|
| `sudo` | Root privileges are typically required for UDP scanning |
| `-sU` | Specifies a UDP scan |
| `--open` | Only shows ports detected as "open" |
| `-p 161` | Scans only port 161 |
| `192.168.50.1-254` | Target IP range |
| `-oG open-snmp.txt` | Saves output in grepable format |

### 2.2. Community String Enumeration with `onesixtyone`

`onesixtyone` is a fast tool for brute-forcing common community strings to identify valid ones. `public` and `private` remain the most common defaults.

```bash
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips
```

| Piece | Purpose |
|---|---|
| `echo public > community` | Creates a `community` file with the string "public" |
| `echo private >> community` | Appends "private" to the same file |
| `echo manager >> community` | Appends "manager" to the same file |
| `for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips` | Generates an `ips` file listing `192.168.50.1-254` |
| `onesixtyone -c community -i ips` | Runs the tool: `-c community` specifies the wordlist, `-i ips` specifies the target IP list |

**Using a bigger SecLists wordlist for more coverage:**

```bash
onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
```

- `-c /opt/useful/seclists/Discovery/SNMP/snmp.txt` — path to the SecLists community-string wordlist
- `10.129.14.128` — target IP

Any device that responds to one of the tried strings gets reported, indicating an exploitable weakness.

### 2.3. Automated Enumeration with `snmpwalk`

`snmpwalk` is a powerful command-line tool for querying SNMP agents and retrieving sets of MIB information. It can pull data from a specific OID or "walk" from a root OID to retrieve everything available beneath it.

```bash
snmpwalk -c public -v1 -t 10 192.168.50.151
```

| Flag | Purpose |
|---|---|
| `-c public` | Community string used for access |
| `-v1` | Use SNMPv1 |
| `-t 10` | 10-second timeout |
| `192.168.50.151` | Target IP |

### 2.4. Targeted Enumeration Scenarios with `snmpwalk` and OIDs

`snmpwalk` combined with specific OIDs can pull detailed, sensitive information about a Windows system:

**Enumerating Windows users:**
```bash
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
```
Useful for building a username list for password-guessing/brute-force attacks.

**Enumerating Windows processes:**
```bash
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
```
Includes process names and PIDs — helps identify installed services/applications that might be vulnerable.

**Enumerating installed software:**
```bash
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2
```
Can reveal outdated software versions with known vulnerabilities.

**Enumerating open ports:**
```bash
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
```
Complements port-scan data and provides insight into active services.

### 2.5. Impact & Post-Exploitation

Information gathered through SNMP enumeration feeds into multiple stages of the attack chain:

- **Vulnerability identification** — outdated software/known CVEs revealed via installed programs and processes.
- **Password guessing/brute-forcing** — valid usernames obtained can be used for credential attacks against other services.
- **Network mapping** — understanding the internal infrastructure via device data.
- **Service discovery** — identifying active services and open ports for further recon/exploitation.
- **Default configuration discovery** — identifying default/weak community strings permitting unauthorized access.

---

## 3. Detection & Mitigation

### 3.1. Detection

- **Monitor SNMP traffic** — use IDS/IPS or network monitoring tools to flag unusual SNMP traffic, particularly from unauthorized sources or attempts using many different community strings (a sign of brute-forcing).
- **Monitor SNMP agent logs** — review agent logs on devices for failed authentication attempts or unusual information requests.

### 3.2. Mitigation

- **Change default community strings** — replace defaults like `public`/`private` with strong, unique, complex strings, using separate strings for read vs. write access.
- **Disable SNMP if unnecessary** — if SNMP management isn't required for a given device, disable the agent to reduce attack surface.
- **Apply Access Control Lists (ACLs)** — configure the SNMP agent to only accept requests from trusted, authorized IPs (e.g., specific network management servers), blocking queries from other networks.
- **Use SNMPv3** — migrate to SNMPv3 for encryption, strong authentication, and the elimination of weak community strings. SNMPv1/v2c provide neither encryption nor strong authentication.
- **Patch regularly** — keep SNMP agents and the underlying OS updated to fix known vulnerabilities that could be leveraged in SNMP enumeration attacks.

---

## Conclusion

SNMP enumeration is a powerful technique attackers can use to gather large amounts of sensitive information about devices and networks. By understanding SNMP fundamentals and using tools like Nmap, `onesixtyone`, and `snmpwalk`, a penetration tester can identify potential weaknesses and move deeper into the target environment.

From a defensive standpoint, this underscores the importance of properly securing SNMP: organizations should go beyond simply changing default community strings, adopt SNMPv3, enforce strict ACLs, and disable the service entirely where it isn't needed. Careful monitoring of SNMP traffic and awareness of the risks associated with this protocol are essential to keeping network infrastructure secure.
