# Information Gathering — FTP Enumeration & Exploitation

> **Track:** Mastering OSCP
> **Section:** Information Gathering — 004
> **Topics:** FTP Protocol Basics, Active vs. Passive Mode, TFTP, vsFTPd Configuration, Anonymous Access, File Upload Risks, Footprinting with Nmap

---

## 1. What is FTP?

**FTP (File Transfer Protocol)** is one of the oldest protocols on the internet. Like HTTP and POP, it operates at the **Application Layer**, and its sole purpose is transferring files between a client and a server — accessible either through a browser or dedicated FTP clients.

### How It Works

Establishing an FTP connection opens **two separate channels**:

| Channel | Port | Purpose |
|---|---|---|
| **Control Channel** | TCP/21 | Sends commands from the client and receives status codes from the server |
| **Data Channel** | TCP/20 | Used exclusively for the actual file transfer (upload/download); if interrupted, the transfer can resume after reconnecting |

### Connection Modes

| Mode | Behavior | Drawback / Benefit |
|---|---|---|
| **Active FTP** | Client connects via port 21 and specifies a local port to receive the server's response | A firewall blocking unsolicited inbound connections will break the transfer |
| **Passive FTP** | Server announces a port, and the client initiates the connection to it | Avoids firewall interference since the client always initiates outbound |

### Commands & Status Codes

FTP supports a range of commands (upload, download, directory management, deletion), and the server replies with **status codes** indicating success or failure of each command.

---

## 2. FTP Security Concerns

- **Credentials:** Access typically requires a username and password.
- **Cleartext transmission:** FTP is a **clear-text protocol** — all data, including credentials, is sent unencrypted, making it vulnerable to sniffing under the right network conditions.
- **Anonymous access:** Some servers allow connecting without a password at all, permitting direct upload/download.

---

## 3. TFTP (Trivial File Transfer Protocol)

TFTP is a simplified alternative to FTP, also used for transferring files between client and server — but stripped of almost everything that makes FTP relatively safer.

| Aspect | FTP | TFTP |
|---|---|---|
| **Authentication** | Requires username & password | No authentication or protected login at all |
| **Transport protocol** | TCP (reliable) | UDP (unreliable — relies on application-layer mechanisms to recover from errors) |
| **Permissions** | Full read/write control | Relies solely on OS-level file permissions; works only with shared files/directories accessible to everyone |
| **Encryption** | None by default | None |

> Because TFTP offers essentially no protection, its use is generally limited to trusted local networks.

### TFTP Commands

| Command | Description |
|---|---|
| `connect` | Sets the remote host (and optionally port) for file transfers |
| `get` | Transfers file(s) from the remote host to the local host |
| `put` | Transfers file(s) from the local host to the remote host |
| `quit` | Exits the TFTP client |
| `status` | Shows current status: transfer mode (ASCII/binary), connection state, timeout value, etc. |
| `verbose` | Toggles verbose mode for additional transfer detail |

> Unlike the FTP client, **TFTP has no directory listing functionality** — you need to already know the filenames you want.

---

## 4. vsFTPd — The Default Linux FTP Server

**vsFTPd (Very Secure FTP Daemon)** is one of several FTP server options on Linux, valued for its simplicity and readable configuration — which makes it a good choice for learning.

```bash
sudo apt install vsftpd
```

- Configuration file: `/etc/vsftpd.conf`
- Some settings ship predefined; others are commented out by default.
- Not every possible setting appears in the config file — additional options can be found in the program's `man` page.

> Tip: Installing vsFTPd on a disposable VM is a great way to experiment with its settings hands-on.

### Reading the Config File

```bash
cat /etc/vsftpd.conf | grep -v "#"
```

| Setting | Description |
|---|---|
| `listen=NO` | Run via `inetd`, or as a standalone daemon? |
| `listen_ipv6=YES` | Listen on IPv6? |
| `anonymous_enable=NO` | Enable anonymous access? |
| `local_enable=YES` | Allow local system users to log in? |
| `dirmessage_enable=YES` | Show a directory message when users enter certain directories? |
| `use_localtime=YES` | Use local time instead of GMT? |
| `xferlog_enable=YES` | Log uploads/downloads? |
| `connect_from_port_20=YES` | Connect from port 20 (classic active-mode data port)? |
| `secure_chroot_dir=/var/run/vsftpd/empty` | An empty directory used for chroot-jail security |
| `pam_service_name=vsftpd` | Name of the PAM service vsftpd will use |
| `rsa_cert_file=...` | Path to the RSA certificate used for SSL-encrypted connections |

### `/etc/ftpusers` — Denying Specific Users

This file blocks specific system accounts from logging into the FTP service, even if they exist as valid Linux users:

```bash
cat /etc/ftpusers
```
```
guest
john
kevin
```

---

## 5. Dangerous FTP Settings

FTP servers expose a number of security-relevant settings that can be (mis)used for things like testing firewall behavior, routing, or authentication mechanisms.

### Anonymous Access

Anonymous login is often enabled to let everyone on an internal network share files quickly and casually — no need to manage individual server access, just log in through one shared "anonymous" account.

```ini
anonymous_enable=YES        # Allow anonymous login
anon_upload_enable=YES      # Allow anonymous users to upload files
anon_mkdir_write_enable=YES # Allow anonymous users to create new directories
no_anon_password=YES        # Don't prompt anonymous users for a password
anon_root=/home/username/ftp # Root directory for anonymous sessions
write_enable=YES            # Allow write-related commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, SITE
```

### Related Upload-Ownership Settings

| Setting | Description |
|---|---|
| `dirmessage_enable=YES` | Show a message the first time a user enters a new directory |
| `chown_uploads=YES` | Change ownership of anonymously uploaded files |
| `chown_username=username` | User granted ownership of anonymously uploaded files |
| `local_enable=YES` | Enable local users to log in |
| `chroot_local_user=YES` | Confine local users to their home directory |
| `chroot_list_enable=YES` | Use a list of local users to be chrooted into their home directories |
| `hide_ids=YES` | Displays all UID/GID info in directory listings as `"ftp"` |
| `ls_recurse_enable=YES` | Allow recursive directory listings |

> ⚠️ When `hide_ids=YES` is set, real UID/GID values are masked as `ftp` in listings — making it harder to determine who actually owns uploaded files, which is useful for hiding operator identity but frustrating for legitimate audits.

---

## 6. Anonymous FTP Access in Practice

Using the standard `ftp` client, you can log in with the `anonymous` account if the server allows it. This is typically meant for trusted internal environments to make file sharing faster — often intended as a temporary convenience.

When connecting, the server responds with code **220** along with a banner, which may reveal:
- A service description
- The version number
- The server's operating system

> Anonymous access is the single most common FTP misconfiguration you'll encounter. Even if uploading/downloading is restricted, simply being able to **list** directory contents can hand over valuable reconnaissance information.

### Example Session

```
$ ftp 10.10.10.10
Connected to 10.10.10.10.
220 "Welcome to the HTB Academy vsFTP service."
Name (10.10.10.10:cry0l1t3): anonymous

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls

200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r-- 1 1002 1002 8138592 Sep 14 16:54 Calendar.pptx
drwxrwxr-x 2 1002 1002 4096    Sep 14 16:50 Clients
```

> It's worth occasionally trying the `debug` and `trace` commands during a session — they surface additional detail about what's actually happening under the hood.

---

## 7. Downloading Files

### Downloading a single file

```
ftp> ls

200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxrwxrwx 1 ftp ftp 0     Sep 16 17:24 Calendar.pptx
drwxrwxrwx 4 ftp ftp 4096  Sep 16 17:57 Clients
drwxrwxrwx 2 ftp ftp 4096  Sep 16 18:05 Documents
drwxrwxrwx 2 ftp ftp 4096  Sep 16 17:24 Employees
-rwxrwxrwx 1 ftp ftp 41    Sep 18 15:58 Important Notes.txt
226 Directory send OK.

ftp> get "Important Notes.txt"

local: Important Notes.txt remote: Important Notes.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for Important Notes.txt (41 bytes).
226 Transfer complete.
41 bytes received in 0.00 secs (606.65 kB/s)

ftp> exit
```

### Downloading everything at once

```bash
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.10
```

`wget -m` mirrors the entire directory structure recursively — useful for grabbing an anonymous FTP share in one shot rather than pulling files one at a time.

---

## 8. File Upload Risks

Once connected, it's worth checking whether **uploading** is permitted, not just downloading.

**Why this matters:**
FTP is commonly used on servers (especially web servers) to sync files and give developers quick access. The problem is administrators frequently assume internal network components aren't reachable from the outside — an assumption that often turns out to be wrong, and the misconfiguration sticks around as a result.

**If upload is allowed on a server tied to a website, the risks escalate quickly:**
1. Direct access to the web server's file structure.
2. Uploading malicious files to obtain a **reverse shell**.
3. Executing commands on the underlying system.
4. Potential **privilege escalation** from there.

---

## 9. Footprinting FTP with Nmap

**Footprinting** means gathering information about a service using network scanners — useful even when a service runs on a non-standard port (e.g., FTP not on port 21).

Nmap is the go-to tool here, and its **Nmap Scripting Engine (NSE)** includes a library of scripts targeting specific services, helping identify version, configuration, and potential vulnerabilities.

```bash
# Update the NSE script database
sudo nmap --script-updatedb
```

### Example Scan

```bash
sudo nmap -sV -p21 -sC -A 10.10.10.10
```

```
Starting Nmap 7.80 (https://nmap.org) at 2021-09-16 18:12 CEST
Nmap scan report for 10.129.14.136
Host is up (0.00013s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rwxrwxrwx 1 ftp ftp 8138592 Sep 16 17:24 Calendar.pptx [NSE: writeable]
| drwxrwxrwx 4 ftp ftp 4096    Sep 16 17:57 Clients [NSE: writeable]
| drwxrwxrwx 2 ftp ftp 4096    Sep 16 18:05 Documents [NSE: writeable]
| drwxrwxrwx 2 ftp ftp 4096    Sep 16 17:24 Employees [NSE: writeable]
| -rwxrwxrwx 1 ftp ftp 41      Sep 16 17:24 Important Notes.txt [NSE: writeable]
| -rwxrwxrwx 1 ftp ftp 0       Sep 15 14:57 testupload.txt [NSE: writeable]
|_ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.4
|      Logged in as ftp
```

**What's happening:**
- Nmap uses service fingerprints, banners, and default ports to identify services and trigger the relevant NSE scripts.
- The `ftp-anon` script checks whether anonymous access is possible and lists the root directory contents if so.
- The `ftp-syst` script runs the `STAT` command to pull server configuration/version details.
- `[NSE: writeable]` flags directories/files the anonymous session actually has write access to — a direct pointer toward the upload risks described above.

### Tracing Script Behavior

```bash
sudo nmap -sV -p21 -sC -A 10.10.10.10 --script-trace
```

```
NSE: TCP 10.10.14.4:54226 > 10.129.14.136:21 | CONNECT
NSE: TCP 10.10.14.4:54228 > 10.129.14.136:21 | CONNECT
NSE: TCP 10.10.14.4:54228 < 10.129.14.136:21 | 220 Welcome to HTB-Academy FTP service.
```

`--script-trace` shows exactly which local ports Nmap uses for each parallel NSE script, the commands sent, and the raw responses received — in this example, several scripts connect simultaneously with different timeouts, and the banner comes back on the second connection. If you need finer manual control over the same interaction, tools like **Netcat** or **Telnet** work just as well for talking to the FTP service directly.
