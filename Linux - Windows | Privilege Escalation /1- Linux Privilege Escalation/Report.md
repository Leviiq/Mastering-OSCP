# Linux Privilege Escalation — Enumeration Fundamentals

**Track:** Mastering OSCP
**Section:** Privilege Escalation — 023
**Topics:** Why PrivEsc Matters, System & Kernel Enumeration, Running Services & Processes, User Home Directory Recon, SSH Keys & Command History, Sudo Privilege Abuse, PATH & Environment Variables, File & Directory Permissions, SUID/SGID Binaries, Writable Files & Directories

---

## 1. Why Privilege Escalation Matters

On Linux, the `root` account has full administrative-level access to the operating system. During an assessment, gaining a low-privileged shell on a Linux host is usually just the beginning — the next objective is escalating that shell to `root`.

Fully compromising a host matters for several reasons:

- It allows capturing traffic and accessing sensitive files that can support further access elsewhere in the environment.
- If the compromised Linux machine is **domain-joined**, escalating fully can expose its NTLM hash — opening the door to Active Directory enumeration and attacks from a Linux foothold.

---

## 2. Initial Enumeration Checklist

The moment a shell is obtained, several categories of information are worth checking immediately, in roughly this order of priority.

### 2.1 OS Version

Knowing the exact distribution (Ubuntu, Debian, FreeBSD, Fedora, SUSE, Red Hat, CentOS, etc.) narrows down which tools are likely available, and which public exploits might apply to that specific OS version.

```bash
cat /etc/os-release
```
```
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
```

### 2.2 Kernel Version

As with the OS version, public exploits often target specific kernel versions. Kernel exploits carry real risk — they can cause system instability or a full crash, so understand exactly what an exploit does and its blast radius before running it, especially against a production system.

```bash
uname -a
```
```
Linux hossam 5.10.0-33-cloud-amd64 #1 SMP Debian 5.10.226-1 (2024-10-03) x86_64 GNU/Linux
```

An alternative source for the same information:

```bash
cat /proc/version
```

**Hardware/CPU details:**

```bash
lscpu
```

### 2.3 Running Services

Knowing what services are running — especially those running **as root** — is critical. A misconfigured or vulnerable root-owned service can be an easy privilege escalation win. Flaws have been found in many common services (Nagios, Exim, Samba, ProFTPd, and others), several with public PoC exploits — e.g. **CVE-2016-9566**, a local privilege escalation flaw in Nagios Core < 4.2.4.

```bash
ps aux | grep root
```
```
root   1  1.3  0.1  37656  5664 ?  Ss  23:26  0:01 /sbin/init
root   2  0.0  0.0      0     0 ?  S   23:26  0:00 [kthreadd]
root   3  0.0  0.0      0     0 ?  S   23:26  0:00 [ksoftirqd/0]
```

### 2.4 Installed Packages & Logged-In Users

Knowing which other packages are installed (and their versions), plus which users are currently logged in and what they're doing, gives insight into possible local lateral movement paths.

**Listing current processes:**

```bash
ps au
```
```
USER          PID  %CPU  %MEM   VSZ   RSS TTY  STAT START TIME COMMAND
root         1256   0.0   0.1 65832  3364 tty1 Ss   23:26 0:00 /bin/login --
cliff.moore  1322   0.0   0.1 22600  5160 tty1 S    23:26 0:00 -bash
shared       1367   0.0   0.1 22568  5116 pts/0 Ss  23:27 0:00 -bash
root         1384   0.0   0.1 52700  3812 tty1 S    23:29 0:00 sudo su
root         1385   0.0   0.1 52284  3448 tty1 S    23:29 0:00 su
root         1386   0.0   0.1 21224  3764 tty1 S+   23:29 0:00 bash
```

Note the `sudo su` → `su` → `bash` chain above — a strong signal that a root shell is (or recently was) active on this box.

---

## 3. User Home Directories

Are other users' home directories accessible? Home folders frequently contain SSH keys usable to access other systems, or scripts and configuration files containing plaintext credentials — not uncommonly enough to leverage access into other systems, or even into an Active Directory environment if the target is domain-joined.

```bash
ls /home
```
```
backupsvc  bob.jones  cliff.moore  Logger  mrb3n  shared  stacey.jenkins
```

**Checking a specific user's home directory** — always include hidden files:

```bash
ls -la /home/stacey.jenkins/
```
```
total 32
drwxr-xr-x 3 stacey.jenkins stacey.jenkins 4096 Aug 30 23:37 .
drwxr-xr-x 9 root           root           4096 Aug 30 23:33 ..
-rw------- 1 stacey.jenkins stacey.jenkins   41 Aug 30 23:35 .bash_history
-rw-r--r-- 1 stacey.jenkins stacey.jenkins  220 Sep  1  2015 .bash_logout
-rw-r--r-- 1 stacey.jenkins stacey.jenkins 3771 Sep  1  2015 .bashrc
-rw-r--r-- 1 stacey.jenkins stacey.jenkins   97 Aug 30 23:37 config.json
-rw-r--r-- 1 stacey.jenkins stacey.jenkins  655 May 16  2017 .profile
drwx------ 2 stacey.jenkins stacey.jenkins 4096 Aug 30 23:35 .ssh
```

### 3.1 Checking SSH Keys

```bash
ls -l ~/.ssh
```
```
total 8
-rw------- 1 mrb3n mrb3n 1679 Aug 30 23:37 id_rsa
-rw-r--r-- 1 mrb3n mrb3n  393 Aug 30 23:37 id_rsa.pub
```

A readable private key (`id_rsa`) here is a direct path to authenticating as that user — either on this host or, frequently, on other machines in the environment that trust the same key.

### 3.2 Checking Command History

```bash
history
```
```
1  id
2  cd /home/cliff.moore
3  exit
4  touch backup.sh
5  tail /var/log/apache2/error.log
6  ssh ec2-user@dmz02.inlanefreight.local
7  history
```

Command history routinely leaks internal hostnames, usernames, and sometimes full credentials typed directly into a command line.

---

## 4. Sudo Privileges

Can the current user run any commands as another user, or as root? Without credentials for that user, sudo permissions may not be leverageable — but sudoers entries frequently include `NOPASSWD`, meaning the specified command can run without ever being prompted for a password.

```bash
sudo -l
```
```
Matching Defaults entries for hossam on hossam:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User hossam may run the following commands on hossam:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
```

This particular output shows `hossam` can run **absolutely anything** as **any user**, on **any host**, with **no password prompt** — an immediate, trivial path to root (`sudo su` or `sudo bash`).

In a more realistic, restricted case, `sudo -l` output naming a *specific* binary with `NOPASSWD` is the far more common finding — at which point checking that specific binary against [GTFOBins](https://gtfobins.github.io/) is the standard next step to find a privilege escalation primitive built into that binary itself.

---

## 5. Environment & Kernel Context

### 5.1 The `PATH` Variable

`PATH` tells the shell where to look when a command is executed without a full path.

```bash
echo $PATH
```
```
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/snap/bin:/bin:/usr/local/go/bin:/home/hossam/go/bin:/home/hossam/nikto/program
```

If you've written a shell script and want it executable by name alone, there are two options:

1. Move the script into one of the directories already listed in `$PATH`:

```bash
cp test/shell.sh /usr/local/bin
```

2. Add the script's own directory to `$PATH`:

```bash
export PATH=$PATH:/home/kali/test
```

> If any directory already in `$PATH` is writable by the current user, and a higher-privileged process later invokes a command by name (without a full path) that resolves into that writable directory, this becomes a genuine privilege escalation vector — not just a convenience feature.

### 5.2 Environment Variables

Worth a full sweep — occasionally something sensitive, like a password, ends up sitting in plain environment variables.

```bash
env
```
```
SHELL=/bin/bash
PWD=/home/hossam
LOGNAME=hossam
XDG_SESSION_TYPE=tty
HOME=/home/hossam
LANG=C.UTF-8
```

### 5.3 Available Shells

```bash
cat /etc/shells
```
```
# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/bin/dash
```

---

## 6. File & Directory Permissions

### 6.1 The Basics

**File permissions:**

| Permission | Effect |
|---|---|
| **Read** | The file's contents can be read |
| **Write** | The file's contents can be modified |
| **Execute** | The file can be executed (run as a process) |

**Directory permissions** are slightly more nuanced:

| Permission | Effect |
|---|---|
| **Execute** | The directory can be entered/traversed. Without this, neither read nor write permissions function correctly |
| **Read** | The directory's contents can be listed |
| **Write** | Files and subdirectories can be created inside it |

### 6.2 SUID and SGID Bits

- **SUID (setuid)** — when set on a file, it executes with the privileges of the file's **owner**, not the user running it.
- **SGID (setgid)** — when set on a file, it executes with the privileges of the file's **group**. When set on a directory, files created inside inherit that directory's group.

In a standard `ls -l` listing, the permission string's final 9 characters represent three sets — owner, group, others — each made of `r`, `w`, `x`. The SUID/SGID bit shows up as an **`s`** in place of the owner's or group's execute bit.

**Why SUID/SGID exist:** they let a low-privileged user run a specific command with elevated privileges, without granting that user full root-level access. The catch: many SUID/SGID binaries contain functionality that can be abused to spawn a root shell directly.

```bash
ls -lah /bin/passwd
```
```
-rwsr-xr-x 1 root root 63K Feb 7 2020 /bin/passwd
```

That `s` in the owner's execute position confirms `passwd` runs as its owner (`root`) regardless of who invokes it — exactly why a normal user is able to change their own password despite `/etc/shadow` being root-owned and unreadable directly.

**Setting/removing SUID manually:**

```bash
chmod u+s filename   # set SUID
chmod u-s filename   # remove SUID
```

### 6.3 Finding Writable Directories

```bash
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```
```
/run/screen
/run/cloud-init/tmp
/run/lock
/var/tmp
/var/tmp/cloud-init
```

World-writable directories are exactly where you'd stage downloaded tools or payloads on a target with limited write access elsewhere.

### 6.4 Finding Writable Files

```bash
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```
```
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/.access
```

A world-writable file owned or executed by a higher-privileged account — a cron job script, a service config, a log rotation script — is a direct privilege escalation primitive: modify it, wait for it to run under its normal (higher) privilege context, and the modification executes with that elevated privilege.

---

## 7. Enumeration Discipline

Enumeration is the single most important skill in privilege escalation. Automated helper scripts — **LinPEAS**, **LinEnum**, and similar — exist specifically to speed this process up and flag likely paths automatically. That said, understanding *what* these scripts are actually looking for, and being able to reproduce that manually, matters just as much: automated tools can be noisy, may miss context-specific findings, and won't always be available to drop onto a target. Treat this checklist as the mental model those tools are automating, not a replacement for understanding it directly.
