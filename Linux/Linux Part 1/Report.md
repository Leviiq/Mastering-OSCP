# Linux & Bash — OSCP Notes

> **Track:** Mastering OSCP
> **Section:** Linux P1
> **Covers:** 001 – Linux Fundamentals

---

# 001 — Linux Fundamentals

> **Topics:** Distributions, Installation Methods, Terminal Basics, Permissions, I/O Redirection

## 1. What is Linux?

Linux is an **open-source, Unix-like operating system**. Because the source code is public, anyone can inspect, modify, and redistribute it. This is exactly why so many different **distributions ("distros")** exist — each one is essentially a customized build of the Linux kernel plus a chosen set of tools and a package manager.

Technically, Linux is part of the broader **Unix family**, and — perhaps surprisingly — so is **Android**, which runs on a modified Linux kernel.

### Linux vs. Windows (quick comparison)

| Aspect | Linux | Windows |
|---|---|---|
| Security | Generally considered more secure by design (permission model, smaller attack surface, faster patching) | Larger attack surface, historically a bigger target |
| Performance | Lighter-weight GUI options (or none at all) mean more resources available for actual workloads | Heavier GUI/services can consume more CPU/GPU/RAM |
| Cost | Most tools and distributions are free and open-source | Many tools/licenses are paid |

### Popular Distribution Families

| Family | Examples | Typical Use Case |
|---|---|---|
| **Debian-based** | Debian, **Kali Linux**, Ubuntu | Kali ships pre-loaded with penetration-testing tools; Ubuntu is popular for general desktop/server use. Both share the `apt` package manager. |
| **RHEL-based** | Red Hat, Fedora, CentOS | Common in enterprise/server and sysadmin environments; use `dnf`/`yum` instead of `apt`. |

## 2. Installation Methods

| Method | Description |
|---|---|
| **Primary system** | Replaces your current OS entirely and installs Linux as the main system. |
| **Virtual machine** | Runs Linux inside your existing OS, using a portion of its resources (RAM/CPU/disk). |
| **Bootable USB (Live USB)** | Linux runs directly from a USB drive without touching the host machine; typically doesn't persist changes across reboots unless configured to. |

### File formats when downloading a distro (e.g., from kali.org)

- **`.iso`** — A raw disk image. You configure the VM/install settings yourself.
- **`.vmdk`** — A pre-built virtual disk image that comes with the OS already installed and configured (ready to import into a hypervisor).

### Note on Tails

**Tails** ("The Amnesic Incognito Live System") is a Live-USB-focused distribution built around privacy and anonymity. It routes traffic through the Tor network and is designed to leave no trace on the host machine after shutdown.

## 3. The Terminal — First Steps

Almost everything on Linux can be done through the **terminal**.

```bash
sudo apt update && sudo apt upgrade
```

| Command | Meaning |
|---|---|
| `apt update` | Refreshes the local package index (list of available package versions). |
| `apt upgrade` | Actually installs the newer versions of packages. |
| `apt` | The package manager itself — acts like a repository/store for software. |

> ⚠️ Running `apt update` without `sudo` will fail with **"Permission denied"**, because `sudo` (**s**uper**u**ser **do**) is required to run commands with root/admin privileges.
>
> To avoid typing `sudo` before every command, you can switch permanently to the superuser with:
> ```bash
> sudo su
> ```

You can stop any running command/process in the terminal with **`Ctrl + C`**, and return from a superuser shell to your normal user with **`exit`**.

### Essential Commands

| Command | Description |
|---|---|
| `whoami` | Shows the current logged-in user |
| `ls` | Lists files/directories |
| `pwd` | Prints the current working directory |
| `clear` | Clears the terminal screen |
| `cd` | Changes directory (`cd ~` → home, `cd ..` → up one level, `cd /folder1/folder2` → absolute path) |
| `cat` | Displays the contents of a file |
| `nano file.txt` | Creates/edits a file (save with `Ctrl+X`, then `Y`) |
| `rm file.txt` | Deletes a file |
| `mkdir folder` | Creates a directory |
| `rm -r folder` | Removes a directory recursively |

## 4. Paths

- **Absolute path** — starts from root `/`. Example: `/home/hossam/downloads/`
- **Relative path** — relative to your current location; no need to write the full path.

> If you navigate up to `/` with `cd ..` repeatedly, you'll find the system's core directories. One of the most sensitive is **`/etc`**, which stores critical system-wide configuration data.

### Moving, Renaming, Copying

```bash
mv xyz.txt /home          # move file to /home
mv xyz.txt rednexus.txt   # rename file
cp xyz.txt /home          # copy file to /home
```

## 5. Write vs. Append

| Operation | Behavior |
|---|---|
| **Write (`>`)** | Overwrites the file — deletes old content and adds the new content. |
| **Append (`>>`)** | Adds new content **without** deleting what's already there. |

```bash
echo "test"
```

## 6. System Information Commands

| Command | Information |
|---|---|
| `ifconfig` | Network interface details |
| `free` | Memory (RAM) usage |
| `df -H` | Disk space usage |
| `ps aux` | Running processes |

> Some malware/malicious processes consume heavy system resources and show up as suspicious entries in `ps aux` — this makes it a useful diagnostic command.

To terminate a process, find its **PID** and run:
```bash
sudo kill [PID]
```

## 7. Installing Tools

```bash
sudo apt install [tool_name]
snap install [tool_name]
dpkg -i [package.deb]     # for standalone .deb packages
```

## 8. File Permissions

Each file/directory has three permission types: **read**, **write**, **execute**.

| Permission | Symbol | Value |
|---|---|---|
| Execute | `x` | 1 |
| Write | `w` | 2 |
| Read | `r` | 4 |

Combine values for the permission set you need:

| Combination | Value |
|---|---|
| Read + Write | 4 + 2 = **6** |
| Write + Execute | 2 + 1 = **3** |
| Read + Write + Execute | 4 + 2 + 1 = **7** |

### Reading `ls -l` output

```
-rwxr-xr-x  2 kali kali 4.0K Feb 9 18:50 wordlists
```

| Position | Meaning |
|---|---|
| 1st character | `-` = regular file, `d` = directory |
| Characters 2–4 | Owner's permissions (`rwx`) |
| Characters 5–7 | Group's permissions (`r-x`) |
| Characters 8–10 | Other users' permissions (`r-x`) |

### Changing Permissions

```bash
chmod 777 xyz.txt   # read+write+execute for everyone
chmod +x xyz.txt     # add execute permission
```

## 9. Piping & Text Filtering

The pipe `|` redirects the output of one command into another.

```bash
cat xyz.txt | grep "hossam"   # find lines containing "hossam"
cat xyz.txt | wc              # count lines/words/characters
```

## 10. Practice Resources

- **Free VPS for practice** (2GB):
  ```bash
  ssh root@segfault.net
  # password: segfault
  ```
- **OverTheWire — Bandit wargame** (great for beginner Linux/CLI practice via SSH):
  https://overthewire.org/wargames/bandit/

---

# 002 — Advanced Linux Administration

> **Topics:** Installing Go, Documentation Commands, File Commands, `locate`/`find`/`grep`, Regular Expressions

## 1. Installing the Go Toolchain

Go has become an important language in the security/tooling space — many modern tools (and their developers) are written in Go, so knowing how to install it lets you build/run those tools from source.

**Steps:**

1. Visit https://go.dev/dl/ and copy the download link for the Linux tarball.
2. Download it in the terminal:
   ```bash
   wget https://go.dev/dl/go1.26.5.linux-amd64.tar.gz
   ```
   > Always check the site for the **current** version number before downloading — this filename will change over time.
3. Extract and install it (typically to `/usr/local`), then add it to your `PATH`.
4. Verify the installation:
   ```bash
   go version
   ```
5. Tools installed via `go install` are placed under `$GOPATH/bin` (commonly `~/go/bin`). To make a tool available system-wide:
   ```bash
   cp toolname /usr/local/bin
   ```

## 2. Using Documentation

Before memorizing every tool's syntax, learn how to look it up.

| Command | Purpose |
|---|---|
| `man <tool>` | Full manual page for a tool — the most complete reference. |
| `apropos <keyword>` | Searches man page descriptions by keyword. Useful when you remember *what a tool does* but not its name — e.g. `apropos port scan` lists everything related to those terms. |
| `whatis <tool>` | One-line summary of what a tool does — e.g. `whatis nmap`. |
| `info <tool>` | A middle ground: more detail than `whatis`, less than a full `man` page. |

## 3. File Commands

| Command | Action |
|---|---|
| `cp file.txt /home` | Copy a file |
| `mv file.txt /home` | Move a file |
| `mv old.txt new.txt` | Rename a file |
| `rm file.txt` | Delete a file |
| `cat file.txt` | Print the entire file contents at once |
| `nl file.txt` | Print file contents with line numbers |
| `head file.txt` | Show the **first** lines of a file |
| `tail file.txt` | Show the **last** lines of a file |
| `less file.txt` | Page through a file interactively — supports scrolling backward and searching. Ideal for large files, since it doesn't load the whole file into memory at once. |
| `more file.txt` | Similar paging tool to `less`, but simpler/older — generally forward-only. |
| `nano file.txt` | Create/edit a file directly in the terminal |
| `touch file.txt` | Create an empty file |

### Compression

```bash
zip newfile.zip file1 file2 ...   # compress files
unzip newfile.zip                 # decompress
```

## 4. `locate` vs. `find`

### `locate` — fast, database-driven search

```bash
locate file.txt
locate /var/www/html --basename index.html

# The locate database needs to be refreshed to find recently created files:
sudo updatedb
locate "*.txt"
```

### `find` — real-time, more powerful search

```bash
find / -name index.html
find /var/www/html -name index.html
find / -name "*.txt"
find / -empty
find /var/www/html -perm 777                      # files with rwxrwxrwx
find / -type d -name ali                           # search directories only
find / -type f -name ali                            # search files only
find / -type f -exec grep -l "hossam" {} \;         # search file contents
find / -type f -name ali.txt -exec mv {} /home/kali/test/ \;
find / -size +1M                                    # files larger than 1MB
```

## 5. Regular Expressions (Regex) Cheat Sheet

| Pattern | Matches |
|---|---|
| `\w` | Any letter or digit |
| `[0-9]` | Any digit only |
| `\s` | Whitespace |
| `\W` | Anything **except** letters/digits |
| `\D` | Anything **except** digits |
| `\S` | Anything **except** whitespace |
| `.` | Any single character |
| `^x` | Line **starts with** `x` |
| `x$` | Line **ends with** `x` |
| `[0-9]{2}` | Exactly 2 digits |
| `\s{3}` | Exactly 3 whitespace characters |

> Note: `.` matches *any* character in regex. To match a literal dot (e.g., in an email or domain), escape it: `\.`

## 6. `grep` in Practice

```bash
cat file.txt | grep "ahmed"        # lines containing "ahmed"
cat file.txt | grep -v "ahmed"     # lines NOT containing "ahmed"
cat file.txt | grep -E "\s"        # extended regex: lines containing whitespace
```

### Example: matching an email address

```
ahmed@gmail.com
ali@yahoo.net
```

```bash
cat file.txt | grep -E "\w+@\w+\.\w+"
```

> The dot must be escaped (`\.`) — otherwise it would match any character, not just a literal period.
