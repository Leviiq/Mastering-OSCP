# Linux & Bash — OSCP Notes (Part 2)

> **Track:** Mastering OSCP
> **Section:** Linux & Bash
> **Covers:** 003 – User & Group Security · 004 – Bash Scripting Fundamentals & `sed`

---

# 003 — User & Group Security

> **Topics:** Users & Groups, User/Group Info, Privilege Escalation via `sudoers`, Account Management, File Attributes, Filesystem Types

## 1. Who's Logged In

| Command | Purpose |
|---|---|
| `who` | Shows the users currently logged into the system. |
| `w` | Similar to `who`, but with more detail — includes source IP and what each user is doing. |
| `users` | Simple list of logged-in usernames. |
| `last` | Shows the history of logins (not just current sessions). |

## 2. Essential Files for Users & Groups

| File | Purpose |
|---|---|
| `/etc/passwd` | List of all system users. Misconfigurations here can sometimes reveal privilege escalation opportunities. |
| `/etc/group` | Defines groups and their members — groups control what a user is authorized to do. |
| `/etc/shadow` | **Highly sensitive** — stores the hashed passwords for every user. |
| `/etc/gshadow` | Same idea as `/etc/shadow`, but for group passwords. |
| `/home/{username}` | Each user's personal directory, often containing valuable information during enumeration. |
| `/etc/skel` | Template directory — its contents are copied into every new user's home directory upon creation. |
| `/etc/login.defs` | Defines default login/account policies (password aging defaults, UID/GID ranges, etc.). |
| `/etc/sudoers` | Defines which users/groups can run commands with elevated privileges, and under what conditions. |

### Understanding `/etc/sudoers`

```
# User privilege specification
root    ALL=(ALL:ALL) ALL
```

This line means the `root` user can execute **any** command, as **any** user, on **any** host.

To grant your own user full sudo rights without a password prompt:

```
kali    ALL=(ALL) NOPASSWD: ALL
```

> Not sure which user you're currently logged in as? `whoami` will tell you.

## 3. Adding, Deleting & Modifying Users

```bash
# Add a new user with a home directory, bash shell, and sudo group membership
useradd -m -s /bin/bash -G sudo john

# Set/change a password
passwd john

# Delete a user and their home directory
userdel -r john
```

### Modifying an Existing User

```bash
# Change home directory
usermod -d /new/directory john
su john
cd ~
pwd

# Rename the user
usermod -l newusername john

# Change login shell
usermod -s /bin/zsh john

# Overwrite secondary group memberships (replaces existing groups!)
usermod -G group1,group2 john

# Add to a new group WITHOUT removing existing group memberships
usermod -aG newgroup john
```

> ⚠️ `usermod -G` **replaces** all secondary groups. If you only want to add a group, always use `-aG` (append).

### Listing & Locking Accounts

```bash
# Show UID, GID, and group memberships
id john

# Lock an account (e.g., an employee who left the company)
passwd -l john

# Unlock an account
passwd -u john
```

Another way to fully block access is disabling the login shell entirely:

```bash
usermod -s /sbin/nologin john
```

> On most Debian-based systems, regular user IDs (UIDs) start at **1000** — anything below that is typically reserved for system/service accounts.

## 4. Managing Groups

```bash
# Create a group (optionally with a specific GID)
groupadd developers
groupadd developers -g 2000

# Delete a group
groupdel developers

# Rename a group
groupmod developers -n devs

# Change a group's GID
groupmod -g 2000 devs

# Add a user to a group (append)
usermod -aG devs john

# Remove a user from a group
sudo gpasswd -d john devs

# List the groups a user belongs to
groups john

# Get detailed info about a group
getent group devs

# Change a user's PRIMARY group
usermod -g devs john

# Set a password for a group
gpasswd devs
```

## 5. Password Aging & Policy

```bash
# View password expiration info for a user
chage -l john

# Set password aging policy
chage [option] john
```

| Option | Meaning |
|---|---|
| `-m days` | Minimum number of days before the password can be changed again |
| `-M days` | Maximum number of days before the password must be changed |
| `-W days` | Number of days before expiration to warn the user |
| `-I days` | Number of inactive days after expiration before the account is locked |
| `-E date` | Account expiration date (`YYYY-MM-DD`) |

### Reading `/etc/passwd`

```
root:x:0:0:root:/root:/bin/bash
```

| Field | Meaning |
|---|---|
| `x` | Password is stored (hashed) in `/etc/shadow`, not here |
| `0:0` | UID:GID — `0` means this is the **root** user |
| `/root:/bin/bash` | Home directory and default shell |

### Reading `/etc/shadow`

```
admin:$y$j9T$CbCTLnmDfJaWMDz6EaxEF0$wgVb2ruLvNfM0kvAqLglnnQb/K2VgzEDxqeRD4kRCS4:19957:0:99999:7:::
```

| Field # | Meaning |
|---|---|
| 1 | Username |
| 2 | Password hash |
| 3 | Date of last password change (days since Jan 1, 1970) |
| 4 | Minimum days before password can be changed |
| 5 | Maximum days before password must be changed |
| 6 | Warning period (days) before expiration |
| 7 | Grace period (days) after expiration before the account is locked |
| 8 | Account expiration date (days since Jan 1, 1970) |

> This is one of the most sensitive files on the system. Note the hash prefix `$y$` — this indicates the **yescrypt** algorithm (the modern default on many distros), not bcrypt. Other common prefixes: `$1$` = MD5, `$2a$`/`$2b$` = bcrypt, `$5$` = SHA-256, `$6$` = SHA-512.

```bash
# Force a user to change their password on next login
passwd -e john
```

## 6. `/etc/skel` — Default Files for New Users

Anything placed inside `/etc/skel` is automatically copied into the home directory of every newly created user. This is useful for shipping default configs, tools, or notes to all future accounts.

```bash
nano /etc/skel/newfile.txt
useradd -m hossamshady
# hossamshady's home directory will now contain newfile.txt automatically
```

## 7. Graphical User & Group Administration

If you prefer a GUI over the command line:

```bash
sudo apt install gnome-system-tools
# or
sudo apt install kuser
# or
sudo apt install cockpit
sudo systemctl start cockpit
```

Cockpit is accessible through a browser at **http://localhost:9090**.

## 8. File Attributes (`chattr`)

| Command | Effect |
|---|---|
| `chattr +i file` | Makes the file immutable — cannot be modified, deleted, or renamed (even by root, until removed) |
| `chattr -i file` | Removes the immutable flag |
| `chattr +a file` | Append-only — data can be added, but existing content can't be changed or deleted |
| `chattr +A file` | Prevents the file's access time (`atime`) from being updated |
| `chattr +d file` | Restricted deletion — prevents non-owners from deleting/renaming the file, even with write permission |

## 9. Filesystem Types

| Filesystem | Notes |
|---|---|
| **EXT4** | Default on many modern Linux distros. Supports files up to 1000 TB, faster than earlier EXT versions. General-purpose use. |
| **NTFS** | Windows' native filesystem. Supports large files/volumes and file-level encryption (EFS). Common on drives shared between Windows and Linux. |
| **ISO 9660** | Filesystem for optical media (CDs/DVDs), often used for bootable images. |
| **NFS** | Network File System — allows file access over a network. Common in enterprise/server environments. |
| **SMB/CIFS** | Protocol for network file sharing, primarily between Windows and other systems — supports remote file access, printing, etc. |

---

# 004 — Bash Scripting Fundamentals & `sed`

> **Topics:** Writing Bash Scripts, Variables, Arguments, Loops, Conditionals, Functions, Regex/`grep`, `sed`

## 1. Writing Your First Script

Bash is the scripting language used to automate tasks on Linux. A script is just a plain text file containing a sequence of commands.

```bash
nano xyz.sh
```

```bash
#!/bin/bash
ls
echo "this is red nexus"
```

Save with `Ctrl+X`, then `Y`, then run it:

```bash
bash xyz.sh
```

> The first line, `#!/bin/bash`, is called a **shebang** — it tells the system which interpreter to use to run the script.

## 2. Variables

```bash
#!/bin/bash
name="Hossam Shady"
echo $name
```

> No spaces around `=` when assigning a variable — `name = "value"` will fail, `name="value"` works.

## 3. Reading a File in a Script

```bash
#!/bin/bash
file="/home/xyz.txt"
cat $file
```

## 4. Positional Arguments

Arguments passed on the command line when running the script are accessible via `$1`, `$2`, `$3`, etc.

```bash
#!/bin/bash
echo $1
```

```bash
bash xyz.sh rednexus
# Output: rednexus
```

Multiple arguments:

```bash
#!/bin/bash
first=$1
second=$2
echo "the first name is $first and second name is $second"
```

```bash
bash xyz.sh hossam shady
```

## 5. Loops

Simple counting loop directly in the terminal:

```bash
for i in {1..100}; do echo "$i"; done
```

Reading a file line by line:

```bash
for i in $(cat xyz.txt); do echo "$i"; done
```

Capturing command output into a loop:

```bash
for i in $(ifconfig); do echo "$i"; done
```

> You'll sometimes see this written with backticks ( `` `command` `` ) instead of `$(command)` — both perform command substitution, but `$(...)` is the modern, more readable syntax and handles nesting better.

## 6. If Conditions

Bash's `if` statement lets a script branch based on a condition. The basic structure:

```bash
#!/bin/bash
if [ condition ]; then
    echo "condition was true"
else
    echo "condition was false"
fi
```

> Spaces matter — `[ $1 -eq 1 ]` needs spaces right after `[` and before `]`, or Bash will throw a syntax error.

### Common comparison operators

| Operator | Meaning | Example |
|---|---|---|
| `-eq` / `-ne` | Equal / Not equal (numbers) | `[ $1 -eq 5 ]` |
| `-gt` / `-lt` | Greater than / Less than | `[ $1 -gt 10 ]` |
| `-ge` / `-le` | Greater or equal / Less or equal | `[ $1 -ge 10 ]` |
| `=` / `!=` | Equal / Not equal (strings) | `[ "$1" = "admin" ]` |
| `-z` | String is empty | `[ -z "$1" ]` |
| `-f` | File exists | `[ -f /etc/passwd ]` |
| `-d` | Directory exists | `[ -d /home/kali ]` |

### Example: checking if a file exists

```bash
#!/bin/bash
file=$1

if [ -f "$file" ]; then
    echo "$file exists."
else
    echo "$file was not found."
fi
```

### Example: checking an argument against a value

```bash
#!/bin/bash
if [ "$1" = "admin" ]; then
    echo "Welcome, admin."
else
    echo "Access denied."
fi
```

You can chain multiple conditions with `elif`:

```bash
#!/bin/bash
port=$1

if [ "$port" -eq 80 ]; then
    echo "HTTP"
elif [ "$port" -eq 443 ]; then
    echo "HTTPS"
elif [ "$port" -eq 22 ]; then
    echo "SSH"
else
    echo "Unknown port"
fi
```

## 7. Functions

A function groups a block of commands under a name, so it can be reused without repeating code.

```bash
#!/bin/bash

greet() {
    echo "Hello, $1!"
}

greet "Hossam"
```

> Inside a function, `$1`, `$2`, etc. refer to the arguments **passed to the function**, not the script's own arguments.

### Example: a reusable function with a return-style value

Bash functions don't return values the way other languages do — instead, they either `echo` output (to be captured) or set an `exit status` (`return`).

```bash
#!/bin/bash

is_root() {
    if [ "$(whoami)" = "root" ]; then
        return 0   # success
    else
        return 1   # failure
    fi
}

if is_root; then
    echo "Running as root."
else
    echo "Not running as root."
fi
```

### Example: a function used for repeated enumeration steps

```bash
#!/bin/bash

check_service() {
    service_name=$1
    if systemctl is-active --quiet "$service_name"; then
        echo "$service_name is running"
    else
        echo "$service_name is NOT running"
    fi
}

check_service ssh
check_service apache2
```

## 8. Variables & User Input

Besides positional arguments, a script can also ask the user for input **while it's running**, using `read`:

```bash
#!/bin/bash
echo "Enter your name:"
read name
echo "Hello, $name!"
```

`read` can also prompt inline with `-p`, and read multiple values at once:

```bash
#!/bin/bash
read -p "Enter username: " user
read -p "Enter port number: " port
echo "Connecting user $user on port $port..."
```

### Reading input silently (e.g., for a password)

```bash
#!/bin/bash
read -sp "Enter password: " pass
echo
echo "Password received (hidden)."
```

> `-s` (silent) hides what's typed — useful any time you don't want sensitive input echoed to the screen.

---

## 9. Regex Basics (Recap)

Regex describes a general **shape/pattern**, not a specific value — for example, you don't care if a number is `10` or `9491`, only that "this is a number."

| Pattern | Matches |
|---|---|
| `[0-9]` | A single digit |
| `[0-9]{2}` | Exactly 2 digits |
| `\d\d` | Also exactly 2 digits (shorthand, depending on regex flavor) |
| `\s` | A single whitespace character |
| `\s{2}` | Exactly 2 whitespace characters |

> Tip: sites like regex101.com are great for testing patterns interactively before using them in `grep`/`sed`.

## 10. `grep` in Practice

```bash
# Lines containing "hacking"
cat xyz.txt | grep "hacking"

# Lines where "hacking" appears at the END of the line
cat xyz.txt | grep -E "hacking$"
```

### Example: extracting URLs ending in `.php`

```
https://google.com/file.txt
https://google.com/file.js
https://google.com/file.php
https://google.com/file.html
```

```bash
cat urls.txt | grep -E "\.php$"
```

> Note the escaped dot (`\.`) — without it, `.` would match *any* character, not just a literal period.

---

## 11. `sed` — Stream Editor

`sed` is a powerful stream editor for Unix/Linux, ideal for making automated, line-by-line modifications to text — widely used in scripts and command-line workflows.

**Common use cases:**
- **Search & replace** — e.g., updating credentials or config values.
- **Log sanitization** — removing/altering log entries to obscure traces of activity.
- **Mass text edits** — modifying multiple files or many lines at once.

### The Substitute Command (`s`)

```bash
sed 's/pattern/replacement/flags' < input_file > output_file
```

**Basic example:**

```bash
echo "day" | sed 's/day/night/'
# Output: night
```

**Multiple substitutions in one command:**

```bash
echo "hello world" | sed 's/hello/hi/; s/world/earth/'
# Output: hi earth
```

> Tip: Always quote the `sed` pattern to avoid the shell interpreting special characters.

### Line Orientation

`sed` processes each line independently, and by default replaces only the **first** match per line.

```
Input:
one two three, one two three
four three two one
one hundred

Command:
sed 's/one/ONE/' file.txt

Output:
ONE two three, one two three
four three two ONE
ONE hundred
```

### Flag: `g` (Global)

Replaces **all** occurrences on each line, not just the first:

```bash
# Input: foo bar foo bar
sed 's/bar/baz/g' file.txt
# Output: foo baz foo baz
```

### Flag: `-i` (In-Place Editing)

Edits the file directly, with no need for output redirection:

```bash
# file.txt:
# apple
# foo
# banana
# foo

sed -i 's/foo/bar/g' file.txt

# file.txt after:
# apple
# bar
# banana
# bar
```

```bash
# settings.conf:
# temp=enabled
# temp_directory=/var/temp

sed -i 's/temp/permanent/g' settings.conf

# settings.conf after:
# permanent=enabled
# permanent_directory=/var/permanent
```

> ⚠️ `-i` overwrites the original file. **Always back up before running `sed -i`** in case something goes wrong.

### Flag: `d` (Delete)

Deletes any line matching the pattern:

```bash
# file.txt:
# apple
# orange
# pattern
# banana
# pattern

sed '/pattern/d' file.txt

# Output:
# apple
# orange
# banana
```
