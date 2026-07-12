# Information Gathering — MySQL Enumeration

> **Track:** Mastering OSCP
> **Section:** Information Gathering — 006
> **Topics:** MySQL Fundamentals, Default Configuration, Dangerous Settings, Footprinting, Manual Interaction

---

## 1. What is MySQL?

**MySQL** is an open-source relational database management system, supported by Oracle, operating on a **client-server model**:

- **Server** — responsible for storing and efficiently organizing data in tables (rows, columns, data types).
- **Clients** — communicate with the server via SQL to add, delete, modify, or retrieve data.

### Advantages

- High performance handling large volumes of data.
- Low storage overhead thanks to its organized storage model.
- Accessible over internal networks or the internet.

### Common Use Cases

- Dynamic websites (e.g., WordPress), storing posts, users, and passwords — usually protected via `localhost`-only access.
- **LAMP** (Linux, Apache, MySQL, PHP) or **LEMP** (Linux, Nginx, MySQL, PHP) stacks.
- Storing all kinds of data: text, addresses, links, users, permissions, passwords, etc.

### Security Note

MySQL *can* store passwords in plaintext, but they're typically hashed beforehand at the application layer (e.g., via PHP) using secure one-way hashing techniques.

> MySQL is a powerful, efficient database engine and the backbone of countless web applications, especially in dynamic hosting environments.

---

## 2. MySQL Commands (Overview)

- The database translates SQL commands internally into executable operations.
- On error, web applications return a message to the user — and these error messages often leak information exploitable in attacks like SQL Injection.
- On success, the database returns results to the client (e.g., login data, search results, logs).

**Functional categories of SQL commands in MySQL:**
- **Data management** — viewing, modifying, adding, or deleting rows within tables.
- **Structure management** — modifying table structure, creating/deleting relationships and indexes.
- **Permission management** — adding/removing users and managing their privileges.

### MariaDB

**MariaDB** is an open-source fork of MySQL, developed after MySQL's lead developer left the company following Oracle's acquisition. It's built on the original MySQL codebase, so it's commonly used as a drop-in, compatible alternative.

---

## 3. Default MySQL Configuration

Database administration and configuration is a broad and complex topic — enough that "Database Administrator" is an entire profession in its own right. These systems tend to grow quickly and need careful planning, making this a core skill for both developers and security analysts. Covering every configuration detail is beyond this section's scope, so it's worth installing MySQL or MariaDB yourself to explore its functions and options hands-on.

### Installing & Reviewing the Config

```bash
sudo apt install mysql-server -y
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#"
```

> Path may vary slightly by distro/version — check `/etc/mysql/` for the exact config file if it isn't at the location above.

```ini
[client]
port     = 3306
socket   = /var/run/mysqld/mysqld.sock

[mysqld_safe]
pid-file = /var/run/mysqld/mysqld.pid
socket   = /var/run/mysqld/mysqld.sock
nice     = 0

[mysqld]
skip-host-cache
skip-name-resolve
user     = mysql
pid-file = /var/run/mysqld/mysqld.pid
```

---

## 4. Dangerous Settings

Many things can be misconfigured in MySQL. The [MySQL reference manual] documents every configurable option in detail — the following are the ones most relevant to security:

| Setting | Description |
|---|---|
| `user` | Sets which OS user the MySQL service runs as |
| `password` | Sets the password for the MySQL user |
| `admin_address` | The IP address the server listens on for administrative TCP/IP connections |
| `debug` | Indicates the current debugging configuration |
| `sql_warnings` | Controls whether single-row `INSERT` statements produce an info string if warnings occur |
| `secure_file_priv` | Limits the effect of data import/export operations |

### Why These Matter

- **`user`, `password`, `admin_address`** — these are typically stored in plaintext inside the config file, making them a direct target if file permissions aren't locked down properly. If an unauthorized party gains file read access or a shell, they can access the entire database — including customer data, passwords, and personal information — and potentially modify it.
- **`debug` / `sql_warnings`** — provide detailed information when errors occur, which is useful for administrators but risky if exposed to attackers. These messages can be leveraged via SQL Injection to execute system-level commands on the MySQL server if adequate security measures aren't in place.

---

## 5. Footprinting the Service

There are plenty of reasons a MySQL server might be reachable from an external network — even though it's far from best practice, it's a configuration you'll run into regularly. Often these exposures were meant to be temporary and simply got forgotten, or were set up as a workaround for some technical issue. MySQL typically runs on **TCP port 3306**, and Nmap can be used to scan it for more detail.

### Scanning MySQL

```bash
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```

```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-21 00:53 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00021s latency).

PORT     STATE SERVICE     VERSION
3306/tcp open  nagios-nsca Nagios NSCA
| mysql-brute:
|   Accounts:
|     root:<empty> - Valid credentials
|_  Statistics: Performed 45010 guesses in 5 seconds, average tps: 9002.0
|_mysql-databases: ERROR: Script execution failed (use -d to debug)
|_mysql-dump-hashes: ERROR: Script execution failed (use -d to debug)
| mysql-empty-password:
|_  root account has empty password
| mysql-enum:
|   Valid usernames:
|     root:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     test:<empty> - Valid credentials
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
| mysql-info:
|   Protocol: 10
|   Version: 8.0.26-0ubuntu0.20.04.1
|   Thread ID: 13
|   Capabilities flags: 65535
|   Some Capabilities: SupportsLoadDataLocal, SupportsTransactions, Speaks41ProtocolOld, LongPassword
|   Status: Autocommit
|   Salt: YTSgMfqvx\x0F\x7F\x16\&\x1EAeK>0
|   Auth Plugin Name: caching_sha2_password
|_mysql-users: ERROR: Script execution failed (use -d to debug)
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
MAC Address: 00:00:00:00:00:00 (VMware)
```

> ⚠️ Note the service label: Nmap fingerprinted port 3306 as `nagios-nsca` — a mismatch worth flagging. Service-detection fingerprints aren't always right, and this is a good example of why manual verification matters.

As with every scan, it's important to treat results with healthy skepticism and manually confirm what a script reports, since false positives happen. This scan is a textbook example: the `mysql-brute`/`mysql-enum` output claims the `root` account has an **empty** password — but in reality, the target server uses a **fixed, non-empty** password. We can verify that directly:

```bash
mysql -u root -h 10.129.14.132
```
```
ERROR 1045 (28000): Access denied for user 'root'@'10.129.14.1' (using password: NO)
```

This confirms the automated result was a false positive.

---

## 6. Interacting with the MySQL Server

If we use a password we've guessed or discovered through prior research, we can log in and start executing commands:

```bash
mysql -u root -pP4SSw0rd -h 10.129.14.128
```

> ⚠️ There must be **no space** between the `-p` flag and the password.

```
Welcome to the MariaDB monitor. Commands end with ; or \g
Your MySQL connection id is 150165
Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu)
```

### Exploring Databases

```sql
MySQL [(none)]> show databases;
```
```
information_schema
performance_schema
```

```sql
MySQL [(none)]> select version();
```
```
8.0.27-0ubuntu0.20.04.1
```

```sql
MySQL [(none)]> use mysql;
MySQL [mysql]> show tables;
```
```
columns_priv
component
db
default_roles
engine_cost
func
general_log
global_grants
gtid_executed
help_category
help_keyword
help_relation
help_topic
innodb_index_stats
```

Two of the most important built-in databases worth knowing:
- **`sys`** — the system schema, containing tables/metadata useful for management insight.
- **`information_schema`** — metadata about the server's own structure (databases, tables, columns, permissions).

```sql
mysql> use sys;
mysql> show tables;
```
```
host_summary
host_summary_by_file_io
host_summary_by_file_io_type
host_summary_by_stages
host_summary_by_statement_latency
host_summary_by_statement_type
innodb_buffer_stats_by_schema
innodb_buffer_stats_by_table
innodb_lock_waits
io_by_thread_by_latency
...SNIP...
x$waits_global_by_latency
```

```sql
mysql> select host, unique_users from host_summary;
```
```
+-------------+--------------+
| host        | unique_users |
+-------------+--------------+
| 10.129.14.1 | 1            |
+-------------+--------------+
```

---

## 7. Useful MySQL Commands Reference

| Command | Description |
|---|---|
| `mysql -u <user> -p<password> -h <IP address>` | Connect to the MySQL server (no space between `-p` and the password) |
| `show databases;` | Show all databases |
| `use <database>;` | Select a database |
| `show tables;` | Show all tables in the selected database |
| `show columns from <table>;` | Show all columns in a table |
| `select * from <table>;` | Dump everything from a table |
| `select * from <table> where <column> = "string";` | Search a table for a specific value |
