# Information Gathering — OSINT Fundamentals

> **Track:** Mastering OSCP
> **Section:** Information Gathering — 001
> **Topics:** Google Dorking, Company & Employee Recon, ASN/IP Discovery, Email Discovery, Leak Checking, GitHub Recon, DNS Enumeration

---

## Why Information Gathering Comes First

The more information you gather about a target, the easier it becomes to compromise it. **You can't hack what you don't know** — which is why information gathering (recon) is consistently the most important phase of a penetration test, and often the most time-consuming: a thorough pass on a real company (employees, emails, leaked credentials, infrastructure, IP ranges, ASN, subdomains) can realistically take days or weeks.

There are two broad approaches:
- **Manual** — Google dorking, browsing social media, reading public records.
- **Tool/site-assisted** — purpose-built OSINT platforms and search engines.

> Before diving in, it's worth setting up a mind-mapping tool (e.g., XMind) to track everything you find — recon produces a lot of scattered data points, and losing track of them defeats the purpose.

---

## 1. Google Dorking

The starting point for almost any engagement is simply searching the company on Google — and specifically, searching for its employees (usernames, roles) on LinkedIn, Twitter/X, etc.

| Dork | Purpose |
|---|---|
| `site:linkedin.com intext:<COMPANY_NAME>` | Find employee profiles associated with the company |
| `site:<COMPANY_NAME>` | Find pages/mentions referencing the company domain |
| `site:megacorpone.com filetype:txt` | Find specific file types (txt, pdf, doc, xls...) that may contain sensitive data |
| `site:megacorpone.com -filetype:html` | Exclude a file type to filter noisy results |
| `intitle:"index of" "parent directory"` | Find exposed web servers with directory listing enabled — can reveal sensitive files/configs |

**Additional resources:**
- [Google Hacking Database (Exploit-DB)](https://www.exploit-db.com/google-hacking-database)
- [DorkSearch.com](https://dorksearch.com/)

---

## 2. Company & Employee Recon

| Tool | What It Provides |
|---|---|
| [Netcraft](https://searchdns.netcraft.com) | Hosting history, OS/web server info, infrastructure changes over time — useful for spotting outdated tech |
| [hunter.io](https://hunter.io) | Employee emails; you can also infer the tech stack from job titles (e.g., a ".NET developer" hints the backend is built in .NET) |
| [OSINT Framework](https://osintframework.com) | Aggregated directory of OSINT tools/sites (useful alternative if Hunter requires a paid plan) |
| [Crunchbase](https://crunchbase.com) | Company acquisitions — useful for mapping a larger corporate structure |
| [Whois.com](https://whois.com) | Domain registration info |
| [Zone-H Archive](https://www.zone-h.org/archive/special=1) | Archive of previously defaced/compromised websites — your target might show up here |
| [DNS Queries](https://www.dnsqueries.com/en/) | DNS lookup utilities |
| [SOCRadar](https://socradar.io) | Threat intelligence — malware/vulnerabilities associated with the target |
| [DeHashed](https://dehashed.com) | Search leaked/breached data |
| [Aleph OCCRP](https://aleph.occrp.org) | Investigative journalism database, useful for corporate/ownership research |

---

## 3. ASN & IP Range Discovery

Every large company owns an **ASN (Autonomous System Number)** — a unique identifier tying a block of IP addresses to that organization. Once you have the ASN, you effectively have a map of the company's servers, subdomains, and infrastructure.

```
Example: test.com → AS1111
```

Find a company's ASN:
```
https://bgp.he.net/search
```

### Shodan

[Shodan](https://shodan.io) is a search engine for internet-connected devices — servers, routers, cameras, etc. Register an account, then search by ASN:

```
asn:11111
```

This returns all IPs/domains tied to that ASN.

### Censys

[Censys](https://search.censys.io) works similarly to Shodan but is generally considered more powerful:

```
autonomous_system.asn:3303
```

**Other similar search engines:** Fofa.info, Netlas.io

---

## 4. Email Discovery & Leak Checking

### Finding company emails

| Tool | Notes |
|---|---|
| [Prospeo](https://app.prospeo.io/domain-search) | Domain-based email search |
| [AnyMailFinder](https://newapp.anymailfinder.com/) | Domain-based email search |
| [Snov.io](https://app.snov.io) | Domain-based email search |

Just provide the company name or main domain.

### Checking if emails have been breached

Once you have a list of employee emails, check them against known breaches:

```
https://haveibeenpwned.com/
```

For deeper credential exposure, a Telegram bot can return leaked passwords tied to a specific email:

```
https://t.me/database_lookupbot
```

> Submit each email individually to see if a corresponding leaked password exists.

---

## 5. GitHub & Open-Source Code Recon

Public code repositories can contain sensitive information accidentally committed by developers — credentials, API keys, or configuration details. Reviewing these sources is a valuable form of **passive** information gathering.

**Common platforms to search:**
- [GitHub](https://github.com/)
- [Gist](https://gist.github.com/)
- [GitLab](https://about.gitlab.com/)
- [SourceForge](https://sourceforge.net/)

**GitHub search example:**
```
owner:megacorpone path:users
```

**Automated tools:**

| Tool | Purpose |
|---|---|
| [Gitrob](https://github.com/michenriksen/gitrob) | Finds sensitive data in public GitHub repositories |
| [Gitleaks](https://github.com/zricethezav/gitleaks) | Detects credentials and other sensitive data inside Git repositories |

```bash
# Example gitleaks usage (check current CLI syntax with --help, as flags change between versions)
gitleaks detect --source /path/to/cloned/repo
```

---

## 6. Terminal Recon Tools

### `whois`

```bash
whois swisscom.com
```

### DNS Records

DNS ties together IPs, domains, mail servers, and databases via different record types:

| Record | Purpose |
|---|---|
| `A` | Points a domain to an IP address |
| `CNAME` | Points a domain to another (host) domain |
| `MX` | Points a domain to its mail server |
| `PTR` | Reverse lookup — points an IP back to its domain name |

> Analogy: when you buy a SIM card, your number is registered with your carrier (e.g., Vodafone) — anyone calling that number gets routed to the carrier first, then to you. DNS records work the same way: a domain is "hosted" somewhere (Azure, GitHub Pages, AWS, etc.), and records tell the internet where to route requests.

```bash
dig google.com CNAME
dig github.com MX
dig +short github.com
```

### Fingerprinting the Tech Stack

- **Wappalyzer** (browser extension) — identifies frameworks/CMS/technologies used by a website.
- **WhatWeb**:
  ```bash
  whatweb google.com
  ```

### Reverse IP / CIDR Lookups

If you have an IP and want to find other domains hosted on it:

```
https://viewdns.info/reverseip
```

or

```bash
nslookup 34.65.54.101
```

If you have a **CIDR range** and want related domains, [hakrevdns](https://github.com/hakluke/hakrevdns) automates reverse DNS lookups across the whole range:

```bash
# Install Go first: https://go.dev/doc/install
go install github.com/hakluke/hakrevdns@latest
sudo mv ~/go/bin/hakrevdns /usr/local/bin

# Usage:
prips 173.0.84.0/24 | hakrevdns -r 8.8.8.8
```

### theHarvester

Aggregates emails, subdomains, hosts, and more from public sources:

```bash
theHarvester -d facebook.com -b bing
```

---

## Next Steps

With OSINT and passive recon covered, the natural next step is **active enumeration** of specific services discovered during this phase — starting with **SMB** and **SMTP**, covered in the next two parts of this section.
