# Active Directory Fundamentals

**Track:** Mastering OSCP
**Section:** Active Directory — 016
**Topics:** Domains, Forests & Trusts, Organizational Units, Objects & Attributes, Security Principals & SIDs, Distinguished/Relative Distinguished Names, sAMAccountName & UPN, Group Policy Objects, Service Principal Names, ACLs & ACEs, NTDS.DIT, Kerberos Authentication Flow

---

## 1. Why Active Directory Exists

Most companies rely on **Windows Server** to manage every device across the organization. Imagine a company with 1,000 devices — configuring each one individually, one at a time, simply isn't realistic for an IT department. There needs to be a single controller capable of managing all of them at once.

That controller is called a **Domain Controller (DC)** — a feature built into Windows Server that manages the entire network along with every associated permission. Need to push a program or tool to every device in the company? One action on the Domain Controller can deploy it to all 1,000 devices simultaneously.

### 1.1 Common Windows Server Versions

- Windows Server 2008
- Windows Server 2012
- Windows Server 2016
- Windows Server 2022
- Windows Server 2025

Windows Server ships with many built-in features, most notably **Active Directory** and **Kerberos**.

### 1.2 What Active Directory Actually Is

**Active Directory (AD)** is a database and a set of services that connect users to the network resources they need to do their jobs. It holds critical information about users — their devices, permissions, group memberships, and more.

**Group Policy** is the feature that controls what users are, and aren't, permitted to do. Together, AD and Group Policy let IT manage an entire network's worth of devices centrally:

- Create separate groups for IT, HR, Managers, and any other department.
- Make specific data or folders shareable only within a given group — e.g. a folder visible only to Managers, and a separate one only for HR.

---

## 2. Organizational Units, Domains & Forests

### 2.1 Organizational Units (OUs)

Every group of users, devices, and services is called an **Organizational Unit (OU)**. An OU identifies which department a person or resource belongs to — for example, an employee named Ahmed working in HR would be placed inside the HR Organizational Unit.

### 2.2 Domain

A **Domain** is a logical grouping of objects — computers, users, OUs, groups, and more — identified by a name such as `test.local` or `master.com`. Domains can operate entirely independently, or be connected to one another via trust relationships. Think of a domain as a city within a state or country.

### 2.3 Forest

A **Forest** is a collection of Active Directory domains — the topmost container in AD, holding every domain, user, group, computer, and Group Policy Object beneath it. Think of a forest as a state within the US, or a country within the EU: it operates independently, but can maintain trust relationships with other forests.

**Real-world analogy:** when Facebook acquired WhatsApp, Facebook's forest needed a way to communicate with WhatsApp's forest. A **trust link** between the two forests is exactly the mechanism that lets any domain in one forest access and communicate with domains in the other, without merging them into a single forest.

---

## 3. Core AD Concepts & Definitions

### 3.1 Object

An **object** is any resource present within an Active Directory environment — OUs, printers, users, domain controllers, and so on.

### 3.2 Attributes

Every object in AD carries a set of **attributes** describing its characteristics. A computer object, for example, has attributes like its hostname and DNS name. Every attribute also has an associated **LDAP name** used when performing LDAP queries — e.g. `displayName` for a user's full name, and `givenName` for their first name.

### 3.3 Security Principals

A **security principal** is anything the operating system can authenticate — users, computer accounts, and more.

### 3.4 Security Identifier (SID)

A **Security Identifier (SID)** is a unique identifier assigned to a security principal or security group. Every account, group, or process has its own unique SID, issued by the Domain Controller and stored in a secure database.

---

## 4. Naming an Object — DN, RDN, sAMAccountName & UPN

Reaching any user inside any OU or group requires their full **path** or **address** within the directory.

### 4.1 Distinguished Name (DN)

A **Distinguished Name (DN)** describes the full path to an object in AD, e.g.:

```
cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local
```

Here, the user `bjones` works in the IT department at Inlanefreight, with an account created inside an Organizational Unit that holds employee accounts. If a person in one domain needs to reach a person in a *different* domain, the DN (or its Common Name component) is what makes that lookup possible.

### 4.2 Relative Distinguished Name (RDN)

A **Relative Distinguished Name (RDN)** is a single component of the DN that identifies an object as unique *among other objects at the same level* in the naming hierarchy. AD doesn't allow two objects with the same name under the same parent container — but two objects can share the same RDN and still be unique overall, because their full DNs differ.

**Example:** `cn=bjones,dc=dev,dc=inlanefreight,dc=local` and `cn=bjones,dc=inlanefreight,dc=local` are recognized as two distinct objects, despite sharing the RDN `bjones`.

### 4.3 sAMAccountName

The **sAMAccountName** is a user's logon name (e.g. `bjones`). It must be unique and no more than 20 characters.

### 4.4 userPrincipalName (UPN)

The **userPrincipalName** is another way to identify a user, combining a prefix (the account name) and a suffix (the domain name) — e.g. `bjones@test.local`. This attribute is not mandatory.

---

## 5. Policy, Services & Access Control

### 5.1 Group Policy Object (GPO)

A **Group Policy Object (GPO)** is a virtual collection of policy settings, each identified by a unique GUID. A GPO can define local filesystem settings or AD-wide settings, and can apply to both user and computer objects — either domain-wide, or scoped down to a specific OU.

### 5.2 Service Principal Name (SPN)

A **Service Principal Name (SPN)** uniquely identifies a service instance. Kerberos authentication uses SPNs to associate a service instance with a logon account, letting a client request authentication for that service without ever needing to know the actual account name behind it.

### 5.3 Access Control Lists & Entries

An **Access Control List (ACL)** is the ordered collection of **Access Control Entries (ACEs)** that apply to a given object. Each ACE identifies a trustee (a user, group, or logon session) and specifies which access rights are allowed, denied, or audited for that trustee.

### 5.4 Active Directory Users and Computers (ADUC)

**ADUC** is the standard GUI console for managing users, groups, computers, and contacts in AD. Anything done through ADUC can equally be done via PowerShell.

### 5.5 NTDS.DIT

**NTDS.DIT** is, in every practical sense, the heart of Active Directory. Stored on a Domain Controller at `C:\Windows\NTDS\`, it's the database holding AD's core data — user and group objects, group membership, and, critically for attackers and penetration testers, **the password hashes for every user in the domain**.

Once full domain compromise is achieved, an attacker can retrieve this file, extract the hashes, and either:
- Use them directly in a **pass-the-hash** attack, or
- Crack them offline with a tool such as **Hashcat** to access additional resources within the domain.

---

## 6. Kerberos Authentication

Kerberos is the service responsible for authenticating users in an AD environment. There are two authentication methods available:

| Method | Description |
|---|---|
| **NTLM** | Users log in with a username and password. Vulnerable to man-in-the-middle attacks — used locally or when Kerberos isn't available. |
| **Kerberos** | Provides a much higher level of encryption, using tickets to authenticate users instead of passing credentials directly. |

### 6.1 The Two Kerberos Tickets

| Ticket | Responsible For |
|---|---|
| **TGT** (Ticket Granting Ticket) | **Authentication** — confirming the user exists and is valid within the Kerberos database |
| **TGS** (Ticket Granting Service) | **Authorization** — confirming the user is permitted to access a specific service |

### 6.2 The Full Authentication Flow

1. **Initial request:** the user (e.g. `hossam`) sends the KDC (Key Distribution Center) a timestamp encrypted with the hash of their own password (their NTLM hash), along with their username.
2. **KDC validation:** the KDC decrypts the timestamp using the password hash it has stored for that user in its database, and checks that it matches. The timestamp must fall within a **5-minute** window to be considered valid.
3. **TGT issuance:** once validated, the KDC returns two items:
   - A **TGT**, encrypted with the KDC's own secret key.
   - A **session key**, encrypted using the user's own password-derived key.
4. **Requesting a TGS:** to access a service, the user builds an **Authenticator** containing:
   - The client's principal name
   - The current timestamp

   The Authenticator is encrypted with the session key issued in step 3, and sent to the KDC alongside the original TGT.
5. **TGS issuance:** the KDC returns:
   - A **TGS**, encrypted with the KDC's secret key.
   - A **new session key**, encrypted using the previous session key.
6. **Service access:** with the TGS in hand, the user can now authenticate directly to the target service — IIS, MySQL, or any other Kerberos-integrated service — without that service ever needing to know the user's password.

This ticket-based exchange is precisely what makes Kerberos resistant to the credential-sniffing attacks that plague NTLM: the user's actual password (or its hash) is never transmitted across the network after the very first request.
