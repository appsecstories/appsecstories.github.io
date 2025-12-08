---
layout: post
title: "Linux Security - Storage, Hardening & Auditing"
date: 2025-11-20 10:00:00 +0000
categories: [linux-security]
tags: [linux-security]
author: Application Security Engineer
comments: true
excerpt: "Linux systems are constantly exposed to network traffic, making secure network configuration essential to prevent unauthorized access and remote attacks."
---

## 1. Filesystem Security & Hardening
In Linux, the filesystem is not just a bucket for files; it is a configurable layer that can enforce security policies.

### The Power of Mount Options
When a disk partition is attached ("mounted") to the system, you can apply flags that restrict what can happen on that disk. This is a critical area for security reviews.

**Key Hardening Flags:**

| Flag | Effect | Security Value |
| :--- | :--- | :--- |
| **noexec** | Cannot run binaries/scripts on this partition. | **Critical for `/tmp` and `/dev/shm`**. Prevents attackers from downloading malware to temporary folders and executing it. |
| **nosuid** | SUID bits are ignored. | **Critical for `/home` and `/tmp`**. Prevents users from creating their own SUID root backdoors in their home folders. |
| **nodev** | Cannot interpret character/block special devices. | Prevents creation of device files that could bypass access controls. |
| **ro** | Read-Only. | Used for container root filesystems to ensure immutability. |

### ❓ Q&A: The `/tmp` Trap
**Q: Why is `/tmp` a specific target for security reviews?**
**A:** `/tmp` is usually world-writable (`777`).
* **The Risk:** Attackers use it as a "staging area" to download exploits or compile tools because they are guaranteed write access.
* **The Fix:** Mounting `/tmp` with `noexec` breaks this kill chain. The attacker can download the malware, but the kernel refuses to execute it.


## 2. File Attributes (Beyond `rwx`)
Standard permissions (`chmod`) are stored in the inode. However, Linux has **Extended Attributes** that override standard permissions.

### The Immutable Bit (`+i`)
Even if you are Root (UID 0), you **cannot** delete, rename, or modify a file with the `+i` attribute.
* **Defense:** Admins use this to protect logs or configs.
* **Offense:** Malware (crypto-miners) uses this to make itself "undeletable" even by root.

**Commands:**
```bash
# Set immutable bit
chattr +i /etc/shadow
```

**View attributes (ls -l will NOT show this)**
lsattr /etc/shadow

**Output: ----i--------- /etc/shadow**

## 3. Logging & Visibility (Systemd Journal & Syslog)

If a security event happens, where is it recorded?

### The Two Standards

1.  **Syslog (/var/log/):** The traditional text-based logs.
    
    *   /var/log/auth.log (or secure in RHEL): SSH logins, sudo usage. **(Review Priority #1)**.
        
    *   /var/log/syslog (or messages in RHEL): General system activity (Kernel errors, Service startups).
        
2.  **Journald:** The modern, binary logging system used by systemd.
    
    *   It collects stdout/stderr from services.
        
    *   By default, it is often **volatile** (stored in RAM//run), meaning logs disappear on reboot unless Storage=persistent is set in /etc/systemd/journald.conf.
        
    *   **Command:** journalctl -xe (View recent events).
        

### ❓ Q&A: Can logs be tampered with?

**Q: If an attacker gets root, can they wipe the logs?A: Yes.**

*   **Local Deletion:** They can simply rm /var/log/auth.log.
    
*   **Timestomping:** They can alter the modification time of logs to hide their activity.
    
*   **The Solution:** **Remote Logging**. In high-security environments, logs should be shipped instantly to a remote server (SIEM/Splunk) so local deletion doesn't matter.
    

## 4. The Linux Audit Framework (auditd)

While Syslog records "high-level" events (e.g., "User Bob logged in"), auditd records "low-level" kernel calls (e.g., "User Bob called the open() syscall on file /etc/secret").

**Why it matters:**This is the gold standard for compliance (PCI-DSS, FedRAMP). It tells you exactly _who_ touched _what_, even if they tried to hide it or use a different filename.

### Configuring Watches (/etc/audit/audit.rules)

You can set "Watches" on specific files to trigger alerts whenever they are accessed.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   
# Syntax: -w [path] -p [permissions] -k [key_name]  
# Watch /etc/shadow for writes (w) or attribute changes (a)  -w /etc/shadow -p wa -k shadow_changes  
# Watch for execution of tcpdump (network sniffing)  -w /usr/sbin/tcpdump -p x -k sniffing   `

### Searching Logs (ausearch)

Audit logs are stored in /var/log/audit/audit.log, but they are hard to read raw. Use ausearch.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   # Search for events related to the "shadow_changes" key defined above  ausearch -k shadow_changes  # Search for events caused by a specific user ID  ausearch -ui 1000   `

## 5. Audit & Hunting Commands (The "Hunter" List)

**1\. Check Mount Flags (Hardening):**Look for noexec on /tmp and /dev/shm.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   mount | grep "noexec"   `

**2\. Hunt for Hidden Immutable Files:**Attackers might hide files using chattr. This command recursively searches for files with the i attribute.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   lsattr -R / 2>/dev/null | grep "\-i\-"   `

**3. Check SSH Login Attempts:**

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   # Failed attempts (Brute Force detection)  grep "Failed password" /var/log/auth.log  # Successful root logins  grep "Accepted password for root" /var/log/auth.log   `

**4. Check Disk Encryption:**Is the disk encrypted (LUKS)? Essential for physical security reviews.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   lsblk -f | grep crypto_LUKS   `

**5. Check Auditd Status:**Ensure the kernel audit system is active.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   auditctl -s   `

## 6. Review Checklist

1.  **Partitioning:** Are /tmp, /var, and /home on separate partitions? (Prevents log flooding from filling up the root disk and crashing the OS).
    
2.  **Mounts:** Is /tmp mounted with noexec, nosuid, and nodev?
    
3.  **Attributes:** Are there unexpected immutable files (+i) in system directories?
    
4.  **Logging:** Is auditd running? Are logs being shipped remotely?
    
5.  **Persistence:** Is journald configured to store logs on disk (Storage=persistent)?
    
6.  **Encryption:** Is full-disk encryption enabled (for laptops/workstations)?
