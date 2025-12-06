# Linux Security Internals: Automated Auditing & Malware Detection

**Target Audience:** Security Engineering
**Scope:** Automating the review process, Vulnerability Scanning, and Rootkit hunting.

---

## 1. Why Automation Matters
Manual reviews (checking `/etc/passwd`, finding SUIDs) are good for learning the *concepts*, but in a real assessment, manual checks are:
1.  **Slow:** Takes hours per server.
2.  **Prone to Error:** You might miss one flag.
3.  **Hard to Scale:** You can't manually review 500 nodes.

Security Engineers use standard tools to automate the "Discovery" phase, then use manual knowledge to "Verify" the findings.

---

## 2. The Industry Standard: Lynis
Lynis is the most popular open-source security auditing tool for Linux/Unix. It performs hundreds of individual tests (including everything we discussed: Users, SUID, Networking, Logging).

### How it works
It is a shell script (no installation required). It runs checks and assigns a "Hardening Index" score.

### Key Usage for Reviewers
* **Run a Scan:**
    ```bash
    git clone [https://github.com/CISOfy/lynis](https://github.com/CISOfy/lynis)
    cd lynis
    ./lynis audit system
    ```
* **The Output:**
    * **[OK]:** Configuration is good.
    * **[SUGGESTION]:** Not critical, but good to fix (e.g., banner missing).
    * **[WARNING]:** Critical security flaw (e.g., SSH root login enabled, firewall off).
* **Log File:** `/var/log/lynis.log` (Contains technical details).
* **Report:** `/var/log/lynis-report.dat` (Machine readable).

### ❓ Q&A: Can I trust the score?
**Q: If Lynis gives me a score of 90/100, is the server secure?**
**A: No.**
* A server can have a high hardening score but still have a vulnerable kernel (e.g., Dirty COW).
* **Lynis checks configuration hygiene**, not software vulnerabilities (CVEs).

---

## 3. Compliance Auditing: OpenSCAP
If you work in Finance, Gov, or Healthcare, you need **SCAP (Security Content Automation Protocol)**.

### The Concept
It compares your system against a specific "Profile" (e.g., PCI-DSS, STIG, HIPAA).
* **Tool:** `oscap`
* **Security Guide:** `scap-security-guide` (Package containing the rules).

### Usage
```bash
# 1. Install
apt-get install libopenscap8 scap-security-guide

# 2. List Profiles (e.g., CIS Level 2, STIG)
oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml

# 3. Run Audit against CIS Level 2 Profile
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level2_server \
--results report.html \
/usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml

4\. Malware & Rootkit Hunting
-----------------------------

If you suspect a system is already compromised, standard tools might lie to you (e.g., a rootkit can modify ls to hide files). You need dedicated hunters.

### A. Chkrootkit

Checks for signs of LKM (Loadable Kernel Module) rootkits.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   sudo chkrootkit   `

### B. Rkhunter (Rootkit Hunter)

Checks for:

1.  **File Hash Changes:** Did /bin/ls change since the OS was installed?
    
2.  **Hidden Files:** Checks for hidden directories used by malware.
    
3.  **Suspicious Strings:** Looks for strings commonly found in hack tools.
    

**Usage:**

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   rkhunter --update  rkhunter --check --rwo  # --rwo = Report Warnings Only   `

5\. Review Checklist (The Toolkit)
----------------------------------

When entering a new environment for a security review, this is your toolkit sequence:

1.  **Manual Triage (The "smell test"):**
    
    *   Check id, whoami.
        
    *   Check open ports (ss -tulpn).
        
    *   Check sudoers (sudo -l).
        
2.  **Automated Audit (The "deep dive"):**
    
    *   Run **Lynis** to catch misconfigurations.
        
    *   Run **OpenSCAP** if compliance is required.
        
3.  **Malware Check (The "paranoid check"):**
    
    *   Run **rkhunter** to ensure binaries haven't been tampered with.
        
4.  **Verification:**
    
    *   Manually verify the \[WARNING\] outputs from the tools using the internal knowledge you learned in previous modules.


