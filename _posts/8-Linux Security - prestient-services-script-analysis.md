Linux Security Internals: Persistence, Services & Script Analysis
=================================================================

Target Audience: Security Engineering

Scope: Cron Jobs, Systemd Services, Shell Script Auditing, and SSH Hardening.

1\. Persistence Mechanisms (Cron & Timers)
------------------------------------------

If an attacker gets in, they want to _stay_ in. They use standard system automation tools to restart their malware after a reboot. You must audit these locations.

### A. The Cron System

Cron schedules tasks to run at specific times.

*   **User Crons:** /var/spool/cron/crontabs/ (One file per user).
    
*   **System Crons:** /etc/crontab and /etc/cron.d/.
    
*   **Daily/Hourly:** /etc/cron.daily, /etc/cron.hourly.
    

Review Check:

Look for "suspicious" scripts running as root.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   # List all cron jobs for all users (requires root)  for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l; done   `

### B. Systemd Timers (The Modern Cron)

Modern Linux uses Systemd Timers instead of Cron.

*   **List Timers:** systemctl list-timers --all
    
*   **Risk:** Attackers create a .timer unit that triggers a malicious .service unit.
    

2\. Systemd Service Hardening
-----------------------------

Most applications (Web servers, Databases) run as Systemd services. You must review their configuration files (usually in /etc/systemd/system/ or /lib/systemd/system/).

### Analyzing a Unit File (.service)

Run cat /etc/systemd/system/myapp.service and look for these directives:

**DirectiveSecure SettingRisk if MisconfiguredUser=**User=nobody (or specific user)If User=root (default), a compromise of the app compromises the whole OS.**ProtectSystem=**full or strictIf missing, the service can modify /usr and /boot.**ProtectHome=**yesIf missing, the service can read /home (user data/keys).**PrivateTmp=**yesIf no, the service shares /tmp with the host, risking race conditions.**CapabilityBoundingSet=**~CAP\_SYS\_ADMINRestricts which Linux Capabilities the service can use.

### The "Auto-Auditor" Tool

Systemd has a built-in security analyzer!

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   systemd-analyze security [service_name]   `

*   **Output:** It gives a score (0.0 = Safe, 10.0 = Unsafe) and lists exposed vectors.
    

3\. Shell Script Security Analysis
----------------------------------

You will frequently encounter custom Bash scripts written by admins (backups, maintenance). These are often the **weakest link**.

### A. Relative Path Hijacking

**Bad Code:**

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   #!/bin/bash  tar -czf /backup/data.tar.gz /data   `

The Flaw: The script calls tar without a full path (/bin/tar).

The Exploit: An attacker creates a malicious script named tar in /tmp, adds /tmp to the PATH variable, and runs the script. The script executes the malware instead of the real tar.

The Fix: Always use absolute paths: /bin/tar.

### B. Wildcard Injection

**Bad Code:**

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   rm *   `

The Flaw: If a file is named -rf, the command expands to rm -rf, which changes the command's logic.

The Fix: Use ./\* or quote variables.

### C. Unquoted Variables

**Bad Code:**

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   rm $FILES   `

The Flaw: If $FILES contains spaces (e.g., "my file"), it is treated as two files ("my" and "file").

The Fix: Always quote variables: rm "$FILES".

### ❓ Q&A: Is curl | bash safe?

Q: I see developers using curl https://site.com/install.sh | bash. Is this safe?

A: No.

1.  **Network Attack:** A MITM attacker can inject malicious code into the stream.
    
2.  Review Finding: Flag this as High Risk.
    

4\. SSH Hardening (The Front Door)
----------------------------------

SSH is the primary entry point. A default config is often insecure.

**File:** /etc/ssh/sshd\_config

**ParameterRecommendedWhy?**PermitRootLogin**no**Prevents direct root login. Force users to login as self and sudo.PasswordAuthentication**no**Disables passwords. Forces use of SSH Keys (which are harder to brute force).PubkeyAuthentication**yes**Enables SSH Keys.AllowUsers**user1 user2**Whitelists only specific users. Even if bob has a password, he cannot SSH if not listed.X11Forwarding**no**Prevents GUI forwarding (reduces attack surface).

**Audit Command:**

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   sshd -t  # Checks the configuration file for syntax errors/validity   `

5\. Audit & Hunting Commands
----------------------------

1\. Check Systemd Security Score:

Check all running services for exposure.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   systemd-analyze security   `

**2\. Hunt for Suspicious Cron Jobs:**

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   cat /etc/crontab  ls -la /etc/cron.*   `

3\. Static Analysis of Scripts (shellcheck):

If you find custom scripts, use shellcheck (a standard tool) to find logic bugs.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   apt install shellcheck  shellcheck /path/to/script.sh   `

4\. Check for Empty Passwords:

Ensure no user is allowed to login without a password.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   awk -F: '($2 == "") {print $1}' /etc/shadow   `

6\. Final Review Checklist (Services & Scripts)
-----------------------------------------------

1.  **Persistence:** Are there unexpected Cron jobs or Systemd timers?
    
2.  **Services:** Do public-facing services (Nginx, App) run as non-root users?
    
3.  **Hardening:** Do Systemd unit files use ProtectSystem and PrivateTmp?
    
4.  **Scripts:** Do admin scripts use absolute paths and quoted variables?
    
5.  **SSH:** Is Root Login disabled and Password Auth turned off?

