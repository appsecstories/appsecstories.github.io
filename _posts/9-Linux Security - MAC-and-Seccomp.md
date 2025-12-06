# Linux Security Internals: Advanced Confinement (MAC & Seccomp)

**Target Audience:** Security Engineering
**Scope:** SELinux, AppArmor, Seccomp BPF, and Sandboxing.

---

## 1. The Concept: DAC vs. MAC
We previously learned about **DAC (Discretionary Access Control)**: standard `rwx` permissions.
* *Flaw:* If I am Root, DAC ignores me. I can read/write anything.
* *Flaw:* If I own a file, I can change its permissions to 777.

**MAC (Mandatory Access Control)** overrides this.
* The system (Kernel) defines the policy.
* Users (even Root) cannot change the policy.
* **Rule:** "The Apache process can ONLY read `/var/www/html`. It CANNOT read `/etc/shadow`, even if it runs as Root."



---

## 2. SELinux (Red Hat / CentOS / Fedora / Android)
SELinux uses a **Labeling System**. Every file and every process has a "Context."

**Format:** `user:role:type:level`
* **The Critical Part:** The **Type** (3rd field).

### How it works
1.  **Labeling:**
    * The Apache binary is labeled: `httpd_exec_t`
    * The web folder is labeled: `httpd_sys_content_t`
    * The shadow file is labeled: `shadow_t`
2.  **Policy:**
    * Allow `httpd_t` to read `httpd_sys_content_t`.
    * **Deny** `httpd_t` to read `shadow_t`.

### The "Enforcing" Mode
* **Enforcing:** Blocks the action and logs it. (Secure).
* **Permissive:** Allows the action but logs it. (Debug mode).
* **Disabled:** No protection.

**Audit Commands:**
```bash
# Check status
sestatus
# Output: Current mode: enforcing

# Check labels on a file (Z flag)
ls -lZ /var/www/html
# Output: system_u:object_r:httpd_sys_content_t:s0 index.html

# Check labels on a process
ps -eZ | grep httpd

### ❓ Q&A: The "Boolean" Switch

**Q: Developers often disable SELinux because "it breaks the app." How do we fix this securely?A: Use Booleans.**SELinux has on/off switches for common features.

*   _Scenario:_ Apache needs to send an email, but SELinux blocks outgoing SMTP.
    
*   _Bad Fix:_ setenforce 0 (Disable SELinux).
    
*   _Good Fix:_ setsebool -P httpd\_can\_sendmail 1.
    

3\. AppArmor (Ubuntu / Debian / SuSE)
-------------------------------------

AppArmor is **Path-Based** (easier to read than SELinux). It uses "Profiles" loaded into the kernel.

### The Profile

Located in /etc/apparmor.d/. A profile for /usr/bin/nginx might look like:

Plaintext

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   /usr/bin/nginx {    # Capability rules    capability net_bind_service,    # File rules    /var/www/html/ r,      # Read only    /var/log/nginx/* w,    # Write only    /etc/shadow deny,      # Explicit deny  }   `

**Audit Commands:**

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   # Check status and loaded profiles  aa-status  # Result:  # 20 profiles are in enforce mode.  # 5 profiles are in complain mode (Permissive).   `

4\. Seccomp (Secure Computing Mode)
-----------------------------------

While MAC restricts _files_ and _network_, **Seccomp** restricts **System Calls (Syscalls)**.

### The Attack Surface

The Linux Kernel has 400+ syscalls (open, read, write, fork, execve, mount...). A web server only needs about 50 of them.

*   **The Risk:** If an attacker exploits the web server, they might try to use mount or keyctl (obscure syscalls) to escalate privileges.
    
*   **The Fix:** Seccomp creates a whitelist. "This process can only call read, write, and close. If it calls mount, kill it instantly."
    

### Usage in Docker

Docker applies a default Seccomp profile automatically.

*   **Check:** grep Seccomp /proc/\[PID\]/status
    
    *   **0:** Disabled.
        
    *   **2:** Filtering active.
        

5\. Audit & Hunting Commands
----------------------------

**1\. Check SELinux Status:**

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   getenforce  # Expect: Enforcing   `

**2\. List SELinux Booleans (Configuration):**See what exceptions are allowed.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   getsebool -a | grep "on$"   `

**3\. Check AppArmor Status:**

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   aa-status   `

**4\. Check for Unconfined Processes:**Find processes running without MAC protection.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   ps -eZ | grep "unconfined"   `

6\. Final Review Checklist (MAC & Seccomp)
------------------------------------------

1.  **Status:** Is SELinux or AppArmor in **Enforcing** mode? (Critical).
    
2.  **Coverage:** Are critical public services (Web, DB) actually confined?
    
    *   _Check:_ Run ps -Z and ensure they have a specific label/profile, not unconfined or default.
        
3.  **Booleans:** Are SELinux Booleans too permissive? (e.g., allow\_execstack).
    
4.  **Seccomp:** (For Containers) Is the default Seccomp profile enabled?


