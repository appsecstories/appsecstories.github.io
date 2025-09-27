---
layout: post
title: "Secure Code Review Methodology: Part 3"
date: 2025-09-20 10:08:00 +0000
categories: [secure-coding]
tags: [secure-coding]
author: Application Security Engineer
comments: true
excerpt: "It covers the most important vulnerability categories to prioritize during code review. These represent the most common and impactful security issues found in modern applications, based on industry research and vulnerability databases like the OWASP Top 10"
---

## Phase 3: Most Critical Security Issues to Focus On

This section covers the most important vulnerability categories to prioritize during code review. These represent the most common and impactful security issues found in modern applications, based on industry research and vulnerability databases like the OWASP Top 10.

### 1. Lack of Input Validation (Injection Attacks)

**Description:** Input validation failures represent one of the most critical security vulnerabilities in web applications. This category encompasses all types of injection attacks where malicious input is processed by the application without proper validation, sanitization, or parameterization. These attacks occur when untrusted data is sent to an interpreter as part of a command or query, allowing attackers to execute unintended commands or access unauthorized data.

**Why This Matters:** Injection vulnerabilities consistently rank as the top security risk in web applications. They can lead to data theft, data loss, denial of service, and complete system compromise. The impact ranges from unauthorized data access to complete system takeover.

**Common Types:**
- SQL Injection (SQLi)
- NoSQL Injection
- LDAP Injection
- Command Injection (OS Command Injection)
- Code Injection
- XML Injection
- Server-Side Template Injection (SSTI)

**What to Look For:**
- Direct concatenation of user input into queries or commands
- Dynamic query construction without parameterization
- Use of string formatting or concatenation for database queries
- User input passed directly to system commands
- Template rendering with unsanitized user input

**Python Examples:**

```python
class InjectionVulnerabilities:
    def sql_injection_examples(self):
        """
        SQL Injection vulnerability examples and fixes
        """
        
        # VULNERABLE: String concatenation
        def vulnerable_user_lookup(user_id):
            import sqlite3
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            
            # VULNERABLE TO SQL INJECTION
            query = f"SELECT * FROM users WHERE id = {user_id}"
            cursor.execute(query)
            return cursor.fetchone()
        
        # SECURE: Parameterized queries
        def secure_user_lookup(user_id):
            import sqlite3
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            
            # SECURE: Parameterized query
            query = "SELECT * FROM users WHERE id = ?"
            cursor.execute(query, (user_id,))
            return cursor.fetchone()
        
        # VULNERABLE: Dynamic query building
        def vulnerable_search(search_term, category):
            query = "SELECT * FROM products WHERE 1=1"
            if search_term:
                query += f" AND name LIKE '%{search_term}%'"  # VULNERABLE
            if category:
                query += f" AND category = '{category}'"      # VULNERABLE
            return query
        
        # SECURE: Proper parameterization
        def secure_search(search_term, category):
            query = "SELECT * FROM products WHERE 1=1"
            params = []
            
            if search_term:
                query += " AND name LIKE ?"
                params.append(f"%{search_term}%")
            if category:
                query += " AND category = ?"
                params.append(category)
            
            return query, params
    
    def command_injection_examples(self):
        """
        Command injection vulnerability examples and fixes
        """
        
        # VULNERABLE: Direct command execution
        def vulnerable_ping(host):
            import os
            # VULNERABLE TO COMMAND INJECTION
            result = os.system(f"ping -c 1 {host}")
            return result
        
        # SECURE: Input validation and subprocess
        def secure_ping(host):
            import subprocess
            import re
            
            # Input validation
            if not re.match(r'^[a-zA-Z0-9.-]+$', host):
                raise ValueError("Invalid hostname")
            
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', host],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    shell=False  # Important: prevents shell injection
                )
                return result.stdout
            except subprocess.TimeoutExpired:
                return "Ping timeout"
    
    def comprehensive_input_validation(self):
        """
        Comprehensive input validation framework
        """
        
        class InputValidator:
            @staticmethod
            def validate_alphanumeric(value, min_length=1, max_length=100):
                if not isinstance(value, str):
                    return False, "Must be a string"
                if len(value) < min_length or len(value) > max_length:
                    return False, f"Length must be between {min_length} and {max_length}"
                if not re.match(r'^[a-zA-Z0-9]+$', value):
                    return False, "Only alphanumeric characters allowed"
                return True, "Valid"
            
            @staticmethod
            def validate_integer(value, min_value=None, max_value=None):
                try:
                    int_value = int(value)
                except (ValueError, TypeError):
                    return False, "Must be an integer"
                
                if min_value is not None and int_value < min_value:
                    return False, f"Must be at least {min_value}"
                if max_value is not None and int_value > max_value:
                    return False, f"Must be at most {max_value}"
                
                return True, int_value
            
            @staticmethod
            def sanitize_filename(filename):
                # Remove dangerous characters
                import os
                safe_chars = re.sub(r'[^\w\-_\.]', '', filename)
                # Prevent directory traversal
                safe_name = os.path.basename(safe_chars)
                # Prevent hidden files
                if safe_name.startswith('.'):
                    safe_name = safe_name[1:]
                return safe_name[:255]  # Limit length
```


### 2. Lack of Output Encoding

**Description:** Output encoding vulnerabilities occur when user-controlled data is included in application responses without proper encoding or escaping. This primarily leads to Cross-Site Scripting (XSS) attacks, where malicious scripts are executed in users' browsers. Output encoding is context-dependent, meaning different encoding methods are required for HTML, JavaScript, CSS, and URL contexts.

**Why This Matters:** XSS attacks can lead to session hijacking, credential theft, phishing attacks, and complete compromise of user accounts. They allow attackers to execute malicious scripts in the context of legitimate applications, bypassing the same-origin policy and accessing sensitive user data. XSS is particularly dangerous because it directly affects end users and can be used to propagate attacks.

**Common Types:**
- Stored XSS (Persistent)
- Reflected XSS (Non-persistent)
- DOM-based XSS
- Blind XSS
- Self-XSS (social engineering component)

**What to Look For:**
- User input directly rendered in HTML without encoding
- Dynamic JavaScript generation with user input
- User data in URL parameters without encoding
- Template rendering without auto-escaping
- JSON responses with user data that could be interpreted as HTML
- HTTP headers constructed with user input

**Python Examples:**

```python
class OutputEncodingExamples:
    def xss_vulnerability_examples(self):
        """
        XSS vulnerability examples and fixes
        """
        
        # VULNERABLE: Direct output without encoding
        def vulnerable_display_comment(comment):
            html = f"<div class='comment'>{comment}</div>"  # VULNERABLE TO XSS
            return html
        
        # SECURE: HTML encoding
        def secure_display_comment(comment):
            import html
            safe_comment = html.escape(comment)
            html_output = f"<div class='comment'>{safe_comment}</div>"
            return html_output
        
        # VULNERABLE: Template rendering without escaping
        def vulnerable_template_rendering():
            from jinja2 import Template
            
            template = Template("<h1>Welcome {{username}}!</h1>")
            # If username contains <script>alert('XSS')</script>
            # it will be executed in the browser
            return template.render(username=user_input)  # VULNERABLE
        
        # SECURE: Template with auto-escaping
        def secure_template_rendering():
            from jinja2 import Environment, select_autoescape
            
            env = Environment(autoescape=select_autoescape(['html', 'xml']))
            template = env.from_string("<h1>Welcome {{username}}!</h1>")
            return template.render(username=user_input)  # SECURE
    
    def context_specific_encoding(self):
        """
        Different contexts require different encoding approaches
        """
        
        class ContextualEncoder:
            @staticmethod
            def html_encode(data):
                import html
                return html.escape(data)
            
            @staticmethod
            def javascript_encode(data):
                # Encode for JavaScript context
                escaped = data.replace('\\', '\\\\')
                escaped = escaped.replace('"', '\\"')
                escaped = escaped.replace("'", "\\'")
                escaped = escaped.replace('\n', '\\n')
                escaped = escaped.replace('\r', '\\r')
                return escaped
            
            @staticmethod
            def url_encode(data):
                import urllib.parse
                return urllib.parse.quote(data)
            
            @staticmethod
            def css_encode(data):
                # Basic CSS encoding
                import re
                return re.sub(r'[<>"\']', lambda m: f'\\{ord(m.group(0)):x}', data)
        
        # Example usage in different contexts
        def render_page_with_user_data(user_data):
            encoder = ContextualEncoder()
            
            # HTML context
            html_safe = encoder.html_encode(user_data['name'])
            
            # JavaScript context
            js_safe = encoder.javascript_encode(user_data['message'])
            
            # URL context
            url_safe = encoder.url_encode(user_data['search_term'])
            
            template = f"""
            <html>
                <body>
                    <h1>Hello {html_safe}!</h1>
                    <script>
                        var message = "{js_safe}";
                        console.log(message);
                    </script>
                    <a href="/search?q={url_safe}">Search</a>
                </body>
            </html>
            """
            return template
```

### 3. Missing Access Control

**Description:** Access control vulnerabilities occur when applications fail to properly restrict user access to resources, functions, or data based on their authentication status and authorization level. These vulnerabilities allow users to access resources they shouldn't be able to access or perform actions beyond their intended privilege level.

**Why This Matters:** Missing access controls can lead to unauthorized data access, privilege escalation, and complete system compromise. These vulnerabilities often result in the most significant business impact because they directly relate to data protection and system security. They can expose sensitive customer data, financial information, or administrative functions to unauthorized users.

**Common Types:**
- Insecure Direct Object References (IDOR)
- Missing Function Level Access Control
- Missing or Inadequate Authentication
- Privilege Escalation (Vertical and Horizontal)
- Force Browsing to Unauthorized URLs
- Insecure API Endpoints

**What to Look For:**
- Functions that don't check user authentication
- Authorization checks that can be bypassed
- Direct access to resources using predictable IDs
- Missing ownership verification for resource access
- Administrative functions accessible to regular users
- API endpoints without proper access controls

**Python Examples:**

```python
class AccessControlExamples:
    def authorization_vulnerabilities(self):
        """
        Common access control vulnerabilities and fixes
        """
        
        # VULNERABLE: No authorization check
        def vulnerable_get_user_profile(user_id):
            # Anyone can access any user's profile
            user = database.get_user(user_id)  # VULNERABLE
            return user.to_dict()
        
        # SECURE: Proper authorization check
        def secure_get_user_profile(requested_user_id, current_user):
            # Check if current user can access the requested profile
            if current_user.id != requested_user_id and not current_user.is_admin():
                raise PermissionError("Access denied")
            
            user = database.get_user(requested_user_id)
            return user.to_dict()
        
        # VULNERABLE: Insecure Direct Object Reference (IDOR)
        def vulnerable_delete_document(document_id, user):
            # No ownership check
            database.delete_document(document_id)  # VULNERABLE
            return {"status": "deleted"}
        
        # SECURE: Ownership verification
        def secure_delete_document(document_id, user):
            document = database.get_document(document_id)
            if not document:
                return {"error": "Document not found"}, 404
            
            # Check ownership
            if document.owner_id != user.id and not user.is_admin():
                return {"error": "Access denied"}, 403
            
            database.delete_document(document_id)
            return {"status": "deleted"}
    
    def role_based_access_control(self):
        """
        Implementing proper role-based access control
        """
        
        from functools import wraps
        from enum import Enum
        
        class Permission(Enum):
            READ_USER = "read_user"
            WRITE_USER = "write_user"
            DELETE_USER = "delete_user"
            ADMIN_ACCESS = "admin_access"
        
        class Role:
            def __init__(self, name, permissions):
                self.name = name
                self.permissions = permissions
            
            def has_permission(self, permission):
                return permission in self.permissions
        
        # Define roles
        ROLES = {
            'user': Role('user', [Permission.READ_USER]),
            'moderator': Role('moderator', [Permission.READ_USER, Permission.WRITE_USER]),
            'admin': Role('admin', [Permission.READ_USER, Permission.WRITE_USER, 
                                  Permission.DELETE_USER, Permission.ADMIN_ACCESS])
        }
        
        # Authorization decorator
        def require_permission(permission):
            def decorator(func):
                @wraps(func)
                def wrapper(*args, **kwargs):
                    user = kwargs.get('current_user')
                    if not user:
                        raise AuthenticationError("Authentication required")
                    
                    user_role = ROLES.get(user.role)
                    if not user_role or not user_role.has_permission(permission):
                        raise PermissionError("Insufficient permissions")
                    
                    return func(*args, **kwargs)
                return wrapper
            return decorator
        
        # Usage example
        @require_permission(Permission.DELETE_USER)
        def delete_user_account(user_id, current_user=None):
            # Only users with DELETE_USER permission can execute this
            database.delete_user(user_id)
            return {"status": "user deleted"}
```

### 4. Weak Regex Checks

**Description:** Regular expression vulnerabilities occur when poorly designed regex patterns are used for input validation or when regex patterns are vulnerable to ReDoS (Regular expression Denial of Service) attacks. Weak regex can also be bypassed by attackers, leading to validation failures and security vulnerabilities.

**Why This Matters:** Regex vulnerabilities can cause application denial of service through catastrophic backtracking, or they can be bypassed to circumvent security controls. ReDoS attacks can consume excessive CPU resources, making applications unresponsive. Bypassable regex patterns can allow malicious input to reach vulnerable code paths.

**Common Issues:**
- Catastrophic backtracking leading to ReDoS
- Incomplete input validation that can be bypassed
- Case sensitivity issues in security-critical patterns
- Overly complex patterns that are hard to verify
- Regex injection in dynamic pattern construction

**What to Look For:**
- Nested quantifiers in regex patterns (e.g., `(a+)+`, `(a*)*`)
- Complex alternations that can cause backtracking
- Regex patterns used for security validation
- User input incorporated into regex patterns
- Case-sensitive patterns where case-insensitive is needed
- Regex patterns that don't anchor properly (`^` and `$`)

**Python Examples:**

```python
import re
import time

class RegexSecurityExamples:
    def redos_vulnerabilities(self):
        """
        ReDoS (Regular expression Denial of Service) examples
        """
        
        # VULNERABLE: Catastrophic backtracking
        def vulnerable_email_regex(email):
            # This regex can cause exponential backtracking
            pattern = r'^([a-zA-Z0-9])+([a-zA-Z0-9\._-])*@([a-zA-Z0-9_-])+([a-zA-Z0-9\._-]+)+\.[a-zA-Z]{2,6}$'
            return re.match(pattern, email) is not None
        
        # Test case that causes ReDoS:
        # malicious_email = "a" * 50 + "!"  # This will take very long time
        
        # SECURE: Avoid nested quantifiers
        def secure_email_regex(email):
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$'
            return re.match(pattern, email) is not None
        
        # VULNERABLE: Nested quantifiers
        def vulnerable_password_regex(password):
            # Pattern with nested quantifiers - ReDoS vulnerable
            pattern = r'^(a+)+b$'
            return re.match(pattern, password) is not None
        
        # SECURE: Linear time complexity
        def secure_password_regex(password):
            # Check individual requirements separately
            if len(password) < 8:
                return False
            if not re.search(r'[A-Z]', password):
                return False
            if not re.search(r'[a-z]', password):
                return False
            if not re.search(r'\d', password):
                return False
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                return False
            return True
    
    def input_validation_bypasses(self):
        """
        Examples of regex patterns that can be bypassed
        """
        
        # VULNERABLE: Incomplete validation
        def vulnerable_filename_check(filename):
            # Trying to prevent directory traversal
            if re.search(r'\.\.', filename):  # INCOMPLETE - can be bypassed
                return False
            return True
        
        # Bypass examples:
        # "../../../etc/passwd" - blocked
        # "..\/..\/..\/etc/passwd" - bypassed (mixed separators)
        # "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" - bypassed (URL encoded)
        
        # SECURE: Comprehensive validation
        def secure_filename_check(filename):
            import os
            # Normalize the path
            normalized = os.path.normpath(filename)
            
            # Check for directory traversal attempts
            if '..' in normalized:
                return False
            
            # Check for absolute paths
            if os.path.isabs(normalized):
                return False
            
            # Whitelist allowed characters
            if not re.match(r'^[a-zA-Z0-9._-]+$', normalized):
                return False
            
            return True
        
        # VULNERABLE: Case sensitivity issues
        def vulnerable_script_filter(content):
            # Only blocks lowercase script tags
            if re.search(r'<script>', content):  # INCOMPLETE
                return False
            return True
        
        # Bypass: <SCRIPT>, <ScRiPt>, etc.
        
        # SECURE: Case-insensitive and comprehensive
        def secure_script_filter(content):
            # Block various script tag variations
            dangerous_patterns = [
                r'<script[^>]*>',
                r'javascript:',
                r'vbscript:',
                r'onload\s*=',
                r'onerror\s*=',
                r'onclick\s*='
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return False
            
            return True
    
    def timing_safe_comparison(self):
        """
        Avoid timing attacks in string comparison
        """
        
        # VULNERABLE: Direct string comparison
        def vulnerable_token_check(provided_token, valid_token):
            # Vulnerable to timing attacks
            return provided_token == valid_token
        
        # SECURE: Constant-time comparison
        def secure_token_check(provided_token, valid_token):
            import hmac
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(provided_token, valid_token)
```

### 5. Weak Encryption or Cryptography

**Description:** Cryptographic vulnerabilities arise from using weak, outdated, or improperly implemented cryptographic algorithms and practices. This includes using deprecated algorithms, insufficient key lengths, poor key management, weak random number generation, and incorrect implementation of cryptographic operations.

**Why This Matters:** Weak cryptography can completely undermine application security, potentially exposing sensitive data, authentication tokens, and other critical information. Even strong business logic and access controls become ineffective if the underlying cryptographic foundation is weak. Cryptographic failures can lead to data breaches, identity theft, and complete system compromise.

**Common Issues:**
- Use of deprecated algorithms (MD5, SHA1, DES, RC4)
- Insufficient key lengths for current security standards
- Poor random number generation
- Hardcoded cryptographic keys
- Missing salt in password hashing
- Use of ECB mode for symmetric encryption
- Improper certificate validation

**What to Look For:**
- Hash functions like MD5 or SHA1 for security purposes
- Symmetric encryption without authentication (e.g., AES-CBC without HMAC)
- Custom cryptographic implementations
- Predictable random number generation
- Hardcoded encryption keys or salts
- Password storage without proper hashing
- SSL/TLS configuration weaknesses

**Python Examples:**

```python
import hashlib
import secrets
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class CryptographyExamples:
    def password_hashing_examples(self):
        """
        Secure password hashing examples
        """
        
        # WEAK: Plain MD5 hashing
        def weak_password_hash(password):
            return hashlib.md5(password.encode()).hexdigest()  # NEVER USE
        
        # WEAK: SHA-256 without salt
        def weak_sha256_hash(password):
            return hashlib.sha256(password.encode()).hexdigest()  # STILL WEAK
        
        # BETTER: SHA-256 with salt (but still not ideal for passwords)
        def better_password_hash(password):
            salt = secrets.token_hex(16)
            hash_value = hashlib.sha256((password + salt).encode()).hexdigest()
            return f"{salt}:{hash_value}"
        
        # STRONG: bcrypt (recommended for passwords)
        def strong_password_hash(password):
            # bcrypt automatically handles salting and is designed for passwords
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password.encode(), salt)
        
        def verify_bcrypt_password(password, hashed):
            return bcrypt.checkpw(password.encode(), hashed)
        
        # STRONG: PBKDF2 (also good for passwords)
        def pbkdf2_password_hash(password):
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,  # High iteration count
            )
            key = kdf.derive(password.encode())
            return salt + key  # Store salt + hash together
    
    def encryption_examples(self):
        """
        Secure encryption examples
        """
        
        # WEAK: Simple XOR encryption
        def weak_xor_encryption(data, key):
            # XOR encryption is easily broken
            return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
        
        # WEAK: AES without proper mode
        def weak_aes_ecb(data, key):
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            
            # ECB mode is vulnerable to pattern analysis
            cipher = Cipher(algorithms.AES(key), modes.ECB())
            encryptor = cipher.encryptor()
            return encryptor.update(data) + encryptor.finalize()
        
        # STRONG: AES-GCM with proper key derivation
        def strong_aes_gcm_encryption(data, password):
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            # Derive key from password using PBKDF2
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256
                salt=salt,
                iterations=100000
            )
            key = kdf.derive(password.encode())
            
            # Use AES-GCM for authenticated encryption
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
            
            ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
            
            # Return salt + nonce + ciphertext
            return salt + nonce + ciphertext
        
        def strong_aes_gcm_decryption(encrypted_data, password):
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            # Extract components
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]
            
            # Derive key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            key = kdf.derive(password.encode())
            
            # Decrypt
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode()
        
        # STRONG: Using Fernet (high-level interface)
        def fernet_encryption_example():
            # Fernet provides authenticated encryption with a simple interface
            key = Fernet.generate_key()
            f = Fernet(key)
            
            # Encrypt
            data = b"sensitive information"
            encrypted = f.encrypt(data)
            
            # Decrypt
            decrypted = f.decrypt(encrypted)
            
            return key, encrypted, decrypted
    
    def random_number_generation(self):
        """
        Secure random number generation
        """
        
        # WEAK: Using standard random module for security purposes
        import random
        def weak_random_token():
            return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(32))
        
        # STRONG: Using cryptographically secure random
        def strong_random_token():
            return secrets.token_urlsafe(32)  # Cryptographically secure
        
        def strong_random_password(length=16):
            alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
            return ''.join(secrets.choice(alphabet) for _ in range(length))
```

### 6. Insecure Function Usage

**Description:** Insecure function usage occurs when developers use inherently dangerous functions or use secure functions in an insecure manner. These functions often provide powerful capabilities that can be exploited if used with untrusted input or without proper safeguards. The risk comes from functions that can execute arbitrary code, access the file system, or perform other privileged operations.

**Why This Matters:** Dangerous functions can provide attackers with direct paths to code execution, file system access, or other privileged operations. Even when used intentionally, these functions can become security vulnerabilities if proper input validation and sandboxing are not implemented. They represent high-risk attack vectors that can lead to complete system compromise.

**Common Dangerous Functions:**
- Code execution functions (eval, exec, compile)
- System command functions (os.system, subprocess with shell=True)
- Deserialization functions (pickle.loads, yaml.load)
- Dynamic import and attribute access (getattr, setattr, __import__)
- File system access functions used with user input

**What to Look For:**
- Functions that execute user-provided code
- System command execution with user input
- Deserialization of untrusted data
- Dynamic loading of modules or classes
- File operations with user-controlled paths
- Template engines with code execution capabilities

**Python Examples:**

```python
class InsecureFunctionUsage:
    def dangerous_functions_examples(self):
        """
        Examples of dangerous function usage and secure alternatives
        """
        
        # DANGEROUS: eval() function
        def dangerous_eval_usage():
            user_input = "2 + 2"  # Seems harmless
            result = eval(user_input)  # DANGEROUS - can execute arbitrary code
            
            # Malicious input: "__import__('os').system('rm -rf /')"
            return result
        
        # SECURE: ast.literal_eval() for safe evaluation
        def secure_eval_alternative():
            import ast
            user_input = "2 + 2"
            try:
                # Only evaluates literals (numbers, strings, lists, etc.)
                result = ast.literal_eval(user_input)
                return result
            except (ValueError, SyntaxError):
                return None
        
        # DANGEROUS: exec() function
        def dangerous_exec_usage():
            code = "print('Hello World')"  # Seems harmless
            exec(code)  # DANGEROUS - can execute arbitrary Python code
        
        # SECURE: Use specific functions instead of dynamic execution
        def secure_dynamic_execution():
            # Instead of exec, use specific allowed operations
            allowed_operations = {
                'greet': lambda name: f"Hello {name}!",
                'add': lambda x, y: x + y,
                'multiply': lambda x, y: x * y
            }
            
            operation = 'greet'
            if operation in allowed_operations:
                return allowed_operations[operation]('World')
        
        # DANGEROUS: pickle.loads() with untrusted data
        def dangerous_pickle_usage():
            import pickle
            # NEVER use pickle.loads() with untrusted data
            untrusted_data = b"arbitrary pickle data"
            obj = pickle.loads(untrusted_data)  # DANGEROUS
            return obj
        
        # SECURE: Use JSON for data serialization
        def secure_serialization():
            import json
            data = {'name': 'John', 'age': 30}
            
            # Serialize
            serialized = json.dumps(data)
            
            # Deserialize (safe with untrusted data)
            deserialized = json.loads(serialized)
            return deserialized
        
        # DANGEROUS: subprocess with shell=True
        def dangerous_subprocess_usage():
            import subprocess
            filename = "test.txt"
            # DANGEROUS - vulnerable to command injection
            result = subprocess.run(f"cat {filename}", shell=True, capture_output=True)
            return result.stdout
        
        # SECURE: subprocess with proper arguments
        def secure_subprocess_usage():
            import subprocess
            filename = "test.txt"
            
            # Input validation
            import os
            if not os.path.basename(filename) == filename:  # Prevent path traversal
                raise ValueError("Invalid filename")
            
            # Use argument list instead of shell
            try:
                result = subprocess.run(
                    ['cat', filename], 
                    capture_output=True, 
                    text=True,
                    shell=False,  # Important!
                    timeout=5  # Prevent hanging
                )
                return result.stdout
            except subprocess.TimeoutExpired:
                return "Operation timed out"
```

### 7. Error Handling

**Description:** Poor error handling can lead to information disclosure, denial of service, and other security vulnerabilities. This includes exposing detailed error messages to users, failing to log security events properly, and not handling exceptional conditions gracefully. Proper error handling is crucial for both security and application stability.

**Why This Matters:** Error messages often contain sensitive information about system internals, database schemas, file paths, and application logic that can aid attackers. Poor error handling can also lead to application crashes, resource leaks, and denial of service conditions. Conversely, inadequate error logging can make it difficult to detect and respond to security incidents.

**Common Issues:**
- Detailed error messages exposed to users
- Stack traces containing sensitive information
- Unhandled exceptions causing application crashes
- Insufficient logging of security events
- Error messages that reveal system internals
- Inconsistent error responses that aid enumeration attacks

**What to Look For:**
- Try-catch blocks with generic exception handling
- Error messages that expose file paths, database details, or system information
- Missing error logging for security-relevant events
- Different error responses for valid vs. invalid resources (information leakage)
- Unhandled exceptions in critical code paths
- Debug information exposed in production error messages

**Python Examples:**

```python
class ErrorHandlingExamples:
    def information_disclosure_examples(self):
        """
        Examples of error handling that may disclose sensitive information
        """
        
        # VULNERABLE: Detailed error messages in production
        def vulnerable_error_handling():
            try:
                import sqlite3
                conn = sqlite3.connect('/path/to/database.db')
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
                return cursor.fetchone()
            except Exception as e:
                # VULNERABLE - exposes internal details
                return {'error': str(e), 'traceback': traceback.format_exc()}
        
        # SECURE: Generic error messages for users, detailed logs for developers
        def secure_error_handling():
            import logging
            
            try:
                import sqlite3
                conn = sqlite3.connect('/path/to/database.db')
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
                return cursor.fetchone()
            except sqlite3.Error as e:
                # Log detailed error for developers
                logging.error(f"Database error: {e}", exc_info=True)
                # Return generic error to user
                return {'error': 'A database error occurred. Please try again later.'}
            except Exception as e:
                # Log unexpected errors
                logging.error(f"Unexpected error: {e}", exc_info=True)
                # Return generic error to user
                return {'error': 'An unexpected error occurred. Please try again later.'}
    
    def secure_error_handling_patterns(self):
        """
        Secure error handling patterns
        """
        
        class SecureErrorHandler:
            def __init__(self):
                self.logger = logging.getLogger(__name__)
                self.logger.setLevel(logging.INFO)
            
            def handle_authentication_error(self, username, error):
                # Don't reveal whether username exists or not
                self.logger.warning(f"Authentication failed for user: {username}, error: {error}")
                return {'error': 'Invalid username or password'}  # Generic message
            
            def handle_authorization_error(self, user_id, resource, error):
                # Log the security violation
                self.logger.warning(f"Unauthorized access attempt: user {user_id} tried to access {resource}")
                return {'error': 'Access denied'}, 403
            
            def handle_validation_error(self, field_name, value, error):
                # Don't expose internal validation logic
                self.logger.info(f"Validation failed for field {field_name}: {error}")
                return {'error': f'Invalid {field_name}'}
            
            def handle_rate_limit_error(self, user_ip, endpoint):
                # Log potential abuse
                self.logger.warning(f"Rate limit exceeded for IP {user_ip} on endpoint {endpoint}")
                return {'error': 'Too many requests. Please try again later.'}, 429
        
        # Usage example
        def login_endpoint(username, password):
            handler = SecureErrorHandler()
            
            try:
                user = authenticate_user(username, password)
                if not user:
                    return handler.handle_authentication_error(username, "Invalid credentials")
                
                return {'user_id': user.id, 'token': generate_token(user)}
            
            except DatabaseConnectionError:
                handler.logger.error("Database connection failed", exc_info=True)
                return {'error': 'Service temporarily unavailable'}, 503
            
            except Exception as e:
                handler.logger.error(f"Unexpected error in login: {e}", exc_info=True)
                return {'error': 'Login failed. Please try again.'}, 500
    
    def security_logging_best_practices(self):
        """
        Security-focused logging practices
        """
        
        class SecurityLogger:
            def __init__(self):
                self.security_logger = logging.getLogger('security')
                self.audit_logger = logging.getLogger('audit')
                
                # Configure handlers (file, syslog, etc.)
                handler = logging.FileHandler('/var/log/security.log')
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                handler.setFormatter(formatter)
                self.security_logger.addHandler(handler)
            
            def log_authentication_event(self, username, success, ip_address):
                event_type = "AUTH_SUCCESS" if success else "AUTH_FAILURE"
                self.security_logger.info(f"{event_type}: user={username}, ip={ip_address}")
            
            def log_authorization_event(self, user_id, resource, action, success):
                event_type = "AUTHZ_SUCCESS" if success else "AUTHZ_FAILURE"
                self.security_logger.info(f"{event_type}: user={user_id}, resource={resource}, action={action}")
            
            def log_sensitive_operation(self, user_id, operation, target):
                self.audit_logger.info(f"SENSITIVE_OP: user={user_id}, op={operation}, target={target}")
            
            def log_security_violation(self, violation_type, details, ip_address):
                self.security_logger.warning(f"SECURITY_VIOLATION: type={violation_type}, ip={ip_address}, details={details}")
        
        # Example usage
        def secure_delete_user(user_id, current_user, ip_address):
            security_logger = SecurityLogger()
            
            try:
                # Check authorization
                if not current_user.can_delete_user(user_id):
                    security_logger.log_authorization_event(current_user.id, f"user:{user_id}", "delete", False)
                    return {'error': 'Access denied'}, 403
                
                # Perform deletion
                deleted_user = database.delete_user(user_id)
                
                # Log successful operation
                security_logger.log_sensitive_operation(current_user.id, "delete_user", user_id)
                security_logger.log_authorization_event(current_user.id, f"user:{user_id}", "delete", True)
                
                return {'status': 'User deleted successfully'}
                
            except Exception as e:
                # Log error without exposing details to user
                logging.error(f"Error deleting user {user_id}: {e}", exc_info=True)
                return {'error': 'Failed to delete user'}, 500
```

### 8. Security Misconfigurations

**Description:** Security misconfigurations occur when security settings are not properly implemented, configured, or maintained. These vulnerabilities often arise from using default configurations, enabling unnecessary features, or incorrectly implementing security controls. They represent some of the most common vulnerabilities found in production applications.

**Why This Matters:** Security misconfigurations can expose applications to various attacks and often provide easy entry points for attackers. They may reveal sensitive information, provide excessive access, or disable important security controls. These issues are often overlooked because they don't involve code changes but rather configuration settings.

**Common Misconfigurations:**
- Default or weak passwords for administrative accounts
- Unnecessary services, ports, or features enabled
- Improper file and directory permissions
- Missing security headers in HTTP responses
- Verbose error messages in production
- Insecure CORS (Cross-Origin Resource Sharing) configurations
- Weak SSL/TLS configurations

**What to Look For:**
- Debug mode enabled in production environments
- Default administrative accounts and passwords
- Overly permissive access controls and permissions
- Missing security headers (HSTS, CSP, X-Frame-Options)
- Insecure session management configurations
- Weak or missing HTTPS configurations
- Excessive information disclosure in error messages

**Python Examples:**

```python
class SecurityMisconfigurationExamples:
    def django_security_settings(self):
        """
        Django security configuration examples
        """
        
        # INSECURE Django settings
        insecure_settings = {
            'DEBUG': True,  # NEVER True in production
            'SECRET_KEY': 'hardcoded-secret-key',  # NEVER hardcode
            'ALLOWED_HOSTS': ['*'],  # Too permissive
            'SECURE_SSL_REDIRECT': False,  # Should be True in production
            'SESSION_COOKIE_SECURE': False,  # Should be True with HTTPS
            'CSRF_COOKIE_SECURE': False,  # Should be True with HTTPS
            'SECURE_BROWSER_XSS_FILTER': False,  # Should be True
            'SECURE_CONTENT_TYPE_NOSNIFF': False,  # Should be True
            'X_FRAME_OPTIONS': 'ALLOWALL',  # Should be 'DENY' or 'SAMEORIGIN'
        }
        
        # SECURE Django settings
        secure_settings = {
            'DEBUG': False,  # Always False in production
            'SECRET_KEY': os.environ.get('DJANGO_SECRET_KEY'),  # From environment
            'ALLOWED_HOSTS': ['yourdomain.com', 'www.yourdomain.com'],  # Specific hosts
            'SECURE_SSL_REDIRECT': True,  # Force HTTPS
            'SESSION_COOKIE_SECURE': True,  # HTTPS only cookies
            'CSRF_COOKIE_SECURE': True,  # HTTPS only CSRF cookies
            'SECURE_BROWSER_XSS_FILTER': True,  # Enable XSS filter
            'SECURE_CONTENT_TYPE_NOSNIFF': True,  # Prevent MIME sniffing
            'X_FRAME_OPTIONS': 'DENY',  # Prevent clickjacking
            'SECURE_HSTS_SECONDS': 31536000,  # HTTP Strict Transport Security
            'SECURE_HSTS_INCLUDE_SUBDOMAINS': True,
            'SECURE_HSTS_PRELOAD': True,
        }
    
    def cors_misconfiguration(self):
        """
        CORS (Cross-Origin Resource Sharing) security examples
        """
        
        # INSECURE: Overly permissive CORS
        def insecure_cors_config():
            from flask_cors import CORS
            from flask import Flask
            
            app = Flask(__name__)
            # DANGEROUS - allows all origins
            CORS(app, origins='*', supports_credentials=True)
        
        # SECURE: Restrictive CORS configuration
        def secure_cors_config():
            from flask_cors import CORS
            from flask import Flask
            
            app = Flask(__name__)
            # Only allow specific origins
            allowed_origins = [
                'https://yourdomain.com',
                'https://www.yourdomain.com'
            ]
            CORS(app, origins=allowed_origins, supports_credentials=True)
        
        # Manual CORS handling with validation
        def handle_cors_manually():
            from flask import request, make_response
            
            def add_cors_headers(response):
                origin = request.headers.get('Origin')
                allowed_origins = ['https://yourdomain.com', 'https://www.yourdomain.com']
                
                if origin in allowed_origins:
                    response.headers['Access-Control-Allow-Origin'] = origin
                    response.headers['Access-Control-Allow-Credentials'] = 'true'
                    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
                    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
                
                return response
    
    def database_security_configuration(self):
        """
        Database security configuration examples
        """
        
        # INSECURE: Database connection with excessive privileges
        def insecure_db_connection():
            import psycopg2
            
            # INSECURE - using superuser account
            connection = psycopg2.connect(
                host="localhost",
                database="myapp",
                user="postgres",  # Superuser - too much privilege
                password="password123"  # Weak password
            )
            return connection
        
        # SECURE: Least privilege database connection
        def secure_db_connection():
            import psycopg2
            import os
            
            # Use dedicated application user with minimal privileges
            connection = psycopg2.connect(
                host=os.environ.get('DB_HOST', 'localhost'),
                database=os.environ.get('DB_NAME', 'myapp'),
                user=os.environ.get('DB_USER', 'myapp_user'),  # Limited privilege user
                password=os.environ.get('DB_PASSWORD'),  # Strong password from environment
                sslmode='require'  # Enforce SSL/TLS
            )
            return connection
        
        # Database user privileges should be minimal
        sql_user_setup = '''
        -- Create application user with minimal privileges
        CREATE USER myapp_user WITH PASSWORD 'strong_random_password';
        
        -- Grant only necessary permissions
        GRANT CONNECT ON DATABASE myapp TO myapp_user;
        GRANT USAGE ON SCHEMA public TO myapp_user;
        GRANT SELECT, INSERT, UPDATE, DELETE ON specific_tables TO myapp_user;
        
        -- Do NOT grant:
        -- SUPERUSER, CREATEDB, CREATEROLE permissions
        '''
    
    def session_management_security(self):
        """
        Secure session management configuration
        """
        
        # INSECURE: Weak session configuration
        def insecure_session_config():
            import flask
            app = flask.Flask(__name__)
            
            # INSECURE settings
            app.config['SESSION_COOKIE_NAME'] = 'session'  # Predictable name
            app.config['SESSION_COOKIE_HTTPONLY'] = False  # Accessible via JavaScript
            app.config['SESSION_COOKIE_SECURE'] = False  # Can be sent over HTTP
            app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 365  # 1 year - too long
        
        # SECURE: Strong session configuration
        def secure_session_config():
            import flask
            from datetime import timedelta
            import secrets
            
            app = flask.Flask(__name__)
            
            # Secure session settings
            app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
            app.config['SESSION_COOKIE_NAME'] = 'secure_session'  # Non-predictable name
            app.config['SESSION_COOKIE_HTTPONLY'] = True  # Not accessible via JavaScript
            app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
            app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # CSRF protection
            app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # Short lifetime
            
            @app.before_request
            def regenerate_session():
                # Regenerate session ID on privilege changes
                if request.endpoint in ['login', 'logout', 'change_password']:
                    session.regenerate_id()
        
        # Session validation example
        def validate_session(session_token):
            import jwt
            import datetime
            
            try:
                # Decode and validate session token
                payload = jwt.decode(
                    session_token, 
                    os.environ.get('JWT_SECRET'), 
                    algorithms=['HS256']
                )
                
                # Check expiration
                if datetime.datetime.utcnow() > datetime.datetime.fromtimestamp(payload['exp']):
                    return None
                
                # Check user status
                user = get_user(payload['user_id'])
                if not user or not user.is_active:
                    return None
                
                return user
                
            except jwt.InvalidTokenError:
                return None
```

### 9. Hardcoded Secrets

**Description:** Hardcoded secrets vulnerabilities occur when sensitive information such as passwords, API keys, cryptographic keys, or other credentials are embedded directly in source code, configuration files, or other artifacts that may be accessible to unauthorized parties. These secrets should be stored securely and accessed through secure configuration management systems.

**Why This Matters:** Hardcoded secrets represent immediate and critical security risks because they can be discovered by anyone with access to the source code, including through version control systems, backups, or compromised development environments. They often provide direct access to critical systems, databases, and external services, potentially leading to complete system compromise.

**Common Forms:**
- Database passwords in connection strings
- API keys and tokens in configuration files
- Private keys and certificates in the codebase
- Encryption keys and initialization vectors
- Third-party service credentials
- Administrative passwords and default credentials

**What to Look For:**
- String literals containing passwords, keys, or tokens
- Configuration files with embedded credentials
- Comments containing sensitive information
- Connection strings with embedded authentication
- Environment variables with default secret values
- Cryptographic keys defined as constants

**Python Examples:**

```python
class HardcodedSecretsExamples:
    def bad_practices_examples(self):
        """
        Examples of hardcoded secrets (NEVER DO THIS)
        """
        
        # NEVER DO THESE:
        DATABASE_PASSWORD = "super_secret_password_123"
        API_KEY = "sk_live_1234567890abcdefghijklmnop"
        JWT_SECRET = "my-jwt-secret-key"
        ENCRYPTION_KEY = b"32-byte-key-for-aes-encryption"
        
        # NEVER hardcode credentials in connection strings
        def bad_database_connection():
            import psycopg2
            return psycopg2.connect(
                "postgresql://username:password@localhost:5432/database"
            )
        
        # NEVER hardcode API keys in source
        def bad_api_call():
            import requests
            headers = {'Authorization': 'Bearer sk_live_hardcoded_key'}
            return requests.get('https://api.example.com/data', headers=headers)
    
    def secure_secrets_management(self):
        """
        Secure ways to handle secrets
        """
        
        # GOOD: Use environment variables
        import os
        
        def secure_database_connection():
            import psycopg2
            return psycopg2.connect(
                host=os.environ.get('DB_HOST'),
                database=os.environ.get('DB_NAME'),
                user=os.environ.get('DB_USER'),
                password=os.environ.get('DB_PASSWORD')
            )
        
        # GOOD: Use configuration files (not in version control)
        def load_config_from_file():
            import json
            
            try:
                with open('/etc/myapp/config.json', 'r') as f:
                    config = json.load(f)
                return config
            except FileNotFoundError:
                raise Exception("Configuration file not found")
        
        # GOOD: Use cloud secret management services
        def get_secret_from_aws():
            import boto3
            import json
            
            client = boto3.client('secretsmanager', region_name='us-east-1')
            
            try:
                response = client.get_secret_value(SecretId='myapp/database')
                return json.loads(response['SecretString'])
            except Exception as e:
                raise Exception(f"Failed to retrieve secret: {e}")
        
        # GOOD: Use Azure Key Vault
        def get_secret_from_azure():
            from azure.keyvault.secrets import SecretClient
            from azure.identity import DefaultAzureCredential
            
            credential = DefaultAzureCredential()
            client = SecretClient(
                vault_url="https://your-vault.vault.azure.net/",
                credential=credential
            )
            
            secret = client.get_secret("database-password")
            return secret.value
    
    def secrets_detection_tools(self):
        """
        Tools and techniques for detecting hardcoded secrets
        """
        
        import re
        
        class SecretScanner:
            def __init__(self):
                self.patterns = {
                    'generic_secrets': [
                        r'password\s*=\s*["\'][^"\']{8,}["\']',
                        r'secret\s*=\s*["\'][^"\']{8,}["\']',
                        r'api[_-]?key\s*=\s*["\'][^"\']{8,}["\']',
                        r'token\s*=\s*["\'][^"\']{8,}["\']'
                    ],
                    'aws_keys': [
                        r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                        r'["\'][0-9a-zA-Z/+]{40}["\']'  # AWS Secret Key
                    ],
                    'private_keys': [
                        r'-----BEGIN\s+.*PRIVATE\s+KEY-----',
                        r'-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----'
                    ],
                    'database_urls': [
                        r'postgresql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+',
                        r'mysql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+'
                    ]
                }
            
            def scan_code(self, code_content):
                findings = []
                
                for category, patterns in self.patterns.items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, code_content, re.IGNORECASE)
                        for match in matches:
                            findings.append({
                                'category': category,
                                'pattern': pattern,
                                'match': match.group(),
                                'line': code_content[:match.start()].count('\n') + 1
                            })
                
                return findings
            
            def scan_file(self, file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    return self.scan_code(content)
                except Exception as e:
                    return [{'error': f"Failed to scan {file_path}: {e}"}]
    
    def secure_configuration_management(self):
        """
        Best practices for configuration management
        """
        
        class SecureConfigManager:
            def __init__(self):
                self.config = {}
                self.load_configuration()
            
            def load_configuration(self):
                # Priority order: Environment variables > Config file > Defaults
                
                # 1. Load defaults
                defaults = {
                    'DEBUG': False,
                    'DATABASE_TIMEOUT': 30,
                    'MAX_FILE_SIZE': 5 * 1024 * 1024  # 5MB
                }
                self.config.update(defaults)
                
                # 2. Load from config file (if exists)
                try:
                    import json
                    with open('/etc/myapp/config.json', 'r') as f:
                        file_config = json.load(f)
                        self.config.update(file_config)
                except FileNotFoundError:
                    pass  # Config file is optional
                
                # 3. Override with environment variables
                env_mappings = {
                    'DEBUG': 'APP_DEBUG',
                    'DATABASE_URL': 'DATABASE_URL',
                    'SECRET_KEY': 'SECRET_KEY',
                    'API_KEY': 'API_KEY'
                }
                
                for config_key, env_var in env_mappings.items():
                    env_value = os.environ.get(env_var)
                    if env_value is not None:
                        # Type conversion for boolean values
                        if config_key == 'DEBUG':
                            self.config[config_key] = env_value.lower() in ('true', '1', 'yes')
                        else:
                            self.config[config_key] = env_value
            
            def get(self, key, default=None):
                return self.config.get(key, default)
            
            def validate_configuration(self):
                """Validate that required configuration is present"""
                required_keys = ['SECRET_KEY', 'DATABASE_URL']
                
                missing_keys = []
                for key in required_keys:
                    if not self.config.get(key):
                        missing_keys.append(key)
                
                if missing_keys:
                    raise Exception(f"Missing required configuration: {missing_keys}")
                
                # Validate SECRET_KEY strength
                secret_key = self.config.get('SECRET_KEY', '')
                if len(secret_key) < 32:
                    raise Exception("SECRET_KEY must be at least 32 characters long")
```

### 10. Logging

**Description:** Logging vulnerabilities encompass inadequate security logging, excessive information disclosure through logs, log injection attacks, and poor log management practices. Proper security logging is essential for incident detection, forensic analysis, and compliance requirements, while improper logging can expose sensitive information or provide attack vectors.

**Why This Matters:** Effective security logging is crucial for detecting attacks, conducting forensic analysis, and meeting compliance requirements. Poor logging practices can hide security incidents from detection, while overly verbose logging can expose sensitive information. Log injection attacks can manipulate log files to hide malicious activity or conduct further attacks.

**Common Logging Issues:**
- Insufficient logging of security events
- Logging sensitive information (passwords, tokens, personal data)
- Log injection vulnerabilities
- Poor log retention and protection policies
- Missing correlation and monitoring capabilities
- Inadequate log formatting for analysis tools

**What to Look For:**
- Security events that are not logged (authentication, authorization failures)
- User input included in log messages without sanitization
- Sensitive data logged in plain text
- Missing timestamps, user context, or session information in logs
- Logs stored with inadequate access controls
- Log files without integrity protection mechanisms

**Python Examples:**

```python
import logging
import json
from datetime import datetime
import hashlib

class SecurityLoggingExamples:
    def __init__(self):
        self.setup_logging()
    
    def setup_logging(self):
        """
        Configure secure logging setup
        """
        
        # Create different loggers for different purposes
        self.security_logger = logging.getLogger('security')
        self.audit_logger = logging.getLogger('audit')
        self.application_logger = logging.getLogger('application')
        
        # Set log levels
        self.security_logger.setLevel(logging.INFO)
        self.audit_logger.setLevel(logging.INFO)
        self.application_logger.setLevel(logging.WARNING)
        
        # Create formatters
        security_formatter = logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
        )
        
        audit_formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(levelname)s - %(message)s'
        )
        
        # Create file handlers
        security_handler = logging.FileHandler('/var/log/security.log')
        audit_handler = logging.FileHandler('/var/log/audit.log')
        
        security_handler.setFormatter(security_formatter)
        audit_handler.setFormatter(audit_formatter)
        
        # Add handlers to loggers
        self.security_logger.addHandler(security_handler)
        self.audit_logger.addHandler(audit_handler)
    
    def security_event_logging(self):
        """
        Examples of important security events to log
        """
        
        def log_authentication_event(self, username, success, ip_address, user_agent):
            """Log authentication attempts"""
            event_data = {
                'event_type': 'AUTHENTICATION',
                'username': username,
                'success': success,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            level = logging.INFO if success else logging.WARNING
            self.security_logger.log(level, json.dumps(event_data))
        
        def log_authorization_event(self, user_id, resource, action, success, ip_address):
            """Log authorization decisions"""
            event_data = {
                'event_type': 'AUTHORIZATION',
                'user_id': user_id,
                'resource': resource,
                'action': action,
                'success': success,
                'ip_address': ip_address,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            level = logging.INFO if success else logging.WARNING
            self.security_logger.log(level, json.dumps(event_data))
        
        def log_sensitive_operation(self, user_id, operation, target, ip_address):
            """Log sensitive operations for audit trail"""
            event_data = {
                'event_type': 'SENSITIVE_OPERATION',
                'user_id': user_id,
                'operation': operation,
                'target': target,
                'ip_address': ip_address,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.audit_logger.info(json.dumps(event_data))
        
        def log_security_violation(self, violation_type, details, ip_address, user_agent):
            """Log security violations and potential attacks"""
            event_data = {
                'event_type': 'SECURITY_VIOLATION',
                'violation_type': violation_type,
                'details': details,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.security_logger.error(json.dumps(event_data))
    
    def log_sanitization_examples(self):
        """
        Examples of proper log sanitization to prevent log injection
        """
        
        def sanitize_log_input(self, user_input):
            """Sanitize user input before logging"""
            if not isinstance(user_input, str):
                user_input = str(user_input)
            
            # Remove or escape dangerous characters
            sanitized = user_input.replace('\n', '\\n')
            sanitized = sanitized.replace('\r', '\\r')
            sanitized = sanitized.replace('\t', '\\t')
            
            # Limit length to prevent log flooding
            if len(sanitized) > 1000:
                sanitized = sanitized[:1000] + '...[TRUNCATED]'
            
            return sanitized
        
        def safe_logging_example(self, username, user_input):
            """Example of safe logging with input sanitization"""
            
            # VULNERABLE: Direct logging of user input
            # logging.info(f"User {username} searched for: {user_input}")  # DON'T DO THIS
            
            # SECURE: Sanitized logging
            safe_username = self.sanitize_log_input(username)
            safe_input = self.sanitize_log_input(user_input)
            
            log_entry = {
                'event_type': 'USER_SEARCH',
                'username': safe_username,
                'search_term': safe_input,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.application_logger.info(json.dumps(log_entry))
    
    def structured_logging_examples(self):
        """
        Examples of structured logging for better analysis
        """
        
        class StructuredLogger:
            def __init__(self, logger_name):
                self.logger = logging.getLogger(logger_name)
                
                # Use JSON formatter for structured logs
                handler = logging.StreamHandler()
                formatter = logging.Formatter('%(message)s')
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
            
            def log_event(self, event_type, **kwargs):
                """Log structured events"""
                log_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'event_type': event_type,
                    **kwargs
                }
                
                self.logger.info(json.dumps(log_entry))
            
            def log_performance_metric(self, operation, duration, user_id=None):
                """Log performance metrics"""
                self.log_event(
                    'PERFORMANCE',
                    operation=operation,
                    duration_ms=duration,
                    user_id=user_id
                )
            
            def log_error_with_context(self, error, user_id=None, request_id=None):
                """Log errors with context"""
                self.log_event(
                    'ERROR',
                    error_type=type(error).__name__,
                    error_message=str(error),
                    user_id=user_id,
                    request_id=request_id
                )
        
        # Usage example
        def example_usage():
            structured_logger = StructuredLogger('myapp')
            
            # Log user action
            structured_logger.log_event(
                'USER_ACTION',
                action='file_upload',
                user_id='123',
                file_size=1024000,
                file_type='pdf'
            )
            
            # Log security event
            structured_logger.log_event(
                'SECURITY',
                event='failed_login',
                username='johndoe',
                ip_address='192.168.1.100',
                attempts=3
            )
    
    def log_retention_and_protection(self):
        """
        Examples of log retention and protection strategies
        """
        
        class SecureLogManager:
            def __init__(self):
                self.log_directory = '/var/log/secure'
                self.retention_days = 90
            
            def rotate_logs(self):
                """Implement log rotation for security logs"""
                from logging.handlers import TimedRotatingFileHandler
                
                # Rotate logs daily, keep for 90 days
                handler = TimedRotatingFileHandler(
                    filename='/var/log/security.log',
                    when='midnight',
                    interval=1,
                    backupCount=self.retention_days
                )
                
                return handler
            
            def hash_log_entries(self, log_content):
                """Create hash of log entries for integrity verification"""
                return hashlib.sha256(log_content.encode()).hexdigest()
            
            def protect_log_files(self):
                """Set appropriate permissions on log files"""
                import os
                import stat
                
                log_files = [
                    '/var/log/security.log',
                    '/var/log/audit.log',
                    '/var/log/application.log'
                ]
                
                for log_file in log_files:
                    try:
                        # Set read/write for owner only
                        os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)
                        
                        # Change ownership to log user
                        # os.chown(log_file, log_uid, log_gid)  # Requires appropriate privileges
                    
                    except OSError as e:
                        logging.error(f"Failed to set permissions on {log_file}: {e}")
            
            def centralized_logging_example(self):
                """Example of centralized logging setup"""
                import logging.handlers
                
                # Send logs to centralized syslog server
                syslog_handler = logging.handlers.SysLogHandler(
                    address=('logserver.example.com', 514)
                )
                
                # Format for syslog
                syslog_formatter = logging.Formatter(
                    'myapp[%(process)d]: %(name)s - %(levelname)s - %(message)s'
                )
                syslog_handler.setFormatter(syslog_formatter)
                
                # Add to security logger
                security_logger = logging.getLogger('security')
                security_logger.addHandler(syslog_handler)
    
    def monitoring_and_alerting_integration(self):
        """
        Integration with monitoring and alerting systems
        """
        
        class SecurityMonitoring:
            def __init__(self):
                self.alert_thresholds = {
                    'failed_logins': 5,  # Alert after 5 failed logins
                    'privilege_escalation': 1,  # Alert immediately
                    'suspicious_file_access': 3
                }
                self.time_window = 300  # 5 minutes
            
            def check_for_alerts(self, event_type, count, time_period):
                """Check if event pattern triggers an alert"""
                threshold = self.alert_thresholds.get(event_type)
                
                if threshold and count >= threshold and time_period <= self.time_window:
                    self.send_security_alert(event_type, count, time_period)
            
            def send_security_alert(self, event_type, count, time_period):
                """Send security alert (example integration)"""
                alert_data = {
                    'alert_type': 'SECURITY_THRESHOLD_EXCEEDED',
                    'event_type': event_type,
                    'count': count,
                    'time_period_seconds': time_period,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                # Log the alert
                logging.critical(json.dumps(alert_data))
                
                # Send to monitoring system (example)
                # self.send_to_monitoring_system(alert_data)
                
                # Send notification (example)
                # self.send_notification(alert_data)
            
            def log_with_correlation_id(self, correlation_id, event_type, **kwargs):
                """Log events with correlation ID for request tracing"""
                log_entry = {
                    'correlation_id': correlation_id,
                    'event_type': event_type,
                    'timestamp': datetime.utcnow().isoformat(),
                    **kwargs
                }
                
                logging.info(json.dumps(log_entry))
```

## Conclusion

This comprehensive secure code review methodology provides a structured approach to identifying and mitigating security vulnerabilities in Python applications. The three-phase approach—Reconnaissance, Mapping, and Vulnerability Focus—ensures thorough coverage of potential security issues while providing practical, actionable guidance for security professionals.

### Key Takeaways

1. **Systematic Approach**: Following a structured methodology ensures consistent and comprehensive security reviews that don't miss critical areas.

2. **Context-Driven Analysis**: Understanding the application's architecture, users, and data flow is crucial for effective security assessment and proper risk prioritization.

3. **Risk-Based Prioritization**: Focusing on high-risk areas such as externally facing code, user input handling, and authentication/authorization mechanisms provides the best return on security investment.

4. **Defense in Depth**: Implementing multiple layers of security controls (input validation, output encoding, access control, etc.) provides robust protection against various attack vectors.

5. **Proactive Security**: Many vulnerabilities can be prevented by following secure coding practices from the beginning of the development process rather than attempting to retrofit security later.

### Implementation Recommendations

- **Automate Where Possible**: Use static analysis tools and dependency scanners to identify obvious issues, but complement with manual review for business logic flaws and context-specific vulnerabilities.

- **Regular Reviews**: Conduct security reviews regularly throughout the development lifecycle, not just before major releases or after incidents.

- **Developer Training**: Educate development teams on secure coding practices to prevent vulnerabilities at the source and improve the overall security posture.

- **Documentation and Knowledge Sharing**: Maintain detailed documentation of security controls, review findings, and lessons learned to build organizational security knowledge.

- **Continuous Improvement**: Update the methodology based on new attack vectors, emerging vulnerabilities, and lessons learned from security incidents and industry best practices.

- **Integration with Development Workflows**: Embed security review processes into existing development workflows to ensure they become part of the standard development practice.

### Final Notes

Security code review is both an art and a science, requiring technical expertise, systematic methodology, and deep understanding of both security principles and application functionality. This methodology provides a solid foundation, but successful implementation requires:

- **Experienced practitioners** who understand both security and the specific technology stack
- **Adequate time allocation** to perform thorough analysis rather than superficial checks
- **Management support** to address identified vulnerabilities and implement security improvements
- **Continuous learning** to stay current with new attack techniques and security best practices

Remember that security is an ongoing process, not a one-time activity. Regular security reviews, combined with other security practices like threat modeling, penetration testing, automated security testing, and security monitoring, form a comprehensive application security program that can effectively protect against evolving threats.

By following this methodology and implementing the security controls demonstrated in the code examples, organizations can significantly improve their application security posture and reduce the risk of successful attacks while building a culture of security awareness and responsibility within their development teams.