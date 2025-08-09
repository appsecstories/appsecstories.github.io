---
layout: post
title: "Cross Site Scripting"
date: 2025-08-09 10:00:00 +0000
categories: [pentest]
tags: [owasp, development, best-practices]
author: Application Security Engineer
comments: true
excerpt: "Web attack are common, Cross Site Scripting is one amoung the famous web attacks which allows to run attacker controlled javascript code on the client"
---

**Cross-site scripting (XSS)**  is a type of security vulnerability that can be found in some web applications. XSS attacks enable attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy..

## Why Secure Coding Matters

Security vulnerabilities in code are responsible for the majority of data breaches and cyber attacks. According to recent studies:

- **94% of applications** have at least one security vulnerability
- **76% of vulnerabilities** are introduced during the coding phase  
- **The average cost** of a data breach is $4.45 million

By implementing secure coding practices, developers can:
- **Reduce vulnerabilities** by up to 80%
- **Lower remediation costs** significantly
- **Improve code quality** and maintainability
- **Build customer trust** through secure applications

## Core Secure Coding Principles

### 1. Input Validation

**Always validate and sanitize input data:**

```python
import re
from html import escape

def validate_email(email):
    """Secure email validation"""
    if not email or len(email) > 254:
        return False
    
    # Use regex for basic format validation
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False
    
    return True

def sanitize_user_input(user_input):
    """Sanitize user input for display"""
    if not user_input:
        return ""
    
    # Remove potential XSS characters
    sanitized = escape(user_input)
    
    # Limit length
    sanitized = sanitized[:1000]
    
    return sanitized.strip()
```

### 2. Authentication and Authorization

**Implement robust authentication mechanisms:**

```python
import bcrypt
import jwt
from datetime import datetime, timedelta

class SecureAuth:
    def __init__(self, secret_key):
        self.secret_key = secret_key
    
    def hash_password(self, password):
        """Securely hash passwords"""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt)
    
    def verify_password(self, password, hashed):
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed)
    
    def generate_token(self, user_id, expires_in_hours=24):
        """Generate secure JWT token"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=expires_in_hours),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_token(self, token):
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload['user_id']
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
```

### 3. SQL Injection Prevention

**Use parameterized queries:**

```python
import sqlite3
from contextlib import contextmanager

class SecureDatabase:
    def __init__(self, db_path):
        self.db_path = db_path
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()
    
    def get_user_by_id(self, user_id):
        """Secure user lookup using parameterized query"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # SECURE: Using parameterized query
            cursor.execute(
                "SELECT id, username, email FROM users WHERE id = ?",
                (user_id,)
            )
            
            return cursor.fetchone()
    
    def search_users(self, search_term, limit=50):
        """Secure user search"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Validate and sanitize search term
            if not search_term or len(search_term) > 100:
                return []
            
            # Use parameterized query with LIKE
            cursor.execute(
                "SELECT id, username, email FROM users WHERE username LIKE ? LIMIT ?",
                (f"%{search_term}%", limit)
            )
            
            return cursor.fetchall()

# NEVER DO THIS (Vulnerable to SQL Injection):
# query = f"SELECT * FROM users WHERE id = {user_id}"
```

### 4. Cross-Site Scripting (XSS) Prevention

**Properly encode output:**

```javascript
// Client-side XSS prevention
class XSSProtection {
    
    static htmlEncode(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
    
    static sanitizeHTML(html) {
        // Use DOMParser for safe HTML parsing
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        
        // Remove dangerous elements
        const dangerousElements = doc.querySelectorAll('script, object, embed, iframe');
        dangerousElements.forEach(el => el.remove());
        
        // Remove dangerous attributes
        const allElements = doc.querySelectorAll('*');
        allElements.forEach(el => {
            const dangerousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover'];
            dangerousAttrs.forEach(attr => {
                if (el.hasAttribute(attr)) {
                    el.removeAttribute(attr);
                }
            });
        });
        
        return doc.body.innerHTML;
    }
    
    static displayUserContent(content, container) {
        // Always encode user content before display
        container.textContent = content; // This automatically encodes
        
        // Or for HTML content, sanitize first
        // container.innerHTML = this.sanitizeHTML(content);
    }
}

// Usage example
const userInput = "<script>alert('XSS')</script>Hello World";
const container = document.getElementById('user-content');
XSSProtection.displayUserContent(userInput, container);
```

### 5. Secure Session Management

**Implement secure session handling:**

```python
import secrets
import hashlib
from datetime import datetime, timedelta

class SecureSessionManager:
    def __init__(self, session_timeout_minutes=30):
        self.sessions = {}
        self.timeout = timedelta(minutes=session_timeout_minutes)
    
    def create_session(self, user_id):
        """Create a secure session"""
        # Generate cryptographically secure session ID
        session_id = secrets.token_urlsafe(32)
        
        # Create session data
        session_data = {
            'user_id': user_id,
            'created_at': datetime.utcnow(),
            'last_activity': datetime.utcnow(),
            'csrf_token': secrets.token_urlsafe(32)
        }
        
        self.sessions[session_id] = session_data
        return session_id, session_data['csrf_token']
    
    def validate_session(self, session_id, csrf_token=None):
        """Validate session and check timeout"""
        if not session_id or session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        # Check if session has expired
        if datetime.utcnow() - session['last_activity'] > self.timeout:
            del self.sessions[session_id]
            return None
        
        # Validate CSRF token if provided
        if csrf_token and session['csrf_token'] != csrf_token:
            return None
        
        # Update last activity
        session['last_activity'] = datetime.utcnow()
        
        return session
    
    def destroy_session(self, session_id):
        """Securely destroy session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
```

## Language-Specific Security Practices

### Python Security

```python
# Secure file handling
import os
from pathlib import Path

def secure_file_upload(filename, upload_dir):
    """Secure file upload handling"""
    # Validate filename
    if not filename or '..' in filename or '/' in filename:
        raise ValueError("Invalid filename")
    
    # Whitelist allowed extensions
    allowed_extensions = {'.txt', '.pdf', '.jpg', '.png', '.docx'}
    file_ext = Path(filename).suffix.lower()
    
    if file_ext not in allowed_extensions:
        raise ValueError("File type not allowed")
    
    # Generate safe filename
    safe_filename = secrets.token_hex(16) + file_ext
    safe_path = os.path.join(upload_dir, safe_filename)
    
    # Ensure path is within upload directory
    if not os.path.commonpath([upload_dir, safe_path]) == upload_dir:
        raise ValueError("Path traversal attempt detected")
    
    return safe_path

# Secure random number generation
import secrets

# SECURE: Use secrets module for cryptographic randomness
session_token = secrets.token_urlsafe(32)
password_reset_token = secrets.token_hex(20)

# INSECURE: Don't use random module for security
# import random
# weak_token = str(random.randint(1000, 9999))  # DON'T DO THIS
```

### JavaScript Security

```javascript
// Secure API communication
class SecureAPIClient {
    constructor(baseURL, apiKey) {
        this.baseURL = baseURL;
        this.apiKey = apiKey;
    }
    
    async makeRequest(endpoint, method = 'GET', data = null) {
        const url = new URL(endpoint, this.baseURL);
        
        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
            'X-Requested-With': 'XMLHttpRequest' // CSRF protection
        };
        
        const options = {
            method: method,
            headers: headers,
            credentials: 'same-origin' // Send cookies only to same origin
        };
        
        if (data && method !== 'GET') {
            options.body = JSON.stringify(data);
        }
        
        try {
            const response = await fetch(url.toString(), options);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }
}

// Content Security Policy helper
function setSecurityHeaders() {
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';";
    document.head.appendChild(meta);
}
```

## Security Testing Integration

### Automated Security Testing

```python
# Example: Integration with security testing tools
import subprocess
import json

class SecurityTestRunner:
    def __init__(self, project_path):
        self.project_path = project_path
    
    def run_bandit_scan(self):
        """Run Bandit security scanner for Python"""
        try:
            result = subprocess.run([
                'bandit', '-r', self.project_path, '-f', 'json'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                print(f"Bandit scan failed: {result.stderr}")
                return None
        except FileNotFoundError:
            print("Bandit not installed. Run: pip install bandit")
            return None
    
    def run_safety_check(self):
        """Check for known security vulnerabilities in dependencies"""
        try:
            result = subprocess.run([
                'safety', 'check', '--json'
            ], capture_output=True, text=True)
            
            return json.loads(result.stdout)
        except FileNotFoundError:
            print("Safety not installed. Run: pip install safety")
            return None
    
    def generate_security_report(self):
        """Generate comprehensive security report"""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'bandit_results': self.run_bandit_scan(),
            'dependency_vulnerabilities': self.run_safety_check()
        }
        
        with open('security_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
```

## Common Vulnerabilities and Fixes

### 1. Insecure Direct Object Reference

```python
# VULNERABLE CODE
@app.route('/user/<user_id>/profile')
def get_user_profile(user_id):
    user = User.query.get(user_id)
    return render_template('profile.html', user=user)

# SECURE CODE
@app.route('/user/<user_id>/profile')
@login_required
def get_user_profile(user_id):
    # Check if current user can access this profile
    if not current_user.can_access_user_profile(user_id):
        abort(403)
    
    user = User.query.get_or_404(user_id)
    return render_template('profile.html', user=user)
```

### 2. Missing Rate Limiting

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Login logic here
    pass
```

### 3. Insufficient Logging

```python
import logging
from datetime import datetime

# Configure security logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)

security_logger = logging.getLogger('security')

def log_security_event(event_type, user_id=None, ip_address=None, details=None):
    """Log security-related events"""
    log_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'ip_address': ip_address,
        'details': details
    }
    
    security_logger.info(f"SECURITY_EVENT: {json.dumps(log_data)}")

# Usage examples
log_security_event('failed_login', user_id=123, ip_address='192.168.1.1')
log_security_event('admin_access', user_id=456, details='accessed user management')
```

## Secure Development Lifecycle Integration

### Pre-commit Security Hooks

```bash
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: bandit
        name: bandit
        entry: bandit
        language: system
        args: ['-r', '.']
        files: \.py$
      
      - id: safety
        name: safety
        entry: safety
        language: system
        args: ['check']
        files: requirements.*\.txt$
      
      - id: semgrep
        name: semgrep
        entry: semgrep
        language: system
        args: ['--config=auto']
```

## Security Code Review Checklist

### General Checklist

- [ ] **Input Validation**: All user inputs validated and sanitized
- [ ] **Authentication**: Strong password policies and secure session management  
- [ ] **Authorization**: Proper access controls implemented
- [ ] **Data Protection**: Sensitive data encrypted at rest and in transit
- [ ] **Error Handling**: No sensitive information leaked in error messages
- [ ] **Logging**: Security events properly logged
- [ ] **Dependencies**: All dependencies up to date and vulnerability-free
- [ ] **Configuration**: Secure default configurations used

### Language-Specific Checks

**Python**:
- [ ] Using `secrets` module instead of `random` for security
- [ ] Parameterized queries for database operations
- [ ] Proper exception handling without information disclosure
- [ ] Virtual environment with pinned dependency versions

**JavaScript**:
- [ ] Content Security Policy (CSP) headers implemented
- [ ] DOM manipulation uses safe methods
- [ ] API calls include proper authentication headers
- [ ] No sensitive data stored in client-side storage

## Tools and Resources

### Static Analysis Tools

| Tool | Language | Key Features |
|------|----------|--------------|
| **Bandit** | Python | Security issue detection |
| **ESLint Security** | JavaScript | Security linting rules |
| **SonarQube** | Multiple | Code quality and security |
| **Semgrep** | Multiple | Custom security rules |

### Dependency Scanners

- **Safety** (Python): Check for known vulnerabilities
- **npm audit** (Node.js): Vulnerability scanning
- **OWASP Dependency Check**: Multi-language support

### Learning Resources

- **OWASP Secure Coding Practices**: Comprehensive guidelines
- **CWE (Common Weakness Enumeration)**: Vulnerability database
- **SANS Secure Coding**: Training and certification
- **Secure Code Warrior**: Interactive learning platform

## Conclusion

Secure coding is not a one-time effort but an ongoing practice that should be integrated into every stage of development. By following these principles and implementing the practices outlined in this guide, developers can significantly reduce security vulnerabilities and build more robust applications.

### Key Takeaways:

1. **Security by Design**: Consider security from the beginning of development
2. **Input Validation**: Never trust user input
3. **Defense in Depth**: Implement multiple layers of security
4. **Continuous Learning**: Stay updated with the latest security practices
5. **Tool Integration**: Use automated tools to catch issues early

### Next Steps:

1. Conduct a security review of your current codebase
2. Implement automated security testing in your CI/CD pipeline
3. Provide secure coding training for your development team
4. Establish security code review practices
5. Stay informed about emerging threats and vulnerabilities

Remember: **Secure coding is everyone's responsibility**. By making security a priority in your development process, you're not just protecting your applications – you're protecting your users and your organization.

---

*Want to dive deeper into specific secure coding topics? Check out my other posts on [penetration testing](/categories/pentest/) and [OWASP Top 10](/categories/web-security/). Have questions? Feel free to [reach out](/contact/)!*