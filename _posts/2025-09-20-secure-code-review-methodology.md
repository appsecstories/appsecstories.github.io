---
layout: post
title: "Comprehensive Secure Code Review Methodology: A Practical Guide"
date: 2025-09-20 10:00:00 +0000
categories: [secure-coding]
tags: [secure-coding, python]
author: Application Security Engineer
comments: true
excerpt: "Secure code review methodology provides a systematic approach to conducting thorough security assessments of source code, focusing on identifying potential attack vectors and security weaknesses."
---

**Comprehensive Secure Code Review Methodology: A Practical Guide**
Secure code review is a critical security practice that helps identify vulnerabilities before they reach production. This methodology provides a systematic approach to conducting thorough security assessments of source code, focusing on identifying potential attack vectors and security weaknesses.

## Introduction

Code review is one of the most effective methods for identifying security vulnerabilities early in the development lifecycle. Unlike automated scanning tools that may miss context-specific issues, manual secure code review allows security professionals to understand the application's logic, data flow, and potential attack surfaces comprehensively.

This guide presents a structured methodology divided into three main phases: **Reconnaissance**, **Mapping**, and **Vulnerability Focus Areas**. Each phase builds upon the previous one, creating a comprehensive security assessment framework.

## Phase 1: Reconnaissance

The reconnaissance phase involves gathering essential information about the application to understand its architecture, functionality, and potential attack surface.

### 1. High-Level Overview of Application Functionality

Understanding how the application works at a conceptual level is crucial for effective security review.

**What to Look For:**
- Application's primary purpose and business logic
- Overall architecture (monolithic, microservices, etc.)
- Integration points with external systems
- Data flow patterns

**Python Example:**
```python
# Example: E-commerce application overview
class ECommerceApp:
    """
    High-level application structure
    - User management and authentication
    - Product catalog and inventory
    - Shopping cart and checkout
    - Payment processing integration
    - Order management and fulfillment
    """
    def __init__(self):
        self.user_service = UserService()
        self.product_service = ProductService()
        self.cart_service = CartService()
        self.payment_service = PaymentService()
        self.order_service = OrderService()
```

### 2. Important Functionalities in Application

Identify critical business functions that require special security attention.

**Key Areas to Document:**
- Authentication and authorization mechanisms
- Data processing and storage functions
- Financial transactions or sensitive operations
- File upload/download capabilities
- Administrative functions

**Python Example:**
```python
# Critical functionalities that need security focus
class CriticalFunctions:
    def authenticate_user(self, username, password):
        # CRITICAL: Authentication logic
        pass
    
    def process_payment(self, amount, card_details):
        # CRITICAL: Financial transaction
        pass
    
    def upload_file(self, file_data, user_id):
        # CRITICAL: File handling
        pass
    
    def admin_user_management(self, action, user_data):
        # CRITICAL: Administrative function
        pass
```

### 3. User Types and Roles

Map out different user categories and their privilege levels.

**Analysis Points:**
- Guest users vs. authenticated users
- Regular users vs. administrative users
- Service accounts and system users
- Role-based permissions and access controls

**Python Example:**
```python
from enum import Enum

class UserRole(Enum):
    GUEST = "guest"
    USER = "user"
    PREMIUM_USER = "premium_user"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"

class User:
    def __init__(self, username, role):
        self.username = username
        self.role = role
        self.permissions = self._get_permissions(role)
    
    def _get_permissions(self, role):
        # Security Review Point: Ensure proper role-based access control
        permission_map = {
            UserRole.GUEST: ['read_public'],
            UserRole.USER: ['read_public', 'create_content', 'edit_own'],
            UserRole.ADMIN: ['read_all', 'write_all', 'delete_all']
        }
        return permission_map.get(role, [])
```

### 4. Major Frameworks and Libraries

Document all frameworks, libraries, and dependencies used in the application.

**Security Implications:**
- Known vulnerabilities in specific versions
- Security features provided by frameworks
- Configuration requirements for secure usage

**Python Example:**
```python
# requirements.txt analysis
"""
Django==3.2.13          # Web framework - check for security updates
requests==2.27.1        # HTTP library - verify SSL/TLS handling
SQLAlchemy==1.4.32     # ORM - check for SQL injection protections
cryptography==36.0.2   # Crypto library - ensure proper usage
Pillow==9.1.0          # Image processing - check for known CVEs
"""

# Security review checklist for frameworks
def review_django_security():
    # Check Django security settings
    security_settings = [
        'DEBUG = False',  # Must be False in production
        'ALLOWED_HOSTS configured',
        'SECRET_KEY properly managed',
        'SECURE_SSL_REDIRECT = True',
        'CSRF_COOKIE_SECURE = True',
        'SESSION_COOKIE_SECURE = True'
    ]
    return security_settings
```

### 5. Add-ons and Plugins

Catalog third-party add-ons, plugins, and extensions.

**Security Considerations:**
- Third-party code may introduce vulnerabilities
- Plugin permissions and access levels
- Update and patch management for add-ons

**Python Example:**
```python
# Third-party integrations security review
class ThirdPartyIntegrations:
    def __init__(self):
        self.payment_gateway = "stripe"  # Review: API security
        self.social_auth = "oauth2"      # Review: Token handling
        self.analytics = "google_analytics"  # Review: Data privacy
        self.cdn = "cloudflare"          # Review: Content security
    
    def review_integration_security(self, integration):
        # Security checklist for each integration
        checklist = {
            'api_authentication': False,
            'data_encryption': False,
            'input_validation': False,
            'rate_limiting': False,
            'secure_communication': False
        }
        return checklist
```

### 6. Common Vulnerabilities Assessment

Identify potential vulnerability categories based on the application type and technology stack.

**OWASP Top 10 Mapping:**
```python
class VulnerabilityCategories:
    def __init__(self, app_type):
        self.app_type = app_type
        self.common_vulns = self._get_common_vulnerabilities()
    
    def _get_common_vulnerabilities(self):
        # Map common vulnerabilities based on application type
        if self.app_type == "web_application":
            return [
                "Injection (SQL, NoSQL, LDAP)",
                "Broken Authentication",
                "Sensitive Data Exposure",
                "XML External Entities (XXE)",
                "Broken Access Control",
                "Security Misconfiguration",
                "Cross-Site Scripting (XSS)",
                "Insecure Deserialization",
                "Using Components with Known Vulnerabilities",
                "Insufficient Logging & Monitoring"
            ]
        # Add other application types as needed
```

### 7. Programming Language and Versions

Document programming languages and their versions for vulnerability research.

**Python Example:**
```python
import sys
import platform

def get_environment_info():
    """
    Collect environment information for security assessment
    """
    env_info = {
        'python_version': sys.version,
        'platform': platform.platform(),
        'architecture': platform.architecture(),
        'libraries': []  # Populated from requirements analysis
    }
    
    # Security Review Point: Check for outdated Python versions
    # Python < 3.8 may have security vulnerabilities
    if sys.version_info < (3, 8):
        print("WARNING: Python version may have security vulnerabilities")
    
    return env_info
```

### 8. Externally Facing Code (Priority Review)

Identify code that handles external inputs and prioritize its review.

**High Priority Areas:**
```python
class ExternallyFacingCode:
    """
    Code that processes external inputs - highest priority for security review
    """
    
    def handle_http_request(self, request):
        # PRIORITY 1: All HTTP request handlers
        user_input = request.POST.get('data')
        # Security Review: Input validation, sanitization
        return self.process_user_input(user_input)
    
    def api_endpoint(self, request):
        # PRIORITY 1: API endpoints
        data = request.json
        # Security Review: Authentication, authorization, input validation
        return self.process_api_data(data)
    
    def file_upload_handler(self, uploaded_file):
        # PRIORITY 1: File upload functionality
        # Security Review: File type validation, size limits, malware scanning
        return self.save_file(uploaded_file)
    
    def database_query(self, user_input):
        # PRIORITY 1: Database interactions with user input
        # Security Review: SQL injection prevention
        query = f"SELECT * FROM users WHERE id = {user_input}"  # VULNERABLE
        # Secure version:
        # query = "SELECT * FROM users WHERE id = %s"
        # cursor.execute(query, (user_input,))
```

### 9. Debug Code Analysis

Check for debug code that might be accidentally left in production.

**Python Example:**
```python
import os

class DebugCodeReview:
    def __init__(self):
        self.debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    def check_debug_issues(self):
        issues = []
        
        # Check for debug prints
        if self.debug_mode:
            print("DEBUG: User credentials:", username, password)  # SECURITY ISSUE
            issues.append("Debug prints may expose sensitive data")
        
        # Check for debug endpoints
        if hasattr(self, 'debug_endpoint'):
            issues.append("Debug endpoints should not exist in production")
        
        # Check for detailed error messages
        try:
            # Some operation
            pass
        except Exception as e:
            if self.debug_mode:
                return str(e)  # SECURITY ISSUE: May expose system info
            else:
                return "An error occurred"  # Secure: Generic error message
        
        return issues
```

### 10. Application Type Classification

Determine the specific type of application for targeted security review.

**Python Example:**
```python
class ApplicationTypeAnalysis:
    def __init__(self, app_characteristics):
        self.app_type = self._classify_application(app_characteristics)
        self.security_focus = self._get_security_focus()
    
    def _classify_application(self, characteristics):
        if 'web_interface' in characteristics:
            return 'web_application'
        elif 'mobile_api' in characteristics:
            return 'mobile_backend'
        elif 'desktop_client' in characteristics:
            return 'thick_client'
        elif 'binary_executable' in characteristics:
            return 'binary_application'
    
    def _get_security_focus(self):
        focus_areas = {
            'web_application': [
                'Input validation',
                'Output encoding',
                'Session management',
                'CSRF protection',
                'XSS prevention'
            ],
            'mobile_backend': [
                'API security',
                'Authentication tokens',
                'Rate limiting',
                'Data encryption'
            ]
        }
        return focus_areas.get(self.app_type, [])
```

## Phase 2: Mapping

The mapping phase involves detailed analysis of data flow, attack surfaces, and security controls.

### 1. Identify Sources and Sinks

Map all data entry points (sources) and processing points (sinks) in the application.

**Python Example:**
```python
class SourceSinkMapping:
    def __init__(self):
        self.sources = []  # Data entry points
        self.sinks = []    # Data processing points
    
    def map_sources(self):
        """
        Identify all potential sources of user input
        """
        sources = [
            'HTTP request parameters',
            'HTTP headers',
            'Request body (JSON/XML)',
            'File uploads',
            'Database queries',
            'External API responses',
            'Configuration files',
            'Environment variables'
        ]
        return sources
    
    def map_sinks(self):
        """
        Identify all data processing endpoints
        """
        sinks = [
            'Database queries',
            'File system operations',
            'External API calls',
            'System commands',
            'Template rendering',
            'Log entries',
            'Response output'
        ]
        return sinks
    
    def analyze_dataflow(self, source, sink):
        """
        Trace data flow from source to sink
        """
        dataflow = {
            'source': source,
            'transformations': [],
            'validations': [],
            'sink': sink,
            'vulnerabilities': []
        }
        return dataflow
```

### 2. User Input and External Endpoint Analysis

Focus specifically on user inputs and external communication points.

**Python Example:**
```python
def analyze_user_inputs():
    """
    Comprehensive analysis of user input handling
    """
    
    # Example: Form input handling
    def handle_form_input(request):
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Security Review Points:
        # 1. Input validation
        if not username or len(username) < 3:
            return "Invalid username"
        
        # 2. Input sanitization
        import re
        if not re.match("^[a-zA-Z0-9_]+$", username):
            return "Invalid characters in username"
        
        # 3. Output encoding (when displaying)
        import html
        safe_username = html.escape(username)
        
        return safe_username
    
    # Example: API endpoint analysis
    def api_endpoint(request):
        # Security Review: Authentication check
        if not request.headers.get('Authorization'):
            return {'error': 'Unauthorized'}, 401
        
        # Security Review: Input validation
        data = request.json
        if not isinstance(data, dict):
            return {'error': 'Invalid data format'}, 400
        
        return {'status': 'success'}
```

### 3. Route Identification and Mapping

Map all application routes and endpoints for comprehensive coverage.

**Python Example:**
```python
# Django URL patterns analysis
from django.urls import path

urlpatterns = [
    path('api/users/<int:user_id>/', user_detail_view),        # Review: Authorization
    path('api/admin/users/', admin_users_view),                # Review: Admin access
    path('upload/', file_upload_view),                         # Review: File validation
    path('search/', search_view),                              # Review: Injection attacks
    path('profile/update/', profile_update_view),              # Review: CSRF protection
]

class RouteSecurityAnalysis:
    def __init__(self, routes):
        self.routes = routes
        self.security_analysis = {}
    
    def analyze_route_security(self, route):
        analysis = {
            'authentication_required': False,
            'authorization_checks': False,
            'input_validation': False,
            'csrf_protection': False,
            'rate_limiting': False,
            'audit_logging': False
        }
        
        # Analyze each route for security controls
        if 'admin' in route.pattern.regex.pattern:
            analysis['authentication_required'] = True
            analysis['authorization_checks'] = True
        
        if route.pattern.regex.pattern.endswith('/$'):
            analysis['csrf_protection'] = True  # POST endpoints need CSRF
        
        return analysis
```

### 4. Server-Side Functionality Mapping

Map routes to their corresponding server-side functions and analyze input handling.

**Python Example:**
```python
class ServerSideFunctionMapping:
    def map_route_to_function(self):
        route_function_map = {
            '/api/users/': {
                'function': 'get_user_list',
                'inputs': ['page', 'limit', 'search'],
                'method': 'GET',
                'authentication': True,
                'authorization': 'user_read'
            },
            '/api/users/create/': {
                'function': 'create_user',
                'inputs': ['username', 'email', 'password', 'role'],
                'method': 'POST',
                'authentication': True,
                'authorization': 'user_create'
            }
        }
        return route_function_map
    
    def analyze_function_inputs(self, function_name, inputs):
        """
        Analyze each input parameter for security implications
        """
        input_analysis = {}
        
        for input_param in inputs:
            input_analysis[input_param] = {
                'data_type': 'unknown',
                'validation_required': True,
                'sanitization_required': True,
                'source': 'user_input',
                'sink_usage': []  # Where this input is used
            }
        
        return input_analysis
```

### 5. HTTP Request Flow Analysis

Trace the complete flow from HTTP request to response.

**Python Example:**
```python
class HTTPFlowAnalysis:
    def trace_request_flow(self):
        """
        Complete HTTP request processing flow
        """
        flow_steps = [
            {
                'step': 'Request Reception',
                'security_checks': ['Rate limiting', 'IP filtering', 'Request size limits'],
                'code_example': '''
                # Middleware: Rate limiting
                from django_ratelimit.decorators import ratelimit
                
                @ratelimit(key='ip', rate='100/h', method='POST')
                def my_view(request):
                    pass
                '''
            },
            {
                'step': 'Authentication',
                'security_checks': ['Token validation', 'Session verification', 'Multi-factor auth'],
                'code_example': '''
                # Authentication middleware
                def authenticate_user(request):
                    token = request.headers.get('Authorization')
                    if not token:
                        raise AuthenticationError("No token provided")
                    
                    # Validate token
                    user = validate_token(token)
                    request.user = user
                '''
            },
            {
                'step': 'Authorization',
                'security_checks': ['Permission verification', 'Role-based access', 'Resource ownership'],
                'code_example': '''
                # Authorization check
                def check_permissions(user, resource, action):
                    if not user.has_permission(resource, action):
                        raise PermissionError("Insufficient permissions")
                '''
            },
            {
                'step': 'Input Processing',
                'security_checks': ['Input validation', 'Data sanitization', 'Type checking'],
                'code_example': '''
                # Input validation
                def validate_input(data):
                    if not isinstance(data, dict):
                        raise ValueError("Invalid data format")
                    
                    required_fields = ['name', 'email']
                    for field in required_fields:
                        if field not in data:
                            raise ValueError(f"Missing required field: {field}")
                '''
            }
        ]
        return flow_steps
```

### 6. Attack Surface Mapping

Understand interoperation within the flow and map the complete attack surface.

**Python Example:**
```python
class AttackSurfaceMapping:
    def __init__(self):
        self.attack_vectors = []
        self.entry_points = []
        self.trust_boundaries = []
    
    def map_attack_surface(self):
        attack_surface = {
            'network_layer': [
                'HTTP/HTTPS endpoints',
                'WebSocket connections',
                'API endpoints',
                'File upload endpoints'
            ],
            'application_layer': [
                'Authentication mechanisms',
                'Session management',
                'Input validation points',
                'Output encoding points'
            ],
            'data_layer': [
                'Database connections',
                'File system access',
                'External service calls',
                'Cache systems'
            ]
        }
        return attack_surface
    
    def identify_trust_boundaries(self):
        """
        Map trust boundaries where security controls should be implemented
        """
        boundaries = [
            {
                'name': 'Internet to Web Server',
                'controls': ['WAF', 'Rate limiting', 'Input validation']
            },
            {
                'name': 'Web Server to Application',
                'controls': ['Authentication', 'Authorization', 'Session management']
            },
            {
                'name': 'Application to Database',
                'controls': ['SQL injection prevention', 'Connection security']
            }
        ]
        return boundaries
```

### 7. Dependency Security Review

Review dependencies and look for security issues extending the concept of sinks.

**Python Example:**
```python
import pkg_resources
import requests

class DependencySecurityReview:
    def __init__(self):
        self.installed_packages = list(pkg_resources.working_set)
        self.vulnerability_databases = [
            'https://pypi.org/pypi/{package}/json',
            'https://api.osv.dev/v1/query'
        ]
    
    def check_known_vulnerabilities(self, package_name, version):
        """
        Check if package version has known vulnerabilities
        """
        # Example check against OSV database
        query = {
            "package": {
                "name": package_name,
                "ecosystem": "PyPI"
            },
            "version": version
        }
        
        try:
            response = requests.post('https://api.osv.dev/v1/query', json=query)
            if response.json().get('vulns'):
                return True, response.json()['vulns']
        except:
            pass
        
        return False, []
    
    def analyze_dependency_usage(self, package_name):
        """
        Analyze how dependencies are used in the codebase
        """
        usage_patterns = {
            'requests': [
                'Check SSL certificate validation',
                'Verify timeout configurations',
                'Review proxy handling'
            ],
            'sqlite3': [
                'Check for SQL injection prevention',
                'Verify parameterized queries'
            ],
            'pickle': [
                'Identify deserialization points',
                'Check for untrusted data sources'
            ]
        }
        return usage_patterns.get(package_name, [])
```

### 8. Dangerous Function Detection

Search for dangerous functions used on user-supplied input.

**Python Example:**
```python
class DangerousFunctionDetection:
    def __init__(self):
        self.dangerous_functions = {
            'code_execution': [
                'eval', 'exec', 'compile', '__import__',
                'getattr', 'setattr', 'delattr'
            ],
            'system_commands': [
                'os.system', 'os.popen', 'subprocess.call',
                'subprocess.run', 'subprocess.Popen'
            ],
            'deserialization': [
                'pickle.loads', 'pickle.load', 'yaml.load',
                'json.loads'  # Less dangerous but context matters
            ],
            'file_operations': [
                'open', 'file', '__file__', '__builtins__'
            ]
        }
    
    def detect_dangerous_usage(self, user_input):
        """
        Examples of dangerous function usage with user input
        """
        
        # DANGEROUS: Direct code execution
        def dangerous_eval(user_code):
            result = eval(user_code)  # NEVER DO THIS
            return result
        
        # DANGEROUS: System command execution
        def dangerous_system_call(filename):
            import os
            os.system(f"cat {filename}")  # VULNERABLE TO INJECTION
        
        # DANGEROUS: Deserialization
        def dangerous_deserialization(user_data):
            import pickle
            obj = pickle.loads(user_data)  # DANGEROUS WITH UNTRUSTED DATA
            return obj
        
        # SECURE ALTERNATIVES:
        def secure_alternatives():
            # Use ast.literal_eval instead of eval for safe evaluation
            import ast
            def safe_eval(expression):
                try:
                    return ast.literal_eval(expression)
                except (ValueError, SyntaxError):
                    return None
            
            # Use subprocess with shell=False and input validation
            import subprocess
            def safe_system_call(filename):
                # Validate filename first
                if not filename.isalnum():
                    raise ValueError("Invalid filename")
                
                result = subprocess.run(
                    ['cat', filename], 
                    capture_output=True, 
                    text=True,
                    shell=False  # Important: prevents shell injection
                )
                return result.stdout
```

### 9. Hardcoded Secrets Detection

Search for hardcoded credentials and secrets in the codebase.

**Python Example:**
```python
import re

class HardcodedSecretsDetection:
    def __init__(self):
        self.secret_patterns = {
            'api_keys': [
                r'api[_-]?key["\'\s]*[=:]["\'\s]*[a-zA-Z0-9]{20,}',
                r'secret[_-]?key["\'\s]*[=:]["\'\s]*[a-zA-Z0-9]{20,}'
            ],
            'passwords': [
                r'password["\'\s]*[=:]["\'\s]*[^\s\'"]{8,}',
                r'passwd["\'\s]*[=:]["\'\s]*[^\s\'"]{8,}'
            ],
            'tokens': [
                r'token["\'\s]*[=:]["\'\s]*[a-zA-Z0-9]{20,}',
                r'bearer["\'\s]*[=:]["\'\s]*[a-zA-Z0-9]{20,}'
            ],
            'database_urls': [
                r'postgresql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+',
                r'mysql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+'
            ]
        }
    
    def scan_for_secrets(self, code_content):
        """
        Scan code content for hardcoded secrets
        """
        findings = []
        
        for secret_type, patterns in self.secret_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code_content, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'type': secret_type,
                        'pattern': pattern,
                        'match': match.group(),
                        'line': code_content[:match.start()].count('\n') + 1
                    })
        
        return findings
    
    def examples_of_bad_practices(self):
        """
        Examples of hardcoded secrets (NEVER DO THIS)
        """
        
        # BAD EXAMPLES:
        DATABASE_URL = "postgresql://user:password123@localhost:5432/mydb"
        API_KEY = "sk_live_51234567890abcdef"
        SECRET_KEY = "my-super-secret-key-12345"
        
        # GOOD PRACTICES:
        import os
        
        # Use environment variables
        DATABASE_URL = os.environ.get('DATABASE_URL')
        API_KEY = os.environ.get('STRIPE_API_KEY')
        SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
        
        # Use configuration management
        from django.conf import settings
        api_key = settings.API_KEY  # Loaded from secure config
```

### 10. Weak Cryptography Detection

Search for weak cryptographic implementations or hashing algorithms.

**Python Example:**
```python
import hashlib
import hmac
from cryptography.fernet import Fernet

class WeakCryptographyDetection:
    def __init__(self):
        self.weak_algorithms = {
            'hashing': ['md5', 'sha1'],
            'encryption': ['des', 'rc4', 'aes_ecb'],
            'key_sizes': {
                'rsa': 1024,  # Minimum should be 2048
                'aes': 128    # 256 is preferred
            }
        }
    
    def examples_of_weak_crypto(self):
        """
        Examples of weak cryptographic practices
        """
        
        # WEAK: MD5 hashing
        def weak_password_hash(password):
            return hashlib.md5(password.encode()).hexdigest()  # WEAK
        
        # WEAK: SHA1 hashing
        def weak_signature(data):
            return hashlib.sha1(data.encode()).hexdigest()  # WEAK
        
        # WEAK: Simple XOR encryption
        def weak_encryption(data, key):
            return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
        
        # STRONG ALTERNATIVES:
        def strong_password_hash(password):
            # Use bcrypt, scrypt, or Argon2 for password hashing
            import bcrypt
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password.encode(), salt)
        
        def strong_signature(data, secret_key):
            # Use HMAC with SHA-256 or better
            return hmac.new(
                secret_key.encode(),
                data.encode(),
                hashlib.sha256
            ).hexdigest()
        
        def strong_encryption(data):
            # Use Fernet (AES 128 in CBC mode with HMAC)
            key = Fernet.generate_key()
            f = Fernet(key)
            encrypted = f.encrypt(data.encode())
            return key, encrypted
        
        def strong_aes_encryption(data, key):
            # Use AES-256-GCM for authenticated encryption
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            aesgcm = AESGCM(key)  # key should be 32 bytes for AES-256
            nonce = os.urandom(12)  # 96-bit nonce for GCM
            ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
            return nonce + ciphertext
```

### 11. Sensitive Data in Comments

Look for sensitive information accidentally left in developer comments.

**Python Example:**
```python
import re

class SensitiveDataInComments:
    def __init__(self):
        self.sensitive_patterns = [
            r'#.*password.*[=:]\s*[\w@#$%^&*]+',
            r'#.*api[_-]?key.*[=:]\s*[\w-]+',
            r'#.*secret.*[=:]\s*[\w-]+',
            r'#.*token.*[=:]\s*[\w-]+',
            r'#.*TODO.*FIXME.*HACK',  # May contain security notes
            r'#.*username.*[=:]\s*\w+',
            r'#.*email.*[=:]\s*[\w@.]+',
            r'/\*.*password.*\*/',  # Multi-line comments
            r'//.*password.*'       # Single line comments in other languages
        ]
    
    def scan_comments_for_sensitive_data(self, code_content):
        """
        Scan code comments for sensitive information
        """
        findings = []
        
        for pattern in self.sensitive_patterns:
            matches = re.finditer(pattern, code_content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                findings.append({
                    'match': match.group(),
                    'line': code_content[:match.start()].count('\n') + 1,
                    'concern': 'Potential sensitive data in comments'
                })
        
        return findings
    
    def examples_of_bad_comments(self):
        """
        Examples of comments that expose sensitive information
        """
        
        # BAD EXAMPLES (NEVER DO THIS):
        
        # password = "admin123"  # Default admin password
        # api_key = "sk_test_123456789"  # Stripe test key
        # TODO: Remove hardcoded secret key before production
        # FIXME: SQL injection vulnerability in user_search function
        # HACK: Temporarily disabled authentication for testing
        
        """
        Database connection string:
        mysql://root:password@localhost:3306/production_db
        """
        
        # BETTER PRACTICES:
        
        # Use environment variable for database password
        # API key loaded from secure configuration
        # TODO: Implement proper input validation (reference ticket #1234)
        # FIXME: Refactor authentication module (security review pending)
        
        pass
```

### 12. Input Validation Centralization Check

Check if the codebase uses centralized input validation or scattered validation logic.

**Python Example:**
```python
class InputValidationAnalysis:
    def __init__(self):
        self.validation_patterns = []
        self.centralized_validation = False
    
    def analyze_validation_architecture(self):
        """
        Analyze whether input validation is centralized or scattered
        """
        
        # GOOD: Centralized validation
        class CentralizedValidator:
            @staticmethod
            def validate_email(email):
                import re
                pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                return re.match(pattern, email) is not None
            
            @staticmethod
            def validate_username(username):
                if not isinstance(username, str):
                    return False
                if len(username) < 3 or len(username) > 50:
                    return False
                if not re.match(r'^[a-zA-Z0-9_]+$', username):
                    return False
                return True
            
            @staticmethod
            def validate_password(password):
                if not isinstance(password, str):
                    return False
                if len(password) < 8:
                    return False
                # Check for complexity requirements
                has_upper = any(c.isupper() for c in password)
                has_lower = any(c.islower() for c in password)
                has_digit = any(c.isdigit() for c in password)
                has_special = any(c in "!@#$%^&*()_+-=" for c in password)
                return all([has_upper, has_lower, has_digit, has_special])
        
        # GOOD: Using centralized validation
        def register_user(request):
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            
            # Centralized validation
            if not CentralizedValidator.validate_username(username):
                return {'error': 'Invalid username'}
            if not CentralizedValidator.validate_email(email):
                return {'error': 'Invalid email'}
            if not CentralizedValidator.validate_password(password):
                return {'error': 'Invalid password'}
            
            # Proceed with registration
            return {'status': 'success'}
        
        # BAD: Scattered validation
        def scattered_validation_example():
            # Different validation logic in different places
            def view1(request):
                username = request.POST.get('username')
                if len(username) < 5:  # Different rule here
                    return "Invalid"
            
            def view2(request):
                username = request.POST.get('username')
                if not username.isalnum():  # Different rule here
                    return "Invalid"
            
            # This leads to inconsistent security controls
```

## Phase 3: Most Critical Security Issues to Focus On

This section covers the most important vulnerability categories to prioritize during code review.

### 1. Lack of Input Validation (Injection Attacks)

Input validation failures can lead to various injection attacks including SQL injection, command injection, and code injection.

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

Output encoding prevents Cross-Site Scripting (XSS) attacks by properly encoding data before rendering.

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

Access control vulnerabilities allow users to access resources or perform actions they shouldn't be authorized for.

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

Improperly designed regular expressions can lead to ReDoS (Regular expression Denial of Service) attacks or bypass security controls.

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

Using weak cryptographic algorithms or implementing cryptography incorrectly can compromise data security.

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

Certain functions are inherently dangerous and should be avoided or used with extreme caution.

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

Poor error handling can lead to information disclosure and security vulnerabilities.

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

Security misconfigurations are common vulnerabilities that occur when security settings are not properly implemented.

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

Hardcoded secrets in source code pose significant security risks.

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

Proper security logging is crucial for detecting attacks and maintaining audit trails.

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

This comprehensive secure code review methodology provides a structured approach to identifying and mitigating security vulnerabilities in Python applications. The three-phase approach—Reconnaissance, Mapping, and Vulnerability Focus—ensures thorough coverage of potential security issues.

### Key Takeaways

1. **Systematic Approach**: Following a structured methodology ensures consistent and comprehensive security reviews.

2. **Context Matters**: Understanding the application's architecture, users, and data flow is crucial for effective security assessment.

3. **Focus on High-Risk Areas**: Prioritizing externally facing code, user input handling, and authentication/authorization mechanisms provides the best return on security investment.

4. **Defense in Depth**: Implementing multiple layers of security controls (input validation, output encoding, access control, etc.) provides robust protection.

5. **Secure by Design**: Many vulnerabilities can be prevented by following secure coding practices from the beginning of the development process.

### Implementation Recommendations

- **Automate Where Possible**: Use static analysis tools to identify obvious issues, but complement with manual review for business logic flaws.
- **Regular Reviews**: Conduct security reviews regularly, not just before major releases.
- **Developer Training**: Educate development teams on secure coding practices to prevent vulnerabilities at the source.
- **Documentation**: Maintain detailed documentation of security controls and review findings.
- **Continuous Improvement**: Update the methodology based on new attack vectors and lessons learned.

By following this methodology and implementing the security controls demonstrated in the code examples, organizations can significantly improve their application security posture and reduce the risk of successful attacks.

Remember that security is an ongoing process, not a one-time activity. Regular security reviews, combined with other security practices like threat modeling, penetration testing, and security monitoring, form a comprehensive application security program.