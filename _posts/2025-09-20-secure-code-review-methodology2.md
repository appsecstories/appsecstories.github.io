---
layout: post
title: "Secure Code Review Methodology: Part 2"
date: 2025-09-09 10:08:00 +0000
categories: [secure-coding]
tags: [secure-coding]
author: Application Security Engineer
comments: true
excerpt: "Involves detailed analysis of data flow, attack surfaces, and security controls. This phase builds upon the reconnaissance findings to create a comprehensive understanding of how data moves through the application and where security vulnerabilities might exist"
---

## Phase 2: Mapping

The mapping phase involves detailed analysis of data flow, attack surfaces, and security controls. This phase builds upon the reconnaissance findings to create a comprehensive understanding of how data moves through the application and where security vulnerabilities might exist.

### 1. Identify Sources and Sinks

**Description:** Sources and sinks analysis is a fundamental security technique that maps all data entry points (sources) where untrusted data enters the application and all data processing points (sinks) where that data is used in potentially dangerous operations. This analysis forms the foundation for identifying data flow vulnerabilities such as injection attacks, cross-site scripting, and path traversal.

**Why This Matters:** Most security vulnerabilities occur when untrusted data from sources reaches dangerous sinks without proper validation or sanitization. By systematically mapping all sources and sinks, security reviewers can trace data flow paths and identify where security controls are missing or inadequate. This approach is essential for comprehensive vulnerability analysis.

**What to Look For:**
- User input sources: forms, URL parameters, headers, cookies
- File system sources: uploaded files, configuration files
- Network sources: API calls, database queries, external services
- Database sinks: SQL queries, NoSQL operations
- File system sinks: file writes, path operations
- Command execution sinks: system calls, script execution
- Output sinks: HTML rendering, log files, response headers

### 2. User Input and External Endpoint Analysis

**Description:** This analysis focuses specifically on how the application handles user-provided input and communication with external systems. It involves examining all mechanisms by which external data enters the application and understanding how that data is processed, validated, and used throughout the system.

**Why This Matters:** User input and external data are the primary attack vectors for most security vulnerabilities. Inadequate input validation leads to injection attacks, while improper handling of external responses can result in data corruption or system compromise. This analysis helps identify the most critical areas for security controls.

**What to Look For:**
- Form input validation and sanitization
- API parameter validation
- File upload restrictions and scanning
- Header and cookie processing
- JSON/XML parsing security
- URL parameter handling
- Authentication token processing

### 3. Route Identification and Mapping

**Description:** Route mapping involves cataloging all application endpoints, URLs, and entry points to create a comprehensive inventory of the application's attack surface. This includes web routes, API endpoints, WebSocket connections, and any other network-accessible interfaces.

**Why This Matters:** Each route represents a potential attack vector. Understanding all available routes helps security reviewers ensure comprehensive coverage during testing and identify routes that might be missing security controls. Hidden or forgotten routes often lack proper security implementations.

**What to Look For:**
- URL patterns and route definitions
- HTTP method restrictions
- Route parameters and wildcards
- Administrative and debug routes
- API version endpoints
- File serving routes
- WebSocket endpoints
- Redirect and proxy routes

### 4. Server-Side Functionality Mapping

**Description:** This step involves mapping routes to their corresponding server-side functions and analyzing how input parameters are processed within each function. It's essential to understand the complete flow from route reception to business logic execution.

**Why This Matters:** The connection between routes and server-side functions reveals how user input flows through the application. This mapping helps identify where input validation should occur, which functions handle sensitive operations, and where authorization checks are needed.

**What to Look For:**
- Function parameter mapping
- Input parameter usage within functions
- Data transformation and processing steps
- Database operations triggered by routes
- External service calls initiated by routes
- File system operations performed by routes

**Python Example:**
```python
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
```

### 5. HTTP Request Flow Analysis

**Description:** This analysis traces the complete journey of an HTTP request from initial reception through authentication, authorization, business logic processing, and response generation. Understanding this flow is crucial for identifying where security controls should be implemented and where they might be missing.

**Why This Matters:** Security vulnerabilities often occur at the boundaries between different processing stages. By understanding the complete request flow, security reviewers can identify gaps in security controls and ensure that security checks are applied at appropriate points in the processing pipeline.

**What to Look For:**
- Request preprocessing and filtering
- Authentication mechanisms and timing
- Authorization checks and enforcement points
- Input validation stages
- Business logic processing
- Database interaction points
- Response generation and output encoding

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

**Description:** Attack surface mapping involves identifying all possible entry points and attack vectors that could be used to compromise the application. This comprehensive analysis examines the application from an attacker's perspective to understand potential exploitation paths and trust boundaries.

**Why This Matters:** A complete understanding of the attack surface enables security teams to prioritize security controls and ensure comprehensive protection. Each component of the attack surface represents a potential vulnerability, and understanding the interconnections helps identify complex attack chains.

**What to Look For:**
- Network-accessible interfaces and protocols
- Authentication and session management interfaces
- File upload and processing capabilities
- Data input and output mechanisms
- Third-party service integrations
- Administrative interfaces
- Error handling and information disclosure points

### 7. Dependency Security Review

**Description:** This analysis extends beyond the application's core code to examine all third-party dependencies, libraries, and external components for security issues. It involves understanding how dependencies are used, what permissions they have, and how they might introduce vulnerabilities into the application.

**Why This Matters:** Modern applications rely heavily on third-party dependencies, which can introduce vulnerabilities that the development team has no direct control over. Supply chain attacks and vulnerable dependencies are increasingly common attack vectors. This analysis helps identify risks from external components.

**What to Look For:**
- Known vulnerabilities in dependency versions
- Dependency update and patch management
- Transitive dependency vulnerabilities
- Dependency permissions and access levels
- Usage patterns of dangerous dependency functions
- License compliance and legal implications
- Dependency integrity and authenticity

### 8. Dangerous Function Detection

**Description:** This analysis involves systematically searching for potentially dangerous functions that could be exploited if used with untrusted input. These functions typically provide powerful capabilities that, while legitimate, can be misused by attackers to execute arbitrary code, access files, or perform other malicious actions.

**Why This Matters:** Dangerous functions are often legitimate and necessary for application functionality, but they become security vulnerabilities when used with unsanitized user input. Identifying these functions helps security reviewers focus on areas where input validation is most critical.

**What to Look For:**
- Code execution functions (eval, exec, compile)
- System command functions (os.system, subprocess)
- Deserialization functions (pickle.loads, yaml.load)
- File system access functions (open, file operations)
- Dynamic loading functions (__import__, getattr)
- Template rendering with user input
- Database query construction with string concatenation

### 9. Hardcoded Secrets Detection

**Description:** This analysis involves systematically searching the codebase for hardcoded credentials, API keys, passwords, and other sensitive information that should not be stored in source code. This includes scanning comments, configuration files, and any location where secrets might accidentally be committed.

**Why This Matters:** Hardcoded secrets represent immediate security risks because they can be discovered by anyone with access to the source code, including through source code repositories, backups, or compromised systems. These secrets often provide direct access to critical systems and data.

**What to Look For:**
- Database connection strings with embedded credentials
- API keys and tokens in configuration files
- Passwords and secrets in environment variables
- Private keys and certificates in the codebase
- Third-party service credentials
- Encryption keys and salts
- Comments containing sensitive information

### 10. Weak Cryptography Detection

**Description:** This analysis focuses on identifying weak cryptographic implementations, outdated algorithms, and insecure cryptographic practices within the application. It involves reviewing all cryptographic operations including hashing, encryption, digital signatures, and random number generation.

**Why This Matters:** Cryptographic weaknesses can completely undermine application security, even if other security controls are properly implemented. Weak cryptography can lead to data breaches, authentication bypasses, and compromise of sensitive information. Modern applications must use current cryptographic standards and best practices.

**What to Look For:**
- Weak hashing algorithms (MD5, SHA1)
- Outdated encryption algorithms (DES, RC4)
- Insufficient key lengths
- Poor random number generation
- Insecure cryptographic modes (ECB)
- Missing authentication in encryption
- Improper key management
- Weak password hashing methods

<!--
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
```
-->

### 11. Sensitive Data in Comments

**Description:** This analysis involves examining all code comments, documentation, and inline notes for accidentally disclosed sensitive information. Developers often leave temporary credentials, debugging information, or other sensitive data in comments that can be discovered by attackers.

**Why This Matters:** Comments are often overlooked during security reviews but can contain valuable information for attackers. They may reveal system internals, temporary credentials, known vulnerabilities, or other information that aids in exploitation. This information remains in the codebase even after the original functionality is changed.

**What to Look For:**
- Temporary credentials and passwords in comments
- Database connection strings and API keys
- System architecture details and internal URLs
- Known security issues marked as TODO or FIXME
- Debugging information with sensitive data paths
- Personal information and contact details
- Business logic explanations that reveal vulnerabilities

### 12. Input Validation Centralization Check

**Description:** This analysis examines whether the application uses a centralized input validation approach or has scattered validation logic throughout the codebase. Centralized validation ensures consistent security controls and makes it easier to maintain and update validation rules.

**Why This Matters:** Scattered validation logic often leads to inconsistent security controls, with some inputs being properly validated while others are not. Centralized validation provides a single point of control for security rules, making it easier to ensure comprehensive coverage and maintain consistent security standards across the application.

**What to Look For:**
- Common validation functions and libraries
- Consistent validation rules across similar inputs
- Validation bypass opportunities in scattered implementations
- Input sanitization and encoding consistency
- Error handling consistency in validation
- Validation rule maintenance and updates
- Framework-provided validation mechanisms

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

