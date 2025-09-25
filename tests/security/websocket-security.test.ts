/**
 * WebSocket Security Tests
 *
 * Comprehensive security tests for WebSocket connections including:
 * - Connection authentication and authorization
 * - Message integrity validation
 * - Rate limiting and DoS protection
 * - Origin validation and CSRF prevention
 * - Message sanitization and validation
 * - Session hijacking prevention
 * - Protocol upgrade security
 * - Binary message security
 */

import { test, expect, describe, beforeEach, afterEach, jest } from '@jest/globals';
import WebSocket from 'ws';
import { EventEmitter } from 'events';
import crypto from 'crypto';

class MockWebSocketServer extends EventEmitter {
  private clients: Set<MockWebSocket> = new Set();
  private rateLimits: Map<string, number[]> = new Map();
  private authenticatedClients: Map<MockWebSocket, any> = new Map();
  
  constructor(private options: any = {}) {
    super();
  }
  
  simulateConnection(mockClient: MockWebSocket) {
    this.clients.add(mockClient);
    this.emit('connection', mockClient);
    
    mockClient.on('close', () => {
      this.clients.delete(mockClient);
      this.authenticatedClients.delete(mockClient);
    });
  }
  
  authenticateClient(client: MockWebSocket, userInfo: any) {
    this.authenticatedClients.set(client, userInfo);
  }
  
  isAuthenticated(client: MockWebSocket): boolean {
    return this.authenticatedClients.has(client);
  }
  
  getClientInfo(client: MockWebSocket): any {
    return this.authenticatedClients.get(client);
  }
  
  checkRateLimit(clientId: string, maxMessages: number = 100, windowMs: number = 60000): boolean {
    const now = Date.now();
    const messages = this.rateLimits.get(clientId) || [];
    
    // Clean old messages
    const recentMessages = messages.filter(time => now - time < windowMs);
    
    if (recentMessages.length >= maxMessages) {
      return false; // Rate limited
    }
    
    recentMessages.push(now);
    this.rateLimits.set(clientId, recentMessages);
    return true;
  }
  
  broadcast(message: any, excludeClient?: MockWebSocket) {
    for (const client of this.clients) {
      if (client !== excludeClient && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(message));
      }
    }
  }
  
  close() {
    for (const client of this.clients) {
      client.close();
    }
    this.clients.clear();
    this.authenticatedClients.clear();
  }
}

class MockWebSocket extends EventEmitter {
  public readyState: number = WebSocket.OPEN;
  public headers: { [key: string]: string } = {};
  public remoteAddress: string = '127.0.0.1';
  private messageQueue: any[] = [];
  
  constructor(public url: string = 'ws://localhost:8080', options: any = {}) {
    super();
    this.headers = options.headers || {};
    this.remoteAddress = options.remoteAddress || '127.0.0.1';
  }
  
  send(data: any) {
    if (this.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not open');
    }
    
    this.messageQueue.push(data);
    
    // Simulate async message handling
    setImmediate(() => {
      this.emit('message', data);
    });
  }
  
  close(code?: number, reason?: string) {
    this.readyState = WebSocket.CLOSED;
    this.emit('close', code, reason);
  }
  
  simulateMessage(data: any) {
    if (this.readyState === WebSocket.OPEN) {
      this.emit('message', data);
    }
  }
  
  getLastMessage(): any {
    return this.messageQueue[this.messageQueue.length - 1];
  }
  
  getAllMessages(): any[] {
    return [...this.messageQueue];
  }
  
  clearMessages() {
    this.messageQueue = [];
  }
}

class WebSocketSecurityTestSuite {
  static generateMaliciousMessages() {
    return {
      oversizedMessage: JSON.stringify({ data: 'A'.repeat(10 * 1024 * 1024) }), // 10MB
      malformedJson: '{"invalid": json}',
      binaryBomb: Buffer.alloc(100 * 1024 * 1024), // 100MB binary data
      
      xssPayload: {
        type: 'message',
        content: '<script>alert("XSS")</script>',
        user: 'javascript:alert("XSS")'
      },
      
      sqlInjection: {
        type: 'query',
        sql: "'; DROP TABLE messages; --",
        filter: "' OR '1'='1"
      },
      
      prototypePollution: {
        type: 'update',
        data: {
          '__proto__': { admin: true },
          'constructor': { 'prototype': { isAdmin: true } }
        }
      },
      
      commandInjection: {
        type: 'execute',
        command: '; rm -rf /',
        args: ['|', 'cat', '/etc/passwd']
      },
      
      ddosMessages: Array.from({ length: 1000 }, (_, i) => ({
        type: 'spam',
        id: i,
        timestamp: Date.now()
      })),
      
      maliciousHeaders: {
        'x-forwarded-for': '127.0.0.1, evil.com',
        'x-real-ip': '192.168.1.100\r\nX-Injected: malicious',
        'user-agent': 'Mozilla/5.0 <script>alert("xss")</script>'
      },
      
      sessionHijacking: {
        type: 'auth',
        token: 'stolen-session-token-12345',
        sessionId: '../../../admin-session'
      }
    };
  }
  
  static createSecureWebSocketHandler() {
    return {
      validateOrigin: (origin: string): boolean => {
        const allowedOrigins = [
          'http://localhost:3000',
          'https://trusted-domain.com',
          'https://app.example.com'
        ];
        return allowedOrigins.includes(origin);
      },
      
      validateMessage: (message: any): { valid: boolean; reason?: string; sanitized?: any } => {
        try {
          // Size limit check
          const messageStr = JSON.stringify(message);
          if (messageStr.length > 1024 * 1024) { // 1MB limit
            return { valid: false, reason: 'Message too large' };
          }
          
          // Required fields check
          if (!message.type || typeof message.type !== 'string') {
            return { valid: false, reason: 'Invalid message type' };
          }
          
          // XSS prevention
          const sanitized = JSON.parse(JSON.stringify(message));
          for (const [key, value] of Object.entries(sanitized)) {
            if (typeof value === 'string') {
              // Basic XSS detection
              if (/<script[^>]*>.*?<\/script>/gi.test(value) ||
                  /javascript:/i.test(value) ||
                  /on\w+\s*=/i.test(value)) {
                return { valid: false, reason: 'XSS content detected' };
              }
              
              // HTML encode dangerous characters
              sanitized[key] = value
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#x27;');
            }
          }
          
          // Prototype pollution prevention
          if (message.__proto__ || message.constructor || message.prototype) {
            return { valid: false, reason: 'Prototype pollution attempt detected' };
          }
          
          // Command injection detection
          const dangerousPatterns = [
            /[;&|`$(){}\[\]]/,
            /\b(rm|del|format|kill)\b/i,
            /\$\(.*\)/,
            /`.*`/
          ];
          
          const messageText = JSON.stringify(message);
          for (const pattern of dangerousPatterns) {
            if (pattern.test(messageText)) {
              return { valid: false, reason: 'Command injection pattern detected' };
            }
          }
          
          return { valid: true, sanitized };
        } catch (error) {
          return { valid: false, reason: 'Message parsing error' };
        }
      },
      
      generateMessageId: (): string => {
        return crypto.randomBytes(16).toString('hex');
      },
      
      validateToken: (token: string): { valid: boolean; payload?: any } => {
        // Mock JWT validation
        if (!token || typeof token !== 'string') {
          return { valid: false };
        }
        
        if (token === 'valid-token') {
          return {
            valid: true,
            payload: {
              userId: 'user123',
              role: 'user',
              exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
            }
          };
        }
        
        if (token === 'expired-token') {
          return { valid: false };
        }
        
        return { valid: false };
      },
      
      encryptMessage: (message: any, key: string): string => {
        // Mock encryption
        const cipher = crypto.createCipher('aes192', key);
        let encrypted = cipher.update(JSON.stringify(message), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
      },
      
      decryptMessage: (encryptedMessage: string, key: string): any => {
        // Mock decryption
        try {
          const decipher = crypto.createDecipher('aes192', key);
          let decrypted = decipher.update(encryptedMessage, 'hex', 'utf8');
          decrypted += decipher.final('utf8');
          return JSON.parse(decrypted);
        } catch (error) {
          throw new Error('Decryption failed');
        }
      }
    };
  }
}

describe('WebSocket Security Test Suite', () => {
  let mockServer: MockWebSocketServer;
  let securityHandler: any;
  
  beforeEach(() => {
    mockServer = new MockWebSocketServer();
    securityHandler = WebSocketSecurityTestSuite.createSecureWebSocketHandler();
    jest.clearAllMocks();
  });
  
  afterEach(() => {
    mockServer.close();
  });
  
  describe('Connection Security', () => {
    test('should validate origin headers during handshake', () => {
      const validOrigins = [
        'http://localhost:3000',
        'https://trusted-domain.com'
      ];
      
      const invalidOrigins = [
        'http://evil.com',
        'https://malicious-site.org',
        'null',
        ''
      ];
      
      validOrigins.forEach(origin => {
        expect(securityHandler.validateOrigin(origin)).toBe(true);
      });
      
      invalidOrigins.forEach(origin => {
        expect(securityHandler.validateOrigin(origin)).toBe(false);
      });
    });
    
    test('should enforce authentication before allowing connections', () => {
      const mockClient = new MockWebSocket();
      mockServer.simulateConnection(mockClient);
      
      // Client should not be authenticated initially
      expect(mockServer.isAuthenticated(mockClient)).toBe(false);
      
      // Simulate authentication
      const authMessage = {
        type: 'auth',
        token: 'valid-token'
      };
      
      const tokenValidation = securityHandler.validateToken(authMessage.token);
      
      if (tokenValidation.valid) {
        mockServer.authenticateClient(mockClient, tokenValidation.payload);
      }
      
      expect(mockServer.isAuthenticated(mockClient)).toBe(true);
    });
    
    test('should prevent connection from blocked IPs', () => {
      const blockedIPs = ['192.168.1.100', '10.0.0.50'];
      
      const validateIP = (ip: string): boolean => {
        return !blockedIPs.includes(ip);
      };
      
      const mockClient1 = new MockWebSocket('ws://localhost:8080', { remoteAddress: '127.0.0.1' });
      const mockClient2 = new MockWebSocket('ws://localhost:8080', { remoteAddress: '192.168.1.100' });
      
      expect(validateIP(mockClient1.remoteAddress)).toBe(true);
      expect(validateIP(mockClient2.remoteAddress)).toBe(false);
    });
    
    test('should enforce secure WebSocket connections in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      try {
        const enforceSecureConnection = (url: string): boolean => {
          if (process.env.NODE_ENV === 'production') {
            return url.startsWith('wss://');
          }
          return true; // Allow ws:// in development
        };
        
        expect(enforceSecureConnection('ws://localhost:8080')).toBe(false);
        expect(enforceSecureConnection('wss://localhost:8080')).toBe(true);
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });
  });
  
  describe('Message Security', () => {
    test('should validate and sanitize incoming messages', () => {
      const {
        xssPayload,
        sqlInjection,
        prototypePollution,
        commandInjection
      } = WebSocketSecurityTestSuite.generateMaliciousMessages();
      
      const maliciousMessages = [
        xssPayload,
        sqlInjection,
        prototypePollution,
        commandInjection
      ];
      
      maliciousMessages.forEach(message => {
        const validation = securityHandler.validateMessage(message);
        expect(validation.valid).toBe(false);
        expect(validation.reason).toBeDefined();
      });
    });
    
    test('should enforce message size limits', () => {
      const { oversizedMessage } = WebSocketSecurityTestSuite.generateMaliciousMessages();
      
      const validation = securityHandler.validateMessage(
        JSON.parse(oversizedMessage)
      );
      
      expect(validation.valid).toBe(false);
      expect(validation.reason).toContain('too large');
    });
    
    test('should handle malformed JSON gracefully', () => {
      const mockClient = new MockWebSocket();
      mockServer.simulateConnection(mockClient);
      
      const handleMessage = (rawMessage: string) => {
        try {
          const message = JSON.parse(rawMessage);
          return securityHandler.validateMessage(message);
        } catch (error) {
          return { valid: false, reason: 'Invalid JSON' };
        }
      };
      
      const { malformedJson } = WebSocketSecurityTestSuite.generateMaliciousMessages();
      const result = handleMessage(malformedJson);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Invalid JSON');
    });
    
    test('should implement message integrity checks', () => {
      const message = {
        type: 'chat',
        content: 'Hello, world!',
        timestamp: Date.now()
      };
      
      // Generate message with checksum
      const messageWithChecksum = {
        ...message,
        checksum: crypto
          .createHash('sha256')
          .update(JSON.stringify(message))
          .digest('hex')
      };
      
      // Validate checksum
      const validateChecksum = (msg: any): boolean => {
        if (!msg.checksum) return false;
        
        const { checksum, ...messageData } = msg;
        const calculatedChecksum = crypto
          .createHash('sha256')
          .update(JSON.stringify(messageData))
          .digest('hex');
        
        return checksum === calculatedChecksum;
      };
      
      expect(validateChecksum(messageWithChecksum)).toBe(true);
      
      // Tamper with message
      messageWithChecksum.content = 'Tampered content';
      expect(validateChecksum(messageWithChecksum)).toBe(false);
    });
  });
  
  describe('Rate Limiting and DoS Protection', () => {
    test('should implement per-client rate limiting', () => {
      const clientId = 'client-123';
      const maxMessages = 10;
      const windowMs = 1000;
      
      // Send messages up to limit
      for (let i = 0; i < maxMessages; i++) {
        expect(mockServer.checkRateLimit(clientId, maxMessages, windowMs)).toBe(true);
      }
      
      // Next message should be rate limited
      expect(mockServer.checkRateLimit(clientId, maxMessages, windowMs)).toBe(false);
    });
    
    test('should prevent message flooding attacks', async () => {
      const mockClient = new MockWebSocket();
      mockServer.simulateConnection(mockClient);
      
      const { ddosMessages } = WebSocketSecurityTestSuite.generateMaliciousMessages();
      let blockedMessages = 0;
      
      const handleFlood = (messages: any[]) => {
        const clientId = 'flood-test-client';
        const maxMessages = 50;
        let allowedMessages = 0;
        
        for (const message of messages) {
          if (mockServer.checkRateLimit(clientId, maxMessages, 60000)) {
            allowedMessages++;
          } else {
            blockedMessages++;
          }
        }
        
        return allowedMessages;
      };
      
      const allowedCount = handleFlood(ddosMessages);
      
      expect(allowedCount).toBeLessThan(ddosMessages.length);
      expect(blockedMessages).toBeGreaterThan(0);
    });
    
    test('should handle binary message size limits', () => {
      const { binaryBomb } = WebSocketSecurityTestSuite.generateMaliciousMessages();
      
      const validateBinaryMessage = (data: Buffer, maxSize: number = 10 * 1024 * 1024): boolean => {
        return data.length <= maxSize;
      };
      
      expect(validateBinaryMessage(binaryBomb)).toBe(false);
      
      const smallBinary = Buffer.alloc(1024);
      expect(validateBinaryMessage(smallBinary)).toBe(true);
    });
  });
  
  describe('Session Security', () => {
    test('should prevent session hijacking', () => {
      const mockClient1 = new MockWebSocket('ws://localhost:8080', { remoteAddress: '192.168.1.1' });
      const mockClient2 = new MockWebSocket('ws://localhost:8080', { remoteAddress: '192.168.1.2' });
      
      mockServer.simulateConnection(mockClient1);
      mockServer.simulateConnection(mockClient2);
      
      // Authenticate client1
      mockServer.authenticateClient(mockClient1, {
        userId: 'user123',
        sessionId: 'session-456',
        ip: '192.168.1.1'
      });
      
      const validateSession = (client: MockWebSocket, sessionId: string): boolean => {
        const clientInfo = mockServer.getClientInfo(client);
        
        if (!clientInfo) return false;
        
        // Check if session belongs to this client
        if (clientInfo.sessionId !== sessionId) return false;
        
        // Check if IP matches (prevent session hijacking)
        if (clientInfo.ip !== client.remoteAddress) return false;
        
        return true;
      };
      
      // Client1 should be able to access its session
      expect(validateSession(mockClient1, 'session-456')).toBe(true);
      
      // Client2 should not be able to access client1's session
      expect(validateSession(mockClient2, 'session-456')).toBe(false);
    });
    
    test('should implement session timeout', () => {
      const mockClient = new MockWebSocket();
      mockServer.simulateConnection(mockClient);
      
      const sessionData = {
        userId: 'user123',
        createdAt: Date.now() - (2 * 60 * 60 * 1000), // 2 hours ago
        lastActivity: Date.now() - (30 * 60 * 1000), // 30 minutes ago
        maxInactivity: 15 * 60 * 1000 // 15 minutes
      };
      
      mockServer.authenticateClient(mockClient, sessionData);
      
      const isSessionValid = (client: MockWebSocket): boolean => {
        const clientInfo = mockServer.getClientInfo(client);
        
        if (!clientInfo) return false;
        
        const now = Date.now();
        const timeSinceLastActivity = now - clientInfo.lastActivity;
        
        return timeSinceLastActivity <= clientInfo.maxInactivity;
      };
      
      // Session should be expired
      expect(isSessionValid(mockClient)).toBe(false);
    });
  });
  
  describe('Message Encryption', () => {
    test('should encrypt sensitive messages', () => {
      const sensitiveMessage = {
        type: 'private',
        content: 'Confidential information',
        recipient: 'user456'
      };
      
      const encryptionKey = 'secret-key-12345';
      
      const encrypted = securityHandler.encryptMessage(sensitiveMessage, encryptionKey);
      expect(encrypted).not.toContain('Confidential information');
      
      const decrypted = securityHandler.decryptMessage(encrypted, encryptionKey);
      expect(decrypted).toEqual(sensitiveMessage);
    });
    
    test('should handle encryption failures gracefully', () => {
      const message = { type: 'test', content: 'test' };
      const wrongKey = 'wrong-key';
      
      const encrypted = securityHandler.encryptMessage(message, 'correct-key');
      
      expect(() => {
        securityHandler.decryptMessage(encrypted, wrongKey);
      }).toThrow('Decryption failed');
    });
  });
  
  describe('Protocol Security', () => {
    test('should validate WebSocket subprotocols', () => {
      const allowedProtocols = ['chat', 'terminal', 'api-v1'];
      
      const validateProtocol = (protocol: string): boolean => {
        return allowedProtocols.includes(protocol);
      };
      
      expect(validateProtocol('chat')).toBe(true);
      expect(validateProtocol('malicious-protocol')).toBe(false);
      expect(validateProtocol('')).toBe(false);
    });
    
    test('should handle protocol upgrade attacks', () => {
      const mockRequest = {
        headers: {
          'connection': 'Upgrade',
          'upgrade': 'websocket',
          'sec-websocket-key': 'x3JJHMbDL1EzLkh9GBhXDw==',
          'sec-websocket-version': '13'
        }
      };
      
      const validateUpgrade = (headers: any): boolean => {
        // Check required headers
        if (headers.connection?.toLowerCase() !== 'upgrade') return false;
        if (headers.upgrade?.toLowerCase() !== 'websocket') return false;
        if (!headers['sec-websocket-key']) return false;
        if (headers['sec-websocket-version'] !== '13') return false;
        
        return true;
      };
      
      expect(validateUpgrade(mockRequest.headers)).toBe(true);
      
      // Test with malicious headers
      const maliciousRequest = {
        headers: {
          'connection': 'upgrade\r\nX-Injected: malicious',
          'upgrade': 'websocket',
          'sec-websocket-key': 'x3JJHMbDL1EzLkh9GBhXDw==',
          'sec-websocket-version': '13'
        }
      };
      
      expect(validateUpgrade(maliciousRequest.headers)).toBe(false);
    });
  });
  
  describe('Error Handling Security', () => {
    test('should not expose sensitive information in error messages', () => {
      const mockClient = new MockWebSocket();
      mockServer.simulateConnection(mockClient);
      
      const handleError = (error: Error): any => {
        // Sanitize error messages
        const safeMessage = error.message
          .replace(/password/gi, '[REDACTED]')
          .replace(/token/gi, '[REDACTED]')
          .replace(/secret/gi, '[REDACTED]')
          .replace(/key/gi, '[REDACTED]')
          .replace(/\b\d{4,}\b/g, '[REDACTED]'); // Remove long numbers
        
        return {
          error: 'An error occurred',
          message: safeMessage,
          timestamp: new Date().toISOString()
        };
      };
      
      const sensitiveError = new Error('Database connection failed with password: secret123');
      const sanitizedError = handleError(sensitiveError);
      
      expect(sanitizedError.message).not.toContain('secret123');
      expect(sanitizedError.message).toContain('[REDACTED]');
    });
    
    test('should log security events without sensitive data', () => {
      const securityLogger = jest.fn();
      
      const logSecurityEvent = (event: string, data: any, client: MockWebSocket) => {
        const sanitizedData = {
          eventType: event,
          clientIP: client.remoteAddress,
          timestamp: new Date().toISOString(),
          // Remove sensitive fields
          ...Object.fromEntries(
            Object.entries(data).filter(([key]) => 
              !['password', 'token', 'secret', 'key'].includes(key.toLowerCase())
            )
          )
        };
        
        securityLogger(sanitizedData);
      };
      
      const mockClient = new MockWebSocket();
      const eventData = {
        username: 'testuser',
        password: 'secret123',
        action: 'login_attempt'
      };
      
      logSecurityEvent('authentication_failure', eventData, mockClient);
      
      expect(securityLogger).toHaveBeenCalledWith(
        expect.not.objectContaining({
          password: 'secret123'
        })
      );
      
      expect(securityLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          username: 'testuser',
          action: 'login_attempt'
        })
      );
    });
  });
});
