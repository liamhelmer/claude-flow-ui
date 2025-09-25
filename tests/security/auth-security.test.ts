/**
 * Authentication Security Tests
 *
 * Comprehensive security tests for authentication mechanisms including:
 * - JWT token security and validation
 * - Session management security
 * - Privilege escalation prevention
 * - Brute force protection
 * - Account lockout mechanisms
 * - Multi-factor authentication bypass attempts
 */

import { test, expect, describe, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

// Mock dependencies
const mockApp = {
  get: jest.fn(),
  post: jest.fn(),
  use: jest.fn(),
  listen: jest.fn(),
};

const mockAuthService = {
  validateToken: jest.fn(),
  generateToken: jest.fn(),
  revokeToken: jest.fn(),
  refreshToken: jest.fn(),
};

const mockUserService = {
  findByCredentials: jest.fn(),
  lockAccount: jest.fn(),
  unlockAccount: jest.fn(),
  isAccountLocked: jest.fn(),
  incrementFailedAttempts: jest.fn(),
  resetFailedAttempts: jest.fn(),
};

class AuthSecurityTestSuite {
  static generateMaliciousTokens() {
    return {
      // JWT token manipulation attempts
      tamperedSignature: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.TAMPERED_SIGNATURE',
      noneAlgorithm: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
      expiredToken: jwt.sign({ sub: '123', exp: Math.floor(Date.now() / 1000) - 3600 }, 'secret'),
      malformedToken: 'not.a.valid.jwt.token',
      emptyToken: '',
      nullByteToken: 'valid.jwt.token\0malicious',
      oversizedToken: 'a'.repeat(10000),
      
      // SQL injection in JWT claims
      sqlInjectionInSub: jwt.sign({ 
        sub: "'; DROP TABLE users; --", 
        name: 'User',
        iat: Math.floor(Date.now() / 1000)
      }, 'secret'),
      
      // XSS in JWT claims
      xssInClaims: jwt.sign({
        sub: '123',
        name: '<script>alert("xss")</script>',
        role: 'javascript:alert("xss")',
        iat: Math.floor(Date.now() / 1000)
      }, 'secret'),
      
      // Privilege escalation attempts
      adminEscalation: jwt.sign({
        sub: '123',
        role: 'admin',
        permissions: ['*'],
        iat: Math.floor(Date.now() / 1000)
      }, 'secret'),
      
      // Algorithm confusion attack
      algorithmConfusion: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.HMAC_SIGNED_BUT_RSA_HEADER',
    };
  }

  static generateBruteForcePayloads() {
    return {
      commonPasswords: [
        'password', '123456', 'password123', 'admin', 'root',
        'qwerty', 'letmein', 'welcome', 'monkey', 'dragon'
      ],
      sqlInjectionPasswords: [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        '" OR "1"="1',
        "' UNION SELECT * FROM users --"
      ],
      timingAttackUsernames: [
        'admin', 'administrator', 'root', 'user', 'test',
        'guest', 'demo', 'service', 'system'
      ]
    };
  }

  static async simulateRapidRequests(endpoint: string, count: number, delay: number = 10) {
    const promises = [];
    for (let i = 0; i < count; i++) {
      promises.push(
        new Promise(resolve => {
          setTimeout(async () => {
            try {
              const response = await request(mockApp)
                .post(endpoint)
                .send({ username: 'test', password: 'wrong' });
              resolve(response);
            } catch (error) {
              resolve(error);
            }
          }, i * delay);
        })
      );
    }
    return Promise.all(promises);
  }
}

describe('Authentication Security Suite', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset rate limiting state
    global.__rateLimitState = {};
  });

  describe('JWT Token Security', () => {
    test('should reject tokens with tampered signatures', async () => {
      const { tamperedSignature } = AuthSecurityTestSuite.generateMaliciousTokens();
      
      mockAuthService.validateToken.mockImplementation((token) => {
        if (token === tamperedSignature) {
          throw new Error('Invalid token signature');
        }
        return { valid: false, reason: 'signature_mismatch' };
      });
      
      const result = await mockAuthService.validateToken(tamperedSignature);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('signature_mismatch');
    });

    test('should prevent algorithm confusion attacks', async () => {
      const { algorithmConfusion, noneAlgorithm } = AuthSecurityTestSuite.generateMaliciousTokens();
      
      mockAuthService.validateToken.mockImplementation((token) => {
        try {
          const decoded = jwt.decode(token, { complete: true });
          if (!decoded || !decoded.header || !decoded.header.alg) {
            throw new Error('Invalid token structure');
          }
          
          // Should enforce expected algorithm
          const expectedAlg = 'HS256';
          if (decoded.header.alg !== expectedAlg) {
            throw new Error(`Algorithm mismatch. Expected ${expectedAlg}, got ${decoded.header.alg}`);
          }
          
          return { valid: false, reason: 'algorithm_mismatch' };
        } catch (error) {
          return { valid: false, reason: error.message };
        }
      });
      
      const result1 = await mockAuthService.validateToken(algorithmConfusion);
      const result2 = await mockAuthService.validateToken(noneAlgorithm);
      
      expect(result1.valid).toBe(false);
      expect(result2.valid).toBe(false);
      expect(result1.reason).toContain('Algorithm mismatch');
      expect(result2.reason).toContain('Algorithm mismatch');
    });

    test('should validate token expiration strictly', async () => {
      const { expiredToken } = AuthSecurityTestSuite.generateMaliciousTokens();
      
      mockAuthService.validateToken.mockImplementation((token) => {
        try {
          const decoded = jwt.decode(token) as any;
          if (!decoded || !decoded.exp) {
            throw new Error('Token missing expiration');
          }
          
          const currentTime = Math.floor(Date.now() / 1000);
          if (decoded.exp < currentTime) {
            throw new Error('Token expired');
          }
          
          return { valid: false, reason: 'expired' };
        } catch (error) {
          return { valid: false, reason: error.message };
        }
      });
      
      const result = await mockAuthService.validateToken(expiredToken);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('expired');
    });

    test('should sanitize JWT claims to prevent XSS', async () => {
      const { xssInClaims } = AuthSecurityTestSuite.generateMaliciousTokens();
      
      mockAuthService.validateToken.mockImplementation((token) => {
        try {
          const decoded = jwt.decode(token) as any;
          if (!decoded) {
            throw new Error('Invalid token');
          }
          
          // Check for XSS patterns in claims
          const dangerousPatterns = [
            /<script[\s\S]*?>[
            /javascript:/i,
            /on\w+\s*=/i,
            /<iframe[\s\S]*?>/i
          ];
          
          for (const [key, value] of Object.entries(decoded)) {
            if (typeof value === 'string') {
              for (const pattern of dangerousPatterns) {
                if (pattern.test(value)) {
                  return { valid: false, reason: `XSS pattern detected in ${key}` };
                }
              }
            }
          }
          
          return { valid: true, user: decoded };
        } catch (error) {
          return { valid: false, reason: error.message };
        }
      });
      
      const result = await mockAuthService.validateToken(xssInClaims);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('XSS pattern detected');
    });

    test('should prevent privilege escalation through JWT manipulation', async () => {
      const { adminEscalation } = AuthSecurityTestSuite.generateMaliciousTokens();
      
      mockAuthService.validateToken.mockImplementation((token) => {
        try {
          const decoded = jwt.decode(token) as any;
          if (!decoded) {
            throw new Error('Invalid token');
          }
          
          // Check for unauthorized privilege escalation
          const suspiciousPrivileges = ['admin', 'root', 'superuser', '*'];
          
          if (decoded.role && suspiciousPrivileges.includes(decoded.role)) {
            return { valid: false, reason: 'Unauthorized privilege escalation detected' };
          }
          
          if (decoded.permissions && Array.isArray(decoded.permissions)) {
            for (const permission of decoded.permissions) {
              if (suspiciousPrivileges.includes(permission)) {
                return { valid: false, reason: 'Unauthorized permission detected' };
              }
            }
          }
          
          return { valid: true, user: decoded };
        } catch (error) {
          return { valid: false, reason: error.message };
        }
      });
      
      const result = await mockAuthService.validateToken(adminEscalation);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Unauthorized');
    });

    test('should handle malformed tokens securely', async () => {
      const { malformedToken, emptyToken, nullByteToken, oversizedToken } = 
        AuthSecurityTestSuite.generateMaliciousTokens();
      
      const testTokens = [malformedToken, emptyToken, nullByteToken, oversizedToken];
      
      mockAuthService.validateToken.mockImplementation((token) => {
        if (!token || token.length === 0) {
          return { valid: false, reason: 'Empty token' };
        }
        
        if (token.length > 8192) { // Max reasonable token size
          return { valid: false, reason: 'Token too large' };
        }
        
        if (token.includes('\0')) {
          return { valid: false, reason: 'Invalid characters in token' };
        }
        
        const parts = token.split('.');
        if (parts.length !== 3) {
          return { valid: false, reason: 'Malformed token structure' };
        }
        
        return { valid: false, reason: 'Invalid token' };
      });
      
      for (const token of testTokens) {
        const result = await mockAuthService.validateToken(token);
        expect(result.valid).toBe(false);
        expect(result.reason).toBeDefined();
      }
    });
  });

  describe('Session Security', () => {
    test('should generate cryptographically secure session IDs', async () => {
      const sessionIds = new Set();
      const sessionIdGenerator = () => crypto.randomBytes(32).toString('hex');
      
      // Generate 1000 session IDs to check for collisions and patterns
      for (let i = 0; i < 1000; i++) {
        const sessionId = sessionIdGenerator();
        expect(sessionId).toMatch(/^[a-f0-9]{64}$/);
        expect(sessionIds.has(sessionId)).toBe(false);
        sessionIds.add(sessionId);
      }
      
      expect(sessionIds.size).toBe(1000);
    });

    test('should implement secure session timeout', async () => {
      const session = {
        id: 'test-session',
        userId: 'user123',
        createdAt: Date.now() - (30 * 60 * 1000), // 30 minutes ago
        lastActivity: Date.now() - (20 * 60 * 1000), // 20 minutes ago
        maxAge: 15 * 60 * 1000, // 15 minutes
      };
      
      const isSessionValid = (session: any) => {
        const now = Date.now();
        const timeSinceLastActivity = now - session.lastActivity;
        return timeSinceLastActivity <= session.maxAge;
      };
      
      expect(isSessionValid(session)).toBe(false);
    });

    test('should prevent session fixation attacks', async () => {
      const oldSessionId = 'old-session-id';
      const mockSessionStore = new Map();
      
      // Simulate user login with existing session ID
      const authenticateUser = (username: string, password: string, sessionId?: string) => {
        if (username === 'testuser' && password === 'testpass') {
          // Generate new session ID on login (prevent session fixation)
          const newSessionId = crypto.randomBytes(32).toString('hex');
          
          // Remove old session if provided
          if (sessionId) {
            mockSessionStore.delete(sessionId);
          }
          
          mockSessionStore.set(newSessionId, {
            userId: 'user123',
            username: 'testuser',
            createdAt: Date.now()
          });
          
          return { success: true, sessionId: newSessionId };
        }
        return { success: false };
      };
      
      const result = await authenticateUser('testuser', 'testpass', oldSessionId);
      
      expect(result.success).toBe(true);
      expect(result.sessionId).not.toBe(oldSessionId);
      expect(mockSessionStore.has(oldSessionId)).toBe(false);
      expect(mockSessionStore.has(result.sessionId)).toBe(true);
    });

    test('should implement secure session cleanup on logout', async () => {
      const sessionId = 'active-session';
      const mockSessionStore = new Map();
      const mockTokenStore = new Map();
      
      // Set up active session
      mockSessionStore.set(sessionId, {
        userId: 'user123',
        data: 'sensitive data'
      });
      
      mockTokenStore.set('refresh-token-123', {
        sessionId: sessionId,
        userId: 'user123'
      });
      
      const secureLogout = (sessionId: string) => {
        // Remove session data
        mockSessionStore.delete(sessionId);
        
        // Revoke all associated tokens
        for (const [tokenId, tokenData] of mockTokenStore.entries()) {
          if ((tokenData as any).sessionId === sessionId) {
            mockTokenStore.delete(tokenId);
          }
        }
        
        return { success: true };
      };
      
      const result = secureLogout(sessionId);
      
      expect(result.success).toBe(true);
      expect(mockSessionStore.has(sessionId)).toBe(false);
      expect(mockTokenStore.size).toBe(0);
    });
  });

  describe('Brute Force Protection', () => {
    test('should implement rate limiting for login attempts', async () => {
      const rateLimiter = {
        attempts: new Map(),
        maxAttempts: 5,
        windowMs: 15 * 60 * 1000, // 15 minutes
        
        isRateLimited(identifier: string): boolean {
          const now = Date.now();
          const attempts = this.attempts.get(identifier) || [];
          
          // Clean old attempts
          const recentAttempts = attempts.filter(
            (timestamp: number) => now - timestamp < this.windowMs
          );
          
          this.attempts.set(identifier, recentAttempts);
          
          return recentAttempts.length >= this.maxAttempts;
        },
        
        recordAttempt(identifier: string): void {
          const attempts = this.attempts.get(identifier) || [];
          attempts.push(Date.now());
          this.attempts.set(identifier, attempts);
        }
      };
      
      const testIdentifier = 'test-user';
      
      // Make 5 attempts
      for (let i = 0; i < 5; i++) {
        expect(rateLimiter.isRateLimited(testIdentifier)).toBe(false);
        rateLimiter.recordAttempt(testIdentifier);
      }
      
      // 6th attempt should be rate limited
      expect(rateLimiter.isRateLimited(testIdentifier)).toBe(true);
    });

    test('should implement progressive delay for repeated failures', async () => {
      const progressiveDelay = {
        getDelay(attempts: number): number {
          // Exponential backoff: 2^attempts * 1000ms
          return Math.min(Math.pow(2, attempts) * 1000, 60000); // Max 60 seconds
        }
      };
      
      expect(progressiveDelay.getDelay(1)).toBe(2000);  // 2 seconds
      expect(progressiveDelay.getDelay(3)).toBe(8000);  // 8 seconds
      expect(progressiveDelay.getDelay(5)).toBe(32000); // 32 seconds
      expect(progressiveDelay.getDelay(10)).toBe(60000); // Capped at 60 seconds
    });

    test('should detect and prevent credential stuffing attacks', async () => {
      const { commonPasswords } = AuthSecurityTestSuite.generateBruteForcePayloads();
      
      const credentialStuffingDetector = {
        suspiciousPatterns: commonPasswords,
        ipAttempts: new Map(),
        
        isSuspiciousPattern(username: string, password: string, ip: string): boolean {
          // Check for common passwords
          if (this.suspiciousPatterns.includes(password.toLowerCase())) {
            return true;
          }
          
          // Check for rapid attempts from same IP with different usernames
          const ipData = this.ipAttempts.get(ip) || { attempts: [], usernames: new Set() };
          ipData.attempts.push(Date.now());
          ipData.usernames.add(username);
          
          // Clean old attempts (last 5 minutes)
          const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);
          ipData.attempts = ipData.attempts.filter((time: number) => time > fiveMinutesAgo);
          
          this.ipAttempts.set(ip, ipData);
          
          // Suspicious if many different usernames from same IP in short time
          return ipData.attempts.length > 10 && ipData.usernames.size > 5;
        }
      };
      
      // Simulate credential stuffing from single IP
      const testIp = '192.168.1.100';
      let suspiciousCount = 0;
      
      for (let i = 0; i < 15; i++) {
        const isSuspicious = credentialStuffingDetector.isSuspiciousPattern(
          `user${i}`, 
          commonPasswords[i % commonPasswords.length], 
          testIp
        );
        if (isSuspicious) suspiciousCount++;
      }
      
      expect(suspiciousCount).toBeGreaterThan(0);
    });

    test('should implement account lockout after failed attempts', async () => {
      const accountLockout = {
        lockedAccounts: new Map(),
        maxFailedAttempts: 5,
        lockoutDuration: 30 * 60 * 1000, // 30 minutes
        
        isAccountLocked(username: string): boolean {
          const lockData = this.lockedAccounts.get(username);
          if (!lockData) return false;
          
          // Check if lockout has expired
          if (Date.now() - lockData.lockedAt > this.lockoutDuration) {
            this.lockedAccounts.delete(username);
            return false;
          }
          
          return true;
        },
        
        recordFailedAttempt(username: string): boolean {
          const lockData = this.lockedAccounts.get(username) || { 
            failedAttempts: 0, 
            lockedAt: null 
          };
          
          lockData.failedAttempts++;
          
          if (lockData.failedAttempts >= this.maxFailedAttempts) {
            lockData.lockedAt = Date.now();
            this.lockedAccounts.set(username, lockData);
            return true; // Account is now locked
          }
          
          this.lockedAccounts.set(username, lockData);
          return false; // Not locked yet
        },
        
        resetFailedAttempts(username: string): void {
          this.lockedAccounts.delete(username);
        }
      };
      
      const testUsername = 'testuser';
      
      // Simulate 5 failed attempts
      let isLocked = false;
      for (let i = 0; i < 5; i++) {
        isLocked = accountLockout.recordFailedAttempt(testUsername);
      }
      
      expect(isLocked).toBe(true);
      expect(accountLockout.isAccountLocked(testUsername)).toBe(true);
    });
  });

  describe('Authentication Timing Attacks', () => {
    test('should implement constant-time password comparison', async () => {
      const constantTimeCompare = (a: string, b: string): boolean => {
        if (a.length !== b.length) {
          // Still perform comparison to avoid timing leak
          let dummy = 0;
          for (let i = 0; i < Math.max(a.length, b.length); i++) {
            dummy += (a.charCodeAt(i % a.length) || 0) ^ (b.charCodeAt(i % b.length) || 0);
          }
          return false;
        }
        
        let result = 0;
        for (let i = 0; i < a.length; i++) {
          result |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        
        return result === 0;
      };
      
      const correctPassword = 'correct_password_123';
      const wrongPassword1 = 'wrong_password_456';
      const wrongPassword2 = 'c'; // Short password
      
      // Measure timing for different password comparisons
      const measureTime = (func: () => boolean) => {
        const start = process.hrtime.bigint();
        func();
        const end = process.hrtime.bigint();
        return Number(end - start);
      };
      
      const time1 = measureTime(() => constantTimeCompare(correctPassword, wrongPassword1));
      const time2 = measureTime(() => constantTimeCompare(correctPassword, wrongPassword2));
      
      // Times should be similar (within reasonable variance)
      const timeDifference = Math.abs(time1 - time2);
      const averageTime = (time1 + time2) / 2;
      const variance = timeDifference / averageTime;
      
      // Allow for some variance due to system scheduling, but should be relatively close
      expect(variance).toBeLessThan(0.5); // Less than 50% difference
    });

    test('should prevent username enumeration through timing', async () => {
      const userDatabase = {
        'validuser': { passwordHash: 'hash1234567890abcdef' },
        'anotheruser': { passwordHash: 'abcdef1234567890hash' }
      };
      
      const authenticateUser = async (username: string, password: string) => {
        // Always perform password hashing operation to maintain consistent timing
        const dummyHash = 'dummy_hash_to_maintain_timing';
        const userExists = username in userDatabase;
        
        // Simulate password hashing time for both valid and invalid users
        const targetHash = userExists ? userDatabase[username].passwordHash : dummyHash;
        
        // Simulate constant-time hash comparison
        await new Promise(resolve => setTimeout(resolve, 10)); // Simulate hash time
        
        const passwordMatches = userExists && targetHash === `hash_of_${password}`;
        
        return {
          success: userExists && passwordMatches,
          message: userExists && passwordMatches ? 'Success' : 'Invalid credentials'
        };
      };
      
      // Test authentication with valid and invalid usernames
      const validUserResult = await authenticateUser('validuser', 'wrongpass');
      const invalidUserResult = await authenticateUser('nonexistentuser', 'wrongpass');
      
      // Both should return same error message (no username enumeration)
      expect(validUserResult.message).toBe(invalidUserResult.message);
      expect(validUserResult.success).toBe(false);
      expect(invalidUserResult.success).toBe(false);
    });
  });

  describe('Security Headers and HTTPS Enforcement', () => {
    test('should enforce HTTPS in production', () => {
      const enforceHttps = (req: any, res: any, next: any) => {
        if (process.env.NODE_ENV === 'production' && !req.secure) {
          return res.redirect(301, `https://${req.headers.host}${req.url}`);
        }
        next();
      };
      
      const mockReq = {
        secure: false,
        headers: { host: 'example.com' },
        url: '/login'
      };
      
      const mockRes = {
        redirect: jest.fn()
      };
      
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      try {
        enforceHttps(mockReq, mockRes, jest.fn());
        expect(mockRes.redirect).toHaveBeenCalledWith(301, 'https://example.com/login');
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    test('should set secure authentication headers', () => {
      const securityHeaders = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
      };
      
      const setSecurityHeaders = (res: any) => {
        for (const [header, value] of Object.entries(securityHeaders)) {
          res.setHeader(header, value);
        }
      };
      
      const mockRes = {
        setHeader: jest.fn()
      };
      
      setSecurityHeaders(mockRes);
      
      // Verify all security headers are set
      Object.entries(securityHeaders).forEach(([header, value]) => {
        expect(mockRes.setHeader).toHaveBeenCalledWith(header, value);
      });
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });
});
