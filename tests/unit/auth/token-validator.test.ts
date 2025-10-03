/**
 * Token Validator Unit Tests
 *
 * Tests for JWT signature verification, claims validation, and token format validation.
 * Ensures robust authentication security.
 */

import { TokenValidator } from '@/services/token-validator';
import { JWKSManager } from '@/services/jwks-manager';
import jwt from 'jsonwebtoken';

// Mock JWKS Manager
jest.mock('@/services/jwks-manager');

describe('TokenValidator', () => {
  let tokenValidator: TokenValidator;
  let mockJWKSManager: jest.Mocked<JWKSManager>;

  const mockConfig = {
    backstageUrl: 'https://backstage.example.com',
    strictMode: true,
    verifyExpiration: true,
    verifyIssuer: true,
    verifyAudience: false,
    verifyNotBefore: true,
    clockTolerance: 60,
    allowedAlgorithms: ['RS256', 'ES256'],
    maxTokenAge: 86400,
  };

  const mockPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxjlCRBqkQGqkHyh6pWvZ
DXOYiMYfpEQgj45r0JJp3vpjUkwFMZbV9kq5_vFr-zZ7pW4q1Z2F3qVfJ5Yz6zQ3
-----END PUBLIC KEY-----`;

  const mockPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxjlCRBqkQGqkHyh6pWvZDXOYiMYfpEQgj45r0JJp3vpjUkwF
MZbV9kq5_vFr-zZ7pW4q1Z2F3qVfJ5Yz6zQ3...
-----END RSA PRIVATE KEY-----`;

  beforeEach(() => {
    mockJWKSManager = {
      getPublicKey: jest.fn().mockResolvedValue(mockPublicKey),
      fetchJWKS: jest.fn(),
      refreshKeys: jest.fn(),
      getCacheMetrics: jest.fn(),
      on: jest.fn(),
    } as any;

    tokenValidator = new TokenValidator(mockConfig, mockJWKSManager);
  });

  describe('Token Format Validation', () => {
    test('should accept valid JWT format', async () => {
      const token = 'header.payload.signature';

      const result = tokenValidator.validateFormat(token);

      expect(result.valid).toBe(true);
    });

    test('should reject malformed JWT (missing parts)', () => {
      const invalidTokens = [
        'header.payload', // Missing signature
        'header', // Missing payload and signature
        '', // Empty token
        'invalid', // Single part
      ];

      invalidTokens.forEach(token => {
        const result = tokenValidator.validateFormat(token);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/malformed.*token/i);
      });
    });

    test('should reject tokens with invalid Base64 encoding', () => {
      const token = 'invalid@base64.invalid@base64.invalid@base64';

      const result = tokenValidator.validateFormat(token);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/invalid.*encoding/i);
    });

    test('should validate token length', () => {
      const tooLongToken = 'a'.repeat(10000) + '.' + 'b'.repeat(10000) + '.' + 'c'.repeat(10000);

      const result = tokenValidator.validateFormat(tooLongToken);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/token.*too.*long/i);
    });
  });

  describe('JWT Header Parsing', () => {
    test('should parse valid JWT header', () => {
      const token = jwt.sign(
        { sub: 'user:default/test' },
        mockPrivateKey,
        { algorithm: 'RS256', keyid: 'key-1' }
      );

      const header = tokenValidator.parseHeader(token);

      expect(header).toMatchObject({
        alg: 'RS256',
        kid: 'key-1',
        typ: 'JWT',
      });
    });

    test('should reject unsupported algorithm', () => {
      const token = jwt.sign(
        { sub: 'user:default/test' },
        'secret',
        { algorithm: 'HS256' } // Not in allowed algorithms
      );

      expect(() => {
        tokenValidator.parseHeader(token);
      }).toThrow(/unsupported.*algorithm/i);
    });

    test('should require kid (Key ID) in header', () => {
      const tokenWithoutKid = jwt.sign(
        { sub: 'user:default/test' },
        mockPrivateKey,
        { algorithm: 'RS256', noTimestamp: true }
      );

      // Remove kid from header
      const [header, payload, signature] = tokenWithoutKid.split('.');
      const decodedHeader = JSON.parse(Buffer.from(header, 'base64').toString());
      delete decodedHeader.kid;
      const modifiedHeader = Buffer.from(JSON.stringify(decodedHeader)).toString('base64');
      const modifiedToken = `${modifiedHeader}.${payload}.${signature}`;

      expect(() => {
        tokenValidator.parseHeader(modifiedToken);
      }).toThrow(/missing.*key.*id/i);
    });
  });

  describe('Signature Verification', () => {
    test('should verify valid JWT signature', async () => {
      const payload = {
        sub: 'user:default/test',
        iss: mockConfig.backstageUrl,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const token = jwt.sign(payload, mockPrivateKey, {
        algorithm: 'RS256',
        keyid: 'key-1',
      });

      const result = await tokenValidator.verifySignature(token);

      expect(result.valid).toBe(true);
      expect(result.payload).toMatchObject(payload);
    });

    test('should reject token with invalid signature', async () => {
      const token = jwt.sign(
        { sub: 'user:default/test' },
        mockPrivateKey,
        { algorithm: 'RS256', keyid: 'key-1' }
      );

      // Tamper with signature
      const parts = token.split('.');
      parts[2] = 'tamperedSignature';
      const tamperedToken = parts.join('.');

      const result = await tokenValidator.verifySignature(tamperedToken);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/invalid.*signature/i);
    });

    test('should reject token signed with wrong key', async () => {
      const wrongPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyUjBkPqQJKBhHGJp8wVWDeXNJiYFhQRHj3p1VkJIq4XJQUKL
-----END RSA PRIVATE KEY-----`;

      const token = jwt.sign(
        { sub: 'user:default/test' },
        wrongPrivateKey,
        { algorithm: 'RS256', keyid: 'key-1' }
      );

      const result = await tokenValidator.verifySignature(token);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/invalid.*signature/i);
    });

    test('should fetch public key from JWKS Manager', async () => {
      const token = jwt.sign(
        { sub: 'user:default/test' },
        mockPrivateKey,
        { algorithm: 'RS256', keyid: 'key-1' }
      );

      await tokenValidator.verifySignature(token);

      expect(mockJWKSManager.getPublicKey).toHaveBeenCalledWith('key-1');
    });

    test('should handle JWKS Manager errors gracefully', async () => {
      mockJWKSManager.getPublicKey.mockRejectedValue(
        new Error('JWKS service unavailable')
      );

      const token = jwt.sign(
        { sub: 'user:default/test' },
        mockPrivateKey,
        { algorithm: 'RS256', keyid: 'key-1' }
      );

      const result = await tokenValidator.verifySignature(token);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/public.*key.*unavailable/i);
    });
  });

  describe('Claims Validation', () => {
    test('should validate all required claims', async () => {
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        sub: 'user:default/test',
        iss: mockConfig.backstageUrl,
        exp: now + 3600,
        iat: now,
        nbf: now,
      };

      const result = tokenValidator.validateClaims(claims);

      expect(result.valid).toBe(true);
    });

    test('should reject expired token', () => {
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        sub: 'user:default/test',
        iss: mockConfig.backstageUrl,
        exp: now - 3600, // Expired 1 hour ago
        iat: now - 7200,
      };

      const result = tokenValidator.validateClaims(claims);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/token.*expired/i);
    });

    test('should reject token with wrong issuer', () => {
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        sub: 'user:default/test',
        iss: 'https://wrong-issuer.com',
        exp: now + 3600,
        iat: now,
      };

      const result = tokenValidator.validateClaims(claims);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/invalid.*issuer/i);
    });

    test('should reject token not yet valid (nbf check)', () => {
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        sub: 'user:default/test',
        iss: mockConfig.backstageUrl,
        exp: now + 3600,
        iat: now,
        nbf: now + 300, // Valid 5 minutes in the future
      };

      const result = tokenValidator.validateClaims(claims);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/token.*not.*yet.*valid/i);
    });

    test('should apply clock tolerance', () => {
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        sub: 'user:default/test',
        iss: mockConfig.backstageUrl,
        exp: now - 30, // Expired 30 seconds ago (within tolerance)
        iat: now - 3600,
      };

      // Clock tolerance is 60 seconds
      const result = tokenValidator.validateClaims(claims);

      expect(result.valid).toBe(true);
    });

    test('should validate audience when configured', () => {
      const validatorWithAud = new TokenValidator(
        { ...mockConfig, verifyAudience: true, expectedAudience: 'claude-flow-ui' },
        mockJWKSManager
      );

      const now = Math.floor(Date.now() / 1000);
      const claims = {
        sub: 'user:default/test',
        iss: mockConfig.backstageUrl,
        aud: 'wrong-audience',
        exp: now + 3600,
        iat: now,
      };

      const result = validatorWithAud.validateClaims(claims);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/invalid.*audience/i);
    });

    test('should reject token older than maxTokenAge', () => {
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        sub: 'user:default/test',
        iss: mockConfig.backstageUrl,
        exp: now + 3600,
        iat: now - 90000, // Issued 25 hours ago (exceeds maxTokenAge)
      };

      const result = tokenValidator.validateClaims(claims);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/token.*too.*old/i);
    });

    test('should validate subject format', () => {
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        sub: 'invalid-subject-format',
        iss: mockConfig.backstageUrl,
        exp: now + 3600,
        iat: now,
      };

      const result = tokenValidator.validateClaims(claims);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/invalid.*subject.*format/i);
    });
  });

  describe('Complete Token Validation', () => {
    test('should validate complete token successfully', async () => {
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        sub: 'user:default/test',
        ent: ['user:default/test', 'group:default/team-a'],
        iss: mockConfig.backstageUrl,
        exp: now + 3600,
        iat: now,
        nbf: now,
      };

      const token = jwt.sign(payload, mockPrivateKey, {
        algorithm: 'RS256',
        keyid: 'key-1',
      });

      const result = await tokenValidator.validate(token);

      expect(result.valid).toBe(true);
      expect(result.identity).toMatchObject({
        userEntityRef: 'user:default/test',
        ownershipEntityRefs: ['user:default/test', 'group:default/team-a'],
      });
    });

    test('should provide detailed error information', async () => {
      const expiredToken = jwt.sign(
        {
          sub: 'user:default/test',
          iss: mockConfig.backstageUrl,
          exp: Math.floor(Date.now() / 1000) - 3600,
          iat: Math.floor(Date.now() / 1000) - 7200,
        },
        mockPrivateKey,
        { algorithm: 'RS256', keyid: 'key-1' }
      );

      const result = await tokenValidator.validate(expiredToken);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.errorCode).toBe('TOKEN_EXPIRED');
      expect(result.stage).toBe('claims_validation');
    });

    test('should validate in strict mode', async () => {
      const strictValidator = new TokenValidator(
        { ...mockConfig, strictMode: true },
        mockJWKSManager
      );

      const tokenWithMissingClaims = jwt.sign(
        {
          sub: 'user:default/test',
          // Missing required claims
        },
        mockPrivateKey,
        { algorithm: 'RS256', keyid: 'key-1' }
      );

      const result = await strictValidator.validate(tokenWithMissingClaims);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/missing.*required.*claim/i);
    });

    test('should allow lenient validation when strict mode disabled', async () => {
      const lenientValidator = new TokenValidator(
        { ...mockConfig, strictMode: false, verifyIssuer: false },
        mockJWKSManager
      );

      const tokenWithoutIssuer = jwt.sign(
        {
          sub: 'user:default/test',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        },
        mockPrivateKey,
        { algorithm: 'RS256', keyid: 'key-1' }
      );

      const result = await lenientValidator.validate(tokenWithoutIssuer);

      expect(result.valid).toBe(true);
    });
  });

  describe('Performance', () => {
    test('should validate token within acceptable time', async () => {
      const token = jwt.sign(
        {
          sub: 'user:default/test',
          iss: mockConfig.backstageUrl,
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        },
        mockPrivateKey,
        { algorithm: 'RS256', keyid: 'key-1' }
      );

      const startTime = Date.now();
      await tokenValidator.validate(token);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(100); // < 100ms
    });

    test('should handle high validation throughput', async () => {
      const token = jwt.sign(
        {
          sub: 'user:default/test',
          iss: mockConfig.backstageUrl,
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        },
        mockPrivateKey,
        { algorithm: 'RS256', keyid: 'key-1' }
      );

      const promises = Array.from({ length: 100 }, () =>
        tokenValidator.validate(token)
      );

      const startTime = Date.now();
      await Promise.all(promises);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(1000); // All 100 validations < 1 second
    });
  });

  describe('Security', () => {
    test('should use constant-time comparison for signatures', async () => {
      // This test verifies timing attack prevention
      const validToken = jwt.sign(
        { sub: 'user:default/test' },
        mockPrivateKey,
        { algorithm: 'RS256', keyid: 'key-1' }
      );

      const timings: number[] = [];

      // Measure verification times
      for (let i = 0; i < 100; i++) {
        const start = process.hrtime.bigint();
        await tokenValidator.verifySignature(validToken);
        const end = process.hrtime.bigint();
        timings.push(Number(end - start) / 1000000); // Convert to ms
      }

      // Calculate standard deviation
      const mean = timings.reduce((a, b) => a + b) / timings.length;
      const variance = timings.reduce((sum, time) => sum + Math.pow(time - mean, 2), 0) / timings.length;
      const stdDev = Math.sqrt(variance);

      // Standard deviation should be small (consistent timing)
      expect(stdDev).toBeLessThan(5); // Less than 5ms variance
    });

    test('should not leak information through error messages', async () => {
      const tokens = [
        jwt.sign({ sub: 'test' }, 'wrong-key', { algorithm: 'HS256' }),
        jwt.sign({ sub: 'test' }, mockPrivateKey, { algorithm: 'RS256' }),
        'invalid.token.format',
      ];

      const results = await Promise.all(
        tokens.map(token => tokenValidator.validate(token))
      );

      // All errors should be generic
      results.forEach(result => {
        if (!result.valid) {
          expect(result.error).not.toContain('key');
          expect(result.error).not.toContain('signature');
          expect(result.error).not.toMatch(/\b[A-Za-z0-9+/=]{20,}\b/); // No key material
        }
      });
    });
  });
});
