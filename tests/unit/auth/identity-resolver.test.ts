/**
 * Identity Resolver Unit Tests
 *
 * Tests for extracting and resolving Backstage identity from JWT claims.
 * Validates user entity refs, group memberships, and permission resolution.
 */

import { IdentityResolver } from '@/services/identity-resolver';

describe('IdentityResolver', () => {
  let identityResolver: IdentityResolver;

  beforeEach(() => {
    identityResolver = new IdentityResolver();
  });

  describe('User Entity Ref Extraction', () => {
    test('should extract user entity ref from JWT subject', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);

      expect(identity.userEntityRef).toBe('user:default/john.doe');
    });

    test('should validate entity ref format', () => {
      const invalidClaims = {
        sub: 'invalid-format',
        ent: [],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      expect(() => {
        identityResolver.resolve(invalidClaims);
      }).toThrow(/invalid.*entity.*ref.*format/i);
    });

    test('should handle different entity kinds', () => {
      const testCases = [
        'user:default/john.doe',
        'group:platform/backend-team',
        'service:default/automation-bot',
      ];

      testCases.forEach(entityRef => {
        const claims = {
          sub: entityRef,
          ent: [entityRef],
          iss: 'https://backstage.example.com',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        };

        const identity = identityResolver.resolve(claims);
        expect(identity.userEntityRef).toBe(entityRef);
      });
    });

    test('should normalize entity refs to lowercase', () => {
      const claims = {
        sub: 'User:Default/John.Doe',
        ent: ['User:Default/John.Doe'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);

      expect(identity.userEntityRef).toBe('user:default/john.doe');
    });
  });

  describe('Ownership Entity Refs Extraction', () => {
    test('should extract all ownership entity refs', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: [
          'user:default/john.doe',
          'group:platform/backend-team',
          'group:security/admins',
        ],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);

      expect(identity.ownershipEntityRefs).toEqual([
        'user:default/john.doe',
        'group:platform/backend-team',
        'group:security/admins',
      ]);
    });

    test('should handle empty ownership refs', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: [],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);

      expect(identity.ownershipEntityRefs).toEqual([]);
    });

    test('should deduplicate ownership refs', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: [
          'user:default/john.doe',
          'group:platform/backend-team',
          'group:platform/backend-team', // Duplicate
        ],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);

      expect(identity.ownershipEntityRefs).toEqual([
        'user:default/john.doe',
        'group:platform/backend-team',
      ]);
    });

    test('should filter invalid ownership refs', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: [
          'user:default/john.doe',
          'invalid-ref',
          'group:platform/backend-team',
          '',
          null,
        ],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);

      expect(identity.ownershipEntityRefs).toEqual([
        'user:default/john.doe',
        'group:platform/backend-team',
      ]);
    });
  });

  describe('Group Membership Resolution', () => {
    test('should extract group memberships', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: [
          'user:default/john.doe',
          'group:platform/backend-team',
          'group:security/admins',
        ],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);

      expect(identity.groups).toEqual([
        'group:platform/backend-team',
        'group:security/admins',
      ]);
    });

    test('should filter non-group ownership refs', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: [
          'user:default/john.doe',
          'group:platform/backend-team',
          'service:default/automation-bot',
        ],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);

      expect(identity.groups).toEqual(['group:platform/backend-team']);
    });

    test('should handle user with no groups', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);

      expect(identity.groups).toEqual([]);
    });
  });

  describe('Session Metadata', () => {
    test('should generate unique session ID', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity1 = identityResolver.resolve(claims);
      const identity2 = identityResolver.resolve(claims);

      expect(identity1.localSessionId).not.toBe(identity2.localSessionId);
      expect(identity1.localSessionId).toMatch(/^[a-f0-9-]{36}$/); // UUID format
    });

    test('should record authentication timestamp', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const beforeAuth = new Date();
      const identity = identityResolver.resolve(claims);
      const afterAuth = new Date();

      expect(identity.authenticatedAt.getTime()).toBeGreaterThanOrEqual(beforeAuth.getTime());
      expect(identity.authenticatedAt.getTime()).toBeLessThanOrEqual(afterAuth.getTime());
    });

    test('should calculate expiration time from claims', () => {
      const expTimestamp = Math.floor(Date.now() / 1000) + 3600;
      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe'],
        iss: 'https://backstage.example.com',
        exp: expTimestamp,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);

      expect(identity.expiresAt.getTime()).toBe(expTimestamp * 1000);
    });

    test('should extract additional metadata from claims', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        email: 'john.doe@example.com',
        name: 'John Doe',
        picture: 'https://example.com/avatar.jpg',
      };

      const identity = identityResolver.resolve(claims);

      expect(identity.metadata).toMatchObject({
        email: 'john.doe@example.com',
        name: 'John Doe',
        picture: 'https://example.com/avatar.jpg',
      });
    });
  });

  describe('Permission Resolution', () => {
    test('should resolve permissions from groups', () => {
      const resolverWithPermissions = new IdentityResolver({
        permissionMapping: {
          'group:security/admins': ['admin', 'read', 'write', 'delete'],
          'group:platform/backend-team': ['read', 'write'],
        },
      });

      const claims = {
        sub: 'user:default/john.doe',
        ent: [
          'user:default/john.doe',
          'group:security/admins',
          'group:platform/backend-team',
        ],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = resolverWithPermissions.resolve(claims);

      expect(identity.permissions).toContain('admin');
      expect(identity.permissions).toContain('read');
      expect(identity.permissions).toContain('write');
      expect(identity.permissions).toContain('delete');
    });

    test('should deduplicate permissions', () => {
      const resolverWithPermissions = new IdentityResolver({
        permissionMapping: {
          'group:security/admins': ['read', 'write'],
          'group:platform/backend-team': ['read', 'write'], // Same permissions
        },
      });

      const claims = {
        sub: 'user:default/john.doe',
        ent: [
          'user:default/john.doe',
          'group:security/admins',
          'group:platform/backend-team',
        ],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = resolverWithPermissions.resolve(claims);

      expect(identity.permissions).toEqual(['read', 'write']);
    });

    test('should handle default permissions', () => {
      const resolverWithDefaults = new IdentityResolver({
        defaultPermissions: ['read'],
      });

      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = resolverWithDefaults.resolve(claims);

      expect(identity.permissions).toContain('read');
    });
  });

  describe('Entity Ref Parsing', () => {
    test('should parse entity ref components', () => {
      const entityRef = 'user:default/john.doe';

      const parsed = identityResolver.parseEntityRef(entityRef);

      expect(parsed).toMatchObject({
        kind: 'user',
        namespace: 'default',
        name: 'john.doe',
      });
    });

    test('should handle entity refs without namespace', () => {
      const entityRef = 'user:john.doe';

      const parsed = identityResolver.parseEntityRef(entityRef);

      expect(parsed).toMatchObject({
        kind: 'user',
        namespace: 'default', // Default namespace
        name: 'john.doe',
      });
    });

    test('should validate entity ref components', () => {
      const invalidRefs = [
        'invalid',
        ':default/name',
        'kind:/name',
        'kind:namespace/',
        '',
      ];

      invalidRefs.forEach(ref => {
        expect(() => {
          identityResolver.parseEntityRef(ref);
        }).toThrow(/invalid.*entity.*ref/i);
      });
    });

    test('should handle special characters in names', () => {
      const entityRef = 'user:default/john.doe+admin';

      const parsed = identityResolver.parseEntityRef(entityRef);

      expect(parsed.name).toBe('john.doe+admin');
    });
  });

  describe('Identity Serialization', () => {
    test('should serialize identity to JSON', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe', 'group:platform/backend-team'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);
      const serialized = JSON.stringify(identity);
      const deserialized = JSON.parse(serialized);

      expect(deserialized.userEntityRef).toBe('user:default/john.doe');
      expect(deserialized.ownershipEntityRefs).toEqual([
        'user:default/john.doe',
        'group:platform/backend-team',
      ]);
    });

    test('should handle date serialization', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const identity = identityResolver.resolve(claims);
      const serialized = JSON.stringify(identity);
      const deserialized = JSON.parse(serialized);

      expect(new Date(deserialized.authenticatedAt)).toBeInstanceOf(Date);
      expect(new Date(deserialized.expiresAt)).toBeInstanceOf(Date);
    });
  });

  describe('Error Handling', () => {
    test('should handle missing subject claim', () => {
      const claims = {
        ent: ['user:default/john.doe'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      expect(() => {
        identityResolver.resolve(claims as any);
      }).toThrow(/missing.*subject/i);
    });

    test('should handle invalid ent claim type', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: 'not-an-array',
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      expect(() => {
        identityResolver.resolve(claims as any);
      }).toThrow(/invalid.*ownership.*refs/i);
    });

    test('should handle missing expiration claim', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe'],
        iss: 'https://backstage.example.com',
        iat: Math.floor(Date.now() / 1000),
      };

      expect(() => {
        identityResolver.resolve(claims as any);
      }).toThrow(/missing.*expiration/i);
    });
  });

  describe('Performance', () => {
    test('should resolve identity efficiently', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe', 'group:platform/backend-team'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const startTime = Date.now();

      for (let i = 0; i < 1000; i++) {
        identityResolver.resolve(claims);
      }

      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(100); // < 100ms for 1000 resolutions
    });

    test('should not leak memory on repeated resolutions', () => {
      const claims = {
        sub: 'user:default/john.doe',
        ent: ['user:default/john.doe'],
        iss: 'https://backstage.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const initialMemory = process.memoryUsage().heapUsed;

      for (let i = 0; i < 10000; i++) {
        identityResolver.resolve(claims);
      }

      if (global.gc) global.gc();

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryGrowth = finalMemory - initialMemory;

      expect(memoryGrowth).toBeLessThan(1 * 1024 * 1024); // < 1MB growth
    });
  });
});
