/**
 * Authorization Engine Unit Tests
 *
 * Tests for checking user/group permissions and access control logic.
 * Validates authorization decisions based on configured allow/deny lists.
 */

import { AuthorizationEngine } from '@/services/authorization';
import { BackstageIdentity } from '@/types/backstage-identity';

describe('AuthorizationEngine', () => {
  let authzEngine: AuthorizationEngine;

  const mockIdentity: BackstageIdentity = {
    userEntityRef: 'user:default/john.doe',
    ownershipEntityRefs: [
      'user:default/john.doe',
      'group:platform/backend-team',
      'group:security/admins',
    ],
    localSessionId: 'session-123',
    authenticatedAt: new Date(),
    expiresAt: new Date(Date.now() + 3600000),
    permissions: ['read', 'write'],
    metadata: {},
  };

  beforeEach(() => {
    authzEngine = new AuthorizationEngine({
      mode: 'allowlist',
      allowedUsers: ['user:default/john.doe', 'user:default/jane.smith'],
      allowedGroups: ['group:security/admins', 'group:platform/backend-team'],
      defaultRole: 'viewer',
      inheritGroupPermissions: true,
    });
  });

  describe('Allowlist Mode', () => {
    test('should allow user in allowlist', async () => {
      const result = await authzEngine.authorize(mockIdentity);

      expect(result.authorized).toBe(true);
      expect(result.reason).toMatch(/user.*allowlist/i);
    });

    test('should allow user in allowed group', async () => {
      const userNotInList: BackstageIdentity = {
        ...mockIdentity,
        userEntityRef: 'user:default/other.user',
        ownershipEntityRefs: [
          'user:default/other.user',
          'group:security/admins', // In allowed groups
        ],
      };

      const result = await authzEngine.authorize(userNotInList);

      expect(result.authorized).toBe(true);
      expect(result.reason).toMatch(/group.*allowlist/i);
    });

    test('should deny user not in allowlist or allowed groups', async () => {
      const unauthorizedUser: BackstageIdentity = {
        ...mockIdentity,
        userEntityRef: 'user:default/unauthorized',
        ownershipEntityRefs: [
          'user:default/unauthorized',
          'group:unallowed/team',
        ],
      };

      const result = await authzEngine.authorize(unauthorizedUser);

      expect(result.authorized).toBe(false);
      expect(result.reason).toMatch(/not.*authorized/i);
    });

    test('should check multiple groups', async () => {
      const userInMultipleGroups: BackstageIdentity = {
        ...mockIdentity,
        userEntityRef: 'user:default/other.user',
        ownershipEntityRefs: [
          'user:default/other.user',
          'group:unallowed/team1',
          'group:platform/backend-team', // One allowed group
          'group:unallowed/team2',
        ],
      };

      const result = await authzEngine.authorize(userInMultipleGroups);

      expect(result.authorized).toBe(true);
    });

    test('should handle empty allowlists', async () => {
      const emptyAuthz = new AuthorizationEngine({
        mode: 'allowlist',
        allowedUsers: [],
        allowedGroups: [],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
      });

      const result = await emptyAuthz.authorize(mockIdentity);

      expect(result.authorized).toBe(false);
    });
  });

  describe('Denylist Mode', () => {
    test('should deny user in denylist', async () => {
      const denyAuthz = new AuthorizationEngine({
        mode: 'denylist',
        deniedUsers: ['user:default/john.doe'],
        deniedGroups: [],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
      });

      const result = await denyAuthz.authorize(mockIdentity);

      expect(result.authorized).toBe(false);
      expect(result.reason).toMatch(/denied/i);
    });

    test('should deny user in denied group', async () => {
      const denyAuthz = new AuthorizationEngine({
        mode: 'denylist',
        deniedUsers: [],
        deniedGroups: ['group:security/admins'],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
      });

      const result = await denyAuthz.authorize(mockIdentity);

      expect(result.authorized).toBe(false);
      expect(result.reason).toMatch(/group.*denied/i);
    });

    test('should allow user not in denylists', async () => {
      const denyAuthz = new AuthorizationEngine({
        mode: 'denylist',
        deniedUsers: ['user:default/other.user'],
        deniedGroups: ['group:unallowed/team'],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
      });

      const result = await denyAuthz.authorize(mockIdentity);

      expect(result.authorized).toBe(true);
    });
  });

  describe('Disabled Mode', () => {
    test('should allow all users when authorization disabled', async () => {
      const disabledAuthz = new AuthorizationEngine({
        mode: 'disabled',
        allowedUsers: [],
        allowedGroups: [],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
      });

      const result = await disabledAuthz.authorize(mockIdentity);

      expect(result.authorized).toBe(true);
      expect(result.reason).toMatch(/disabled/i);
    });

    test('should allow any user entity ref when disabled', async () => {
      const disabledAuthz = new AuthorizationEngine({
        mode: 'disabled',
        allowedUsers: [],
        allowedGroups: [],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
      });

      const randomUser: BackstageIdentity = {
        ...mockIdentity,
        userEntityRef: 'user:default/random.user',
        ownershipEntityRefs: ['user:default/random.user'],
      };

      const result = await disabledAuthz.authorize(randomUser);

      expect(result.authorized).toBe(true);
    });
  });

  describe('Case Sensitivity', () => {
    test('should handle case-insensitive user refs', async () => {
      const upperCaseUser: BackstageIdentity = {
        ...mockIdentity,
        userEntityRef: 'User:Default/John.Doe', // Different case
        ownershipEntityRefs: ['User:Default/John.Doe'],
      };

      const result = await authzEngine.authorize(upperCaseUser);

      expect(result.authorized).toBe(true);
    });

    test('should handle case-insensitive group refs', async () => {
      const mixedCaseGroups: BackstageIdentity = {
        ...mockIdentity,
        userEntityRef: 'user:default/other.user',
        ownershipEntityRefs: [
          'user:default/other.user',
          'Group:Security/Admins', // Different case
        ],
      };

      const result = await authzEngine.authorize(mixedCaseGroups);

      expect(result.authorized).toBe(true);
    });
  });

  describe('Permission Inheritance', () => {
    test('should inherit group permissions when enabled', async () => {
      const authzWithPerms = new AuthorizationEngine({
        mode: 'allowlist',
        allowedUsers: [],
        allowedGroups: ['group:security/admins'],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
        groupPermissions: {
          'group:security/admins': ['admin', 'read', 'write', 'delete'],
        },
      });

      const result = await authzWithPerms.authorize(mockIdentity);

      expect(result.authorized).toBe(true);
      expect(result.resolvedPermissions).toContain('admin');
      expect(result.resolvedPermissions).toContain('delete');
    });

    test('should not inherit permissions when disabled', async () => {
      const authzNoInherit = new AuthorizationEngine({
        mode: 'allowlist',
        allowedUsers: ['user:default/john.doe'],
        allowedGroups: [],
        defaultRole: 'viewer',
        inheritGroupPermissions: false,
        groupPermissions: {
          'group:security/admins': ['admin'],
        },
      });

      const result = await authzNoInherit.authorize(mockIdentity);

      expect(result.authorized).toBe(true);
      expect(result.resolvedPermissions).not.toContain('admin');
    });

    test('should merge permissions from multiple groups', async () => {
      const authzMultiGroup = new AuthorizationEngine({
        mode: 'allowlist',
        allowedUsers: [],
        allowedGroups: ['group:security/admins', 'group:platform/backend-team'],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
        groupPermissions: {
          'group:security/admins': ['admin', 'delete'],
          'group:platform/backend-team': ['read', 'write'],
        },
      });

      const result = await authzMultiGroup.authorize(mockIdentity);

      expect(result.resolvedPermissions).toContain('admin');
      expect(result.resolvedPermissions).toContain('read');
      expect(result.resolvedPermissions).toContain('write');
      expect(result.resolvedPermissions).toContain('delete');
    });
  });

  describe('Default Roles', () => {
    test('should apply default role permissions', async () => {
      const authzWithDefault = new AuthorizationEngine({
        mode: 'allowlist',
        allowedUsers: ['user:default/john.doe'],
        allowedGroups: [],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
        rolePermissions: {
          viewer: ['read'],
          editor: ['read', 'write'],
          admin: ['read', 'write', 'delete'],
        },
      });

      const result = await authzWithDefault.authorize(mockIdentity);

      expect(result.resolvedPermissions).toContain('read');
      expect(result.role).toBe('viewer');
    });

    test('should override default role with group role', async () => {
      const authzWithRoles = new AuthorizationEngine({
        mode: 'allowlist',
        allowedUsers: [],
        allowedGroups: ['group:security/admins'],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
        groupRoles: {
          'group:security/admins': 'admin',
        },
        rolePermissions: {
          viewer: ['read'],
          admin: ['read', 'write', 'delete'],
        },
      });

      const result = await authzWithRoles.authorize(mockIdentity);

      expect(result.role).toBe('admin');
      expect(result.resolvedPermissions).toContain('delete');
    });
  });

  describe('Timing Attack Prevention', () => {
    test('should use constant-time comparison for authorization checks', async () => {
      const timings: number[] = [];

      // Measure authorization check times
      for (let i = 0; i < 100; i++) {
        const start = process.hrtime.bigint();
        await authzEngine.authorize(mockIdentity);
        const end = process.hrtime.bigint();
        timings.push(Number(end - start) / 1000000);
      }

      // Calculate standard deviation
      const mean = timings.reduce((a, b) => a + b) / timings.length;
      const variance = timings.reduce((sum, time) => sum + Math.pow(time - mean, 2), 0) / timings.length;
      const stdDev = Math.sqrt(variance);

      // Standard deviation should be small (consistent timing)
      expect(stdDev).toBeLessThan(5); // Less than 5ms variance
    });

    test('should take similar time for authorized and unauthorized users', async () => {
      const authorizedUser = mockIdentity;
      const unauthorizedUser: BackstageIdentity = {
        ...mockIdentity,
        userEntityRef: 'user:default/unauthorized',
        ownershipEntityRefs: ['user:default/unauthorized'],
      };

      const authorizedTimings: number[] = [];
      const unauthorizedTimings: number[] = [];

      for (let i = 0; i < 50; i++) {
        const start1 = process.hrtime.bigint();
        await authzEngine.authorize(authorizedUser);
        const end1 = process.hrtime.bigint();
        authorizedTimings.push(Number(end1 - start1) / 1000000);

        const start2 = process.hrtime.bigint();
        await authzEngine.authorize(unauthorizedUser);
        const end2 = process.hrtime.bigint();
        unauthorizedTimings.push(Number(end2 - start2) / 1000000);
      }

      const authorizedMean = authorizedTimings.reduce((a, b) => a + b) / authorizedTimings.length;
      const unauthorizedMean = unauthorizedTimings.reduce((a, b) => a + b) / unauthorizedTimings.length;

      // Means should be similar (within 10%)
      const difference = Math.abs(authorizedMean - unauthorizedMean);
      const percentDifference = (difference / authorizedMean) * 100;

      expect(percentDifference).toBeLessThan(10);
    });
  });

  describe('Audit Logging', () => {
    test('should log authorization decisions', async () => {
      const auditSpy = jest.fn();
      const authzWithAudit = new AuthorizationEngine({
        mode: 'allowlist',
        allowedUsers: ['user:default/john.doe'],
        allowedGroups: [],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
        auditLogger: auditSpy,
      });

      await authzWithAudit.authorize(mockIdentity);

      expect(auditSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'authorization_check',
          userEntityRef: 'user:default/john.doe',
          authorized: true,
          timestamp: expect.any(Date),
        })
      );
    });

    test('should log denied authorizations', async () => {
      const auditSpy = jest.fn();
      const authzWithAudit = new AuthorizationEngine({
        mode: 'allowlist',
        allowedUsers: [],
        allowedGroups: [],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
        auditLogger: auditSpy,
      });

      await authzWithAudit.authorize(mockIdentity);

      expect(auditSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'authorization_denied',
          userEntityRef: 'user:default/john.doe',
          authorized: false,
        })
      );
    });

    test('should not log sensitive information', async () => {
      const auditSpy = jest.fn();
      const authzWithAudit = new AuthorizationEngine({
        mode: 'allowlist',
        allowedUsers: ['user:default/john.doe'],
        allowedGroups: [],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
        auditLogger: auditSpy,
      });

      await authzWithAudit.authorize(mockIdentity);

      const allLogs = auditSpy.mock.calls.flat().map(call => JSON.stringify(call)).join(' ');

      // Should not contain session IDs or metadata
      expect(allLogs).not.toContain(mockIdentity.localSessionId);
    });
  });

  describe('Performance', () => {
    test('should perform authorization checks quickly', async () => {
      const startTime = Date.now();

      for (let i = 0; i < 1000; i++) {
        await authzEngine.authorize(mockIdentity);
      }

      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(100); // < 100ms for 1000 checks
    });

    test('should handle large allowlists efficiently', async () => {
      const largeAllowlist = Array.from({ length: 1000 }, (_, i) => `user:default/user${i}`);

      const largeAuthz = new AuthorizationEngine({
        mode: 'allowlist',
        allowedUsers: largeAllowlist,
        allowedGroups: [],
        defaultRole: 'viewer',
        inheritGroupPermissions: true,
      });

      const start = Date.now();
      await largeAuthz.authorize(mockIdentity);
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(50); // < 50ms
    });
  });

  describe('Error Handling', () => {
    test('should handle missing identity gracefully', async () => {
      await expect(authzEngine.authorize(null as any)).rejects.toThrow(
        /invalid.*identity/i
      );
    });

    test('should handle malformed entity refs', async () => {
      const malformedIdentity: BackstageIdentity = {
        ...mockIdentity,
        userEntityRef: 'invalid-format',
      };

      const result = await authzEngine.authorize(malformedIdentity);

      expect(result.authorized).toBe(false);
      expect(result.error).toMatch(/invalid.*entity.*ref/i);
    });

    test('should handle empty ownership refs', async () => {
      const emptyIdentity: BackstageIdentity = {
        ...mockIdentity,
        ownershipEntityRefs: [],
      };

      const result = await authzEngine.authorize(emptyIdentity);

      // Should still check user allowlist
      expect(result.authorized).toBe(true);
    });
  });
});
