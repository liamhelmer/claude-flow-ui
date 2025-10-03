/**
 * Identity Resolver for Backstage Authentication
 *
 * Resolves user and group entity references from Backstage JWT tokens.
 * Handles entity reference parsing and normalization.
 */

import type { BackstageEntityRef, BackstageAuthConfig, AuthenticatedUser, AuthorizationResult, AuthErrorType } from '../types/backstage-auth';
import { AuthenticationError } from '../types/backstage-auth';

/**
 * Parse Backstage entity reference string
 * Format: [kind]:[namespace]/[name]
 * Examples: user:default/john.doe, group:default/admins
 *
 * @param entityRef - Entity reference string
 * @returns Parsed entity reference
 */
export function parseEntityRef(entityRef: string): BackstageEntityRef {
  // Match format: kind:namespace/name
  const match = entityRef.match(/^([^:]+):([^/]+)\/(.+)$/);

  if (!match) {
    throw new AuthenticationError(
      'INVALID_TOKEN' as AuthErrorType,
      'Invalid entity reference format',
      401,
      { entityRef }
    );
  }

  const [, kind, namespace, name] = match;

  return {
    kind: kind.toLowerCase(),
    namespace: namespace.toLowerCase(),
    name: name.toLowerCase(),
  };
}

/**
 * Stringify entity reference back to string format
 * @param ref - Entity reference object
 * @returns Entity reference string
 */
export function stringifyEntityRef(ref: BackstageEntityRef): string {
  return `${ref.kind}:${ref.namespace}/${ref.name}`;
}

/**
 * Compare two entity references for equality
 * @param ref1 - First entity reference
 * @param ref2 - Second entity reference
 * @returns True if references are equal
 */
export function entityRefsEqual(ref1: BackstageEntityRef, ref2: BackstageEntityRef): boolean {
  return (
    ref1.kind === ref2.kind &&
    ref1.namespace === ref2.namespace &&
    ref1.name === ref2.name
  );
}

/**
 * Check if user is in allowed users list
 * @param userRef - User entity reference
 * @param allowedUsers - List of allowed user entity reference strings
 * @returns True if user is allowed
 */
export function isUserAllowed(userRef: BackstageEntityRef, allowedUsers: string[]): boolean {
  if (allowedUsers.length === 0) {
    return true; // No restrictions if list is empty
  }

  return allowedUsers.some(allowedUser => {
    try {
      const allowedRef = parseEntityRef(allowedUser);
      return entityRefsEqual(userRef, allowedRef);
    } catch {
      return false; // Ignore invalid references
    }
  });
}

/**
 * Check if user belongs to any allowed groups
 * @param groupRefs - User's group entity references
 * @param allowedGroups - List of allowed group entity reference strings
 * @returns True if user belongs to allowed group
 */
export function hasAllowedGroup(groupRefs: BackstageEntityRef[], allowedGroups: string[]): boolean {
  if (allowedGroups.length === 0) {
    return true; // No restrictions if list is empty
  }

  return allowedGroups.some(allowedGroup => {
    try {
      const allowedRef = parseEntityRef(allowedGroup);
      return groupRefs.some(groupRef => entityRefsEqual(groupRef, allowedRef));
    } catch {
      return false; // Ignore invalid references
    }
  });
}

/**
 * Authorize user based on allowed users and groups
 * @param user - Authenticated user context
 * @param config - Backstage auth configuration
 * @returns Authorization result
 */
export function authorizeUser(
  user: AuthenticatedUser,
  config: BackstageAuthConfig
): AuthorizationResult {
  const allowedUsers = config.allowedUsers || [];
  const allowedGroups = config.allowedGroups || [];

  // If both lists are empty, allow all authenticated users
  if (allowedUsers.length === 0 && allowedGroups.length === 0) {
    return {
      allowed: true,
      reason: 'No authorization restrictions configured',
      user,
    };
  }

  // Check if user is in allowed users list
  if (isUserAllowed(user.userRef, allowedUsers)) {
    return {
      allowed: true,
      reason: `User ${stringifyEntityRef(user.userRef)} is in allowed users list`,
      user,
    };
  }

  // Check if user belongs to allowed groups
  if (hasAllowedGroup(user.groupRefs, allowedGroups)) {
    const allowedGroupRef = user.groupRefs.find(groupRef =>
      hasAllowedGroup([groupRef], allowedGroups)
    );

    return {
      allowed: true,
      reason: `User belongs to allowed group ${allowedGroupRef ? stringifyEntityRef(allowedGroupRef) : 'unknown'}`,
      user,
    };
  }

  // User not authorized
  return {
    allowed: false,
    reason: 'User not in allowed users or groups',
    user,
  };
}

/**
 * Get user display name from entity reference
 * @param userRef - User entity reference
 * @returns Display name
 */
export function getUserDisplayName(userRef: BackstageEntityRef): string {
  return userRef.name;
}

/**
 * Get all groups user belongs to as display names
 * @param groupRefs - Group entity references
 * @returns Array of group display names
 */
export function getGroupDisplayNames(groupRefs: BackstageEntityRef[]): string[] {
  return groupRefs.map(ref => ref.name);
}

/**
 * Normalize entity reference string (ensure lowercase)
 * @param entityRef - Entity reference string
 * @returns Normalized entity reference string
 */
export function normalizeEntityRef(entityRef: string): string {
  const ref = parseEntityRef(entityRef);
  return stringifyEntityRef(ref);
}

/**
 * Validate entity reference format
 * @param entityRef - Entity reference string to validate
 * @returns True if valid
 */
export function isValidEntityRef(entityRef: string): boolean {
  try {
    parseEntityRef(entityRef);
    return true;
  } catch {
    return false;
  }
}
