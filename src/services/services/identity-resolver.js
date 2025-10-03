"use strict";
/**
 * Identity Resolver for Backstage Authentication
 *
 * Resolves user and group entity references from Backstage JWT tokens.
 * Handles entity reference parsing and normalization.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseEntityRef = parseEntityRef;
exports.stringifyEntityRef = stringifyEntityRef;
exports.entityRefsEqual = entityRefsEqual;
exports.isUserAllowed = isUserAllowed;
exports.hasAllowedGroup = hasAllowedGroup;
exports.authorizeUser = authorizeUser;
exports.getUserDisplayName = getUserDisplayName;
exports.getGroupDisplayNames = getGroupDisplayNames;
exports.normalizeEntityRef = normalizeEntityRef;
exports.isValidEntityRef = isValidEntityRef;
const backstage_auth_1 = require("../types/backstage-auth");
/**
 * Parse Backstage entity reference string
 * Format: [kind]:[namespace]/[name]
 * Examples: user:default/john.doe, group:default/admins
 *
 * @param entityRef - Entity reference string
 * @returns Parsed entity reference
 */
function parseEntityRef(entityRef) {
    // Match format: kind:namespace/name
    const match = entityRef.match(/^([^:]+):([^/]+)\/(.+)$/);
    if (!match) {
        throw new backstage_auth_1.AuthenticationError('INVALID_TOKEN', 'Invalid entity reference format', 401, { entityRef });
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
function stringifyEntityRef(ref) {
    return `${ref.kind}:${ref.namespace}/${ref.name}`;
}
/**
 * Compare two entity references for equality
 * @param ref1 - First entity reference
 * @param ref2 - Second entity reference
 * @returns True if references are equal
 */
function entityRefsEqual(ref1, ref2) {
    return (ref1.kind === ref2.kind &&
        ref1.namespace === ref2.namespace &&
        ref1.name === ref2.name);
}
/**
 * Check if user is in allowed users list
 * @param userRef - User entity reference
 * @param allowedUsers - List of allowed user entity reference strings
 * @returns True if user is allowed
 */
function isUserAllowed(userRef, allowedUsers) {
    if (allowedUsers.length === 0) {
        return true; // No restrictions if list is empty
    }
    return allowedUsers.some(allowedUser => {
        try {
            const allowedRef = parseEntityRef(allowedUser);
            return entityRefsEqual(userRef, allowedRef);
        }
        catch {
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
function hasAllowedGroup(groupRefs, allowedGroups) {
    if (allowedGroups.length === 0) {
        return true; // No restrictions if list is empty
    }
    return allowedGroups.some(allowedGroup => {
        try {
            const allowedRef = parseEntityRef(allowedGroup);
            return groupRefs.some(groupRef => entityRefsEqual(groupRef, allowedRef));
        }
        catch {
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
function authorizeUser(user, config) {
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
        const allowedGroupRef = user.groupRefs.find(groupRef => hasAllowedGroup([groupRef], allowedGroups));
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
function getUserDisplayName(userRef) {
    return userRef.name;
}
/**
 * Get all groups user belongs to as display names
 * @param groupRefs - Group entity references
 * @returns Array of group display names
 */
function getGroupDisplayNames(groupRefs) {
    return groupRefs.map(ref => ref.name);
}
/**
 * Normalize entity reference string (ensure lowercase)
 * @param entityRef - Entity reference string
 * @returns Normalized entity reference string
 */
function normalizeEntityRef(entityRef) {
    const ref = parseEntityRef(entityRef);
    return stringifyEntityRef(ref);
}
/**
 * Validate entity reference format
 * @param entityRef - Entity reference string to validate
 * @returns True if valid
 */
function isValidEntityRef(entityRef) {
    try {
        parseEntityRef(entityRef);
        return true;
    }
    catch {
        return false;
    }
}
