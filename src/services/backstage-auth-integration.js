/**
 * Backstage Authentication Integration for unified-server.js
 *
 * This module provides the integration layer between the TypeScript authentication
 * services and the Node.js unified-server. It handles CLI parsing, configuration,
 * and initialization of authentication middleware.
 */

const { AuthenticationManager } = require('../middleware/authentication');
const { AuthorizationManager } = require('../middleware/authorization');

/**
 * Parse Backstage authentication CLI options
 * @param {string[]} args - Command line arguments
 * @returns {Object} Parsed authentication configuration
 */
function parseBackstageAuthOptions(args) {
  const config = {
    backstageUrl: process.env.BACKSTAGE_URL || null,
    jwksPath: process.env.BACKSTAGE_JWKS_PATH || '/api/auth/.well-known/jwks.json',
    requireAuth: process.env.BACKSTAGE_REQUIRE_AUTH === 'true' || false,
    issuer: process.env.BACKSTAGE_ISSUER || null,
    audience: process.env.BACKSTAGE_AUDIENCE || null,
    allowedUsers: [],
    allowedGroups: [],
    jwksCacheTTL: parseInt(process.env.BACKSTAGE_JWKS_TTL) || 3600000,
    maxRetryAttempts: parseInt(process.env.BACKSTAGE_MAX_RETRY) || 3,
    rateLimitMax: parseInt(process.env.BACKSTAGE_RATE_LIMIT_MAX) || 100,
    rateLimitWindow: parseInt(process.env.BACKSTAGE_RATE_LIMIT_WINDOW) || 900000,
  };

  // Parse command line arguments
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--backstage-url' && i + 1 < args.length) {
      config.backstageUrl = args[i + 1];
      i++;
    } else if (arg === '--backstage-jwks-path' && i + 1 < args.length) {
      config.jwksPath = args[i + 1];
      i++;
    } else if (arg === '--backstage-require-auth') {
      if (i + 1 < args.length && args[i + 1] !== '--') {
        config.requireAuth = args[i + 1].toLowerCase() === 'true';
        i++;
      } else {
        config.requireAuth = true;
      }
    } else if (arg === '--backstage-issuer' && i + 1 < args.length) {
      config.issuer = args[i + 1];
      i++;
    } else if (arg === '--backstage-audience' && i + 1 < args.length) {
      config.audience = args[i + 1];
      i++;
    } else if (arg === '--backstage-allowed-users' && i + 1 < args.length) {
      config.allowedUsers = args[i + 1].split(',').map(s => s.trim()).filter(Boolean);
      i++;
    } else if (arg === '--backstage-allowed-groups' && i + 1 < args.length) {
      config.allowedGroups = args[i + 1].split(',').map(s => s.trim()).filter(Boolean);
      i++;
    } else if (arg === '--backstage-rate-limit-max' && i + 1 < args.length) {
      config.rateLimitMax = parseInt(args[i + 1]);
      i++;
    } else if (arg === '--backstage-rate-limit-window' && i + 1 < args.length) {
      config.rateLimitWindow = parseInt(args[i + 1]);
      i++;
    }
  }

  // Parse environment variables for allowed users/groups if not set via CLI
  if (config.allowedUsers.length === 0 && process.env.BACKSTAGE_ALLOWED_USERS) {
    config.allowedUsers = process.env.BACKSTAGE_ALLOWED_USERS
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
  }

  if (config.allowedGroups.length === 0 && process.env.BACKSTAGE_ALLOWED_GROUPS) {
    config.allowedGroups = process.env.BACKSTAGE_ALLOWED_GROUPS
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
  }

  return config;
}

/**
 * Initialize Backstage authentication system
 * @param {Object} config - Authentication configuration
 * @returns {Object} Initialized authentication and authorization managers
 */
function initializeBackstageAuth(config) {
  // Validate configuration
  if (!config.backstageUrl) {
    console.log('[Backstage Auth] Not enabled (no --backstage-url provided)');
    return null;
  }

  console.log('[Backstage Auth] Initializing with configuration:');
  console.log(`  URL: ${config.backstageUrl}`);
  console.log(`  JWKS Path: ${config.jwksPath}`);
  console.log(`  Require Auth: ${config.requireAuth}`);
  console.log(`  Issuer: ${config.issuer || 'not specified'}`);
  console.log(`  Audience: ${config.audience || 'not specified'}`);
  console.log(`  Allowed Users: ${config.allowedUsers.length} configured`);
  console.log(`  Allowed Groups: ${config.allowedGroups.length} configured`);
  console.log(`  Rate Limit: ${config.rateLimitMax} requests per ${config.rateLimitWindow}ms`);

  try {
    const authManager = new AuthenticationManager(config);
    const authzManager = new AuthorizationManager(config);

    return {
      authManager,
      authzManager,
      config,
    };
  } catch (error) {
    console.error('[Backstage Auth] Failed to initialize:', error);
    throw error;
  }
}

/**
 * Apply authentication middleware to Express app
 * @param {Object} app - Express app
 * @param {Object} authSystem - Initialized auth system
 */
function applyExpressMiddleware(app, authSystem) {
  if (!authSystem) {
    return; // No auth configured
  }

  const { authManager, authzManager } = authSystem;

  // Apply authentication middleware (validates JWT)
  app.use(authManager.createExpressMiddleware());

  // Apply authorization middleware (checks allowed users/groups)
  app.use(authzManager.createExpressMiddleware());

  console.log('[Backstage Auth] Express middleware applied');
}

/**
 * Apply WebSocket authentication middleware
 * @param {Object} io - Socket.IO server
 * @param {Object} authSystem - Initialized auth system
 */
function applyWebSocketMiddleware(io, authSystem) {
  if (!authSystem) {
    return; // No auth configured
  }

  const { authManager, authzManager } = authSystem;

  // Apply authentication middleware (validates JWT)
  io.use(authManager.createWebSocketMiddleware());

  // Apply authorization middleware (checks allowed users/groups)
  io.use(authzManager.createWebSocketMiddleware());

  console.log('[Backstage Auth] WebSocket middleware applied');
}

/**
 * Get authenticated user from request
 * @param {Object} req - Express request
 * @returns {Object|null} Authenticated user or null
 */
function getAuthenticatedUser(req) {
  return req.user || null;
}

/**
 * Get authenticated user from socket
 * @param {Object} socket - Socket.IO socket
 * @returns {Object|null} Authenticated user or null
 */
function getSocketAuthenticatedUser(socket) {
  return socket.user || null;
}

/**
 * Check if terminal access is allowed
 * @param {Object} authSystem - Initialized auth system
 * @param {Object} user - Authenticated user
 * @param {string} terminalId - Terminal ID
 * @param {string} terminalOwner - Terminal owner user ref
 * @returns {boolean} True if access allowed
 */
function canAccessTerminal(authSystem, user, terminalId, terminalOwner) {
  if (!authSystem || !user) {
    return true; // No auth or no user, allow
  }

  return authSystem.authzManager.canAccessTerminal(user, terminalId, terminalOwner);
}

/**
 * Print help for Backstage authentication options
 */
function printBackstageAuthHelp() {
  console.log('\nBackstage Authentication Options:');
  console.log('  --backstage-url <url>              Backstage base URL (required for auth)');
  console.log('  --backstage-jwks-path <path>       Path to JWKS endpoint (default: /api/auth/.well-known/jwks.json)');
  console.log('  --backstage-require-auth <bool>    Require authentication for all requests (default: false)');
  console.log('  --backstage-issuer <string>        Expected JWT issuer');
  console.log('  --backstage-audience <string>      Expected JWT audience');
  console.log('  --backstage-allowed-users <refs>   Comma-separated list of allowed user entity refs');
  console.log('  --backstage-allowed-groups <refs>  Comma-separated list of allowed group entity refs');
  console.log('  --backstage-rate-limit-max <num>   Max requests per window (default: 100)');
  console.log('  --backstage-rate-limit-window <ms> Rate limit window in milliseconds (default: 900000)');
  console.log('\nEnvironment Variables:');
  console.log('  BACKSTAGE_URL                      Same as --backstage-url');
  console.log('  BACKSTAGE_REQUIRE_AUTH             Same as --backstage-require-auth');
  console.log('  BACKSTAGE_ISSUER                   Same as --backstage-issuer');
  console.log('  BACKSTAGE_AUDIENCE                 Same as --backstage-audience');
  console.log('  BACKSTAGE_ALLOWED_USERS            Same as --backstage-allowed-users');
  console.log('  BACKSTAGE_ALLOWED_GROUPS           Same as --backstage-allowed-groups');
  console.log('\nExample:');
  console.log('  claude-flow-ui --backstage-url https://backstage.example.com \\');
  console.log('    --backstage-require-auth true \\');
  console.log('    --backstage-allowed-users "user:default/admin" \\');
  console.log('    --backstage-allowed-groups "group:default/devops"');
}

module.exports = {
  parseBackstageAuthOptions,
  initializeBackstageAuth,
  applyExpressMiddleware,
  applyWebSocketMiddleware,
  getAuthenticatedUser,
  getSocketAuthenticatedUser,
  canAccessTerminal,
  printBackstageAuthHelp,
};
