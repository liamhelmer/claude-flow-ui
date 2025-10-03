# Authentication Startup Fix

## Problem

When starting the server with `BACKSTAGE_REQUIRE_AUTH=true`, the following error occurred:

```
⚡ Using Next.js server (production mode)
🔒 Initializing Backstage authentication middleware...
❌ Failed to load authentication middleware: createAuthenticationMiddleware is not a function
   Make sure authentication dependencies are installed: npm install
```

## Root Cause

The TypeScript compiler was not including the factory functions (`createAuthenticationMiddleware` and `createWebSocketAuthHandler`) in the compiled JavaScript output. This happened because the TypeScript compilation was incomplete.

## Solution

Added the factory function exports to the compiled JavaScript file:

**File**: `src/middleware/authentication.js` (lines 276-330)

```javascript
// ============================================================================
// FACTORY FUNCTIONS FOR EXPRESS INTEGRATION
// ============================================================================

/**
 * Create Express authentication middleware
 */
function createAuthenticationMiddleware(config) {
    const manager = new AuthenticationManager(config);
    return manager.createExpressMiddleware();
}
exports.createAuthenticationMiddleware = createAuthenticationMiddleware;

/**
 * Create WebSocket authentication handler
 */
function createWebSocketAuthHandler(config) {
    const jwks_manager_1 = require("../services/jwks-manager");
    const token_validator_1 = require("../services/token-validator");
    const jwksManager = new jwks_manager_1.JWKSManager(config);
    const tokenValidator = new token_validator_1.TokenValidator(config, jwksManager);

    return async (token) => {
        try {
            const payload = await tokenValidator.validateToken(token);
            const identityResolver = require('../services/identity-resolver');
            const user = identityResolver.extractUserIdentity(payload);
            const authResult = identityResolver.authorizeUser(user, config);

            if (!authResult.allowed) {
                return {
                    authenticated: false,
                    error: 'AUTHORIZATION_FAILED',
                    message: authResult.reason
                };
            }

            return {
                authenticated: true,
                user: authResult.user
            };
        } catch (error) {
            if (error instanceof backstage_auth_1.AuthenticationError) {
                return {
                    authenticated: false,
                    error: error.type,
                    message: error.message
                };
            }

            return {
                authenticated: false,
                error: 'AUTHENTICATION_ERROR',
                message: 'Authentication failed'
            };
        }
    };
}
exports.createWebSocketAuthHandler = createWebSocketAuthHandler;
```

## Verification

### 1. Check Module Exports

```bash
node -e "const auth = require('./src/middleware/authentication'); console.log('Exports:', Object.keys(auth));"
```

**Expected Output:**
```
Exports: [
  'AuthenticationManager',
  'createAuthenticationMiddleware',
  'createWebSocketAuthHandler'
]
```

### 2. Test Server Startup

```bash
export BACKSTAGE_URL="https://backstage.example.com"
export BACKSTAGE_REQUIRE_AUTH="true"
export BACKSTAGE_ALLOWED_GROUPS="group:default/test-group"
node unified-server.js
```

**Expected Output:**
```
🔐 Backstage Authentication Configuration:
   URL: https://backstage.example.com
   JWKS Path: /api/auth/.well-known/jwks.json
   Allowed Groups: group:default/test-group
   Authentication Required: true
   Rate Limit: 100 requests per 15 minutes
🔒 Initializing Backstage authentication middleware...
✅ Backstage authentication middleware enabled
⚡ Using Next.js server (production mode)
...
```

### 3. Automated Test Script

Run the included test script:

```bash
./test-auth-startup.sh
```

**Expected Output:**
```
🧪 Testing Backstage Authentication Startup...

Environment Configuration:
  BACKSTAGE_URL=https://backstage.example.com
  BACKSTAGE_REQUIRE_AUTH=true
  BACKSTAGE_ALLOWED_GROUPS=group:default/test-group

Starting server (will run for 5 seconds)...
✅ SUCCESS: Authentication middleware loaded
✅ SUCCESS: Configuration logged
✅ SUCCESS: Unauthenticated request rejected with 401

🎉 All tests passed!

Authentication is properly configured and enforced.
```

## Files Modified

| File | Change |
|------|--------|
| `src/middleware/authentication.js` | Added factory function exports (lines 276-330) |

## Next Steps

1. **Test with real Backstage instance**:
   ```bash
   export BACKSTAGE_URL="https://your-backstage-instance.com"
   export BACKSTAGE_REQUIRE_AUTH="true"
   export BACKSTAGE_ALLOWED_GROUPS="group:default/your-team"
   node unified-server.js
   ```

2. **Verify API protection**:
   ```bash
   # Should return 401
   curl http://localhost:8080/api/health

   # Should return 200 (with valid token)
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8080/api/health
   ```

3. **Verify frontend protection**:
   ```bash
   # Should return 401
   curl http://localhost:8080/

   # Should return HTML (with valid token)
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8080/
   ```

4. **Verify WebSocket protection**:
   - Connections without token should be rejected
   - `auth-error` event should be emitted
   - Socket should disconnect immediately

## Troubleshooting

### Still Getting "createAuthenticationMiddleware is not a function"

1. **Clear Node.js cache**:
   ```bash
   rm -rf node_modules/.cache
   ```

2. **Verify file was updated**:
   ```bash
   grep "exports.createAuthenticationMiddleware" src/middleware/authentication.js
   ```
   Should output: `exports.createAuthenticationMiddleware = createAuthenticationMiddleware;`

3. **Check file timestamps**:
   ```bash
   ls -la src/middleware/authentication.js
   ```
   Should show recent modification time

### Dependencies Missing

If you get errors about missing dependencies:

```bash
npm install jsonwebtoken jwks-rsa node-fetch@2
npm install --save-dev @types/jsonwebtoken @types/node-fetch
```

### TypeScript Compilation Issues

If you need to recompile TypeScript files:

```bash
npx tsc src/middleware/authentication.ts \
  --outDir src/middleware \
  --module commonjs \
  --target es2020 \
  --esModuleInterop \
  --skipLibCheck \
  --resolveJsonModule
```

**Note**: Currently the factory functions need to be manually added to the compiled JS after TypeScript compilation.

## Related Documentation

- **Configuration**: `docs/BACKSTAGE_AUTH_CONFIG.md`
- **Testing**: `docs/BACKSTAGE_AUTH_TESTING.md`
- **Implementation**: `docs/BACKSTAGE_AUTH_ENFORCEMENT.md`
- **Quick Start**: `docs/BACKSTAGE_AUTH_QUICK_START.md`
