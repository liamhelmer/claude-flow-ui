# Backstage JWT Authentication Implementation

## Overview

This document describes the Backstage JWT authentication implementation for claude-flow-ui. The implementation provides secure, enterprise-grade authentication using JSON Web Tokens (JWT) from Backstage.io.

## Architecture

### Components

1. **Type Definitions** (`src/types/backstage-auth.ts`)
   - TypeScript interfaces for configuration
   - JWT payload structure
   - Entity reference types
   - Error types

2. **JWKS Manager** (`src/services/jwks-manager.ts`)
   - Fetches JWKS from Backstage
   - Caches keys with TTL (1 hour default)
   - Auto-refresh on expiry
   - Retry logic with exponential backoff

3. **Token Validator** (`src/services/token-validator.ts`)
   - Extracts JWT from Authorization header
   - Verifies signature using JWKS
   - Validates all claims (exp, iss, aud, nbf)
   - Type-safe payload parsing

4. **Identity Resolver** (`src/services/identity-resolver.ts`)
   - Parses Backstage entity references
   - Maps user and group information
   - Authorization logic for access control

5. **Authentication Middleware** (`src/middleware/authentication.ts`)
   - Express middleware for API endpoints
   - WebSocket authentication handler
   - Rate limiting (100 req/15min default)
   - Audit logging

6. **Authorization Middleware** (`src/middleware/authorization.ts`)
   - Checks allowed users/groups
   - Resource ownership validation
   - Admin privilege checks

7. **Integration Layer** (`src/services/backstage-auth-integration.js`)
   - CLI option parsing
   - System initialization
   - Middleware application

## Configuration

### CLI Options

```bash
claude-flow-ui \
  --backstage-url https://backstage.example.com \
  --backstage-jwks-path /api/auth/.well-known/jwks.json \
  --backstage-require-auth true \
  --backstage-issuer backstage \
  --backstage-audience my-app \
  --backstage-allowed-users "user:default/admin,user:default/devops" \
  --backstage-allowed-groups "group:default/admins,group:default/devops" \
  --backstage-rate-limit-max 100 \
  --backstage-rate-limit-window 900000
```

### Environment Variables

```bash
BACKSTAGE_URL=https://backstage.example.com
BACKSTAGE_REQUIRE_AUTH=true
BACKSTAGE_ISSUER=backstage
BACKSTAGE_AUDIENCE=my-app
BACKSTAGE_ALLOWED_USERS=user:default/admin,user:default/devops
BACKSTAGE_ALLOWED_GROUPS=group:default/admins,group:default/devops
BACKSTAGE_JWKS_PATH=/api/auth/.well-known/jwks.json
BACKSTAGE_JWKS_TTL=3600000
BACKSTAGE_MAX_RETRY=3
BACKSTAGE_RATE_LIMIT_MAX=100
BACKSTAGE_RATE_LIMIT_WINDOW=900000
```

## Security Features

### JWT Validation

- ✅ Signature verification using JWKS public keys
- ✅ Expiration time (`exp`) validation
- ✅ Issuer (`iss`) validation
- ✅ Audience (`aud`) validation
- ✅ Not before (`nbf`) validation
- ✅ Clock skew tolerance (30 seconds)

### Rate Limiting

- 100 requests per 15 minutes per user/IP (configurable)
- Per-user and per-IP tracking
- Automatic cleanup of expired entries

### Audit Logging

- Authentication success/failure events
- Authorization decisions
- Rate limit violations
- WebSocket connection events
- All events stored in memory (last 10,000 events)

### Error Handling

- Generic error messages (no sensitive info disclosure)
- Detailed logging for debugging
- Proper HTTP status codes (401, 403, 429, 500)
- Constant-time string comparisons where needed

## Usage

### HTTP API Authentication

Clients must include a Bearer token in the Authorization header:

```bash
curl -H "Authorization: Bearer <jwt-token>" \
  http://localhost:11235/api/terminals
```

### WebSocket Authentication

Clients can provide the token in multiple ways:

1. **Handshake auth object:**
```javascript
const socket = io('http://localhost:11235', {
  path: '/api/ws',
  auth: {
    token: '<jwt-token>'
  }
});
```

2. **Query parameter:**
```javascript
const socket = io('http://localhost:11235', {
  path: '/api/ws',
  query: {
    token: '<jwt-token>'
  }
});
```

### Accessing User Information

In Express route handlers:

```javascript
app.get('/api/protected', (req, res) => {
  const user = req.user; // Attached by authentication middleware
  if (user) {
    res.json({
      userRef: stringifyEntityRef(user.userRef),
      groups: user.groupRefs.map(stringifyEntityRef)
    });
  }
});
```

In WebSocket handlers:

```javascript
io.on('connection', (socket) => {
  const user = socket.user; // Attached by authentication middleware
  if (user) {
    console.log(`User connected: ${stringifyEntityRef(user.userRef)}`);
  }
});
```

## Integration with unified-server.js

The authentication system integrates seamlessly with the existing unified-server.js:

1. **CLI Parsing**: Authentication options are parsed alongside existing options
2. **Middleware Application**: Applied before route handlers and WebSocket connections
3. **Terminal Ownership**: Terminals can be associated with authenticated users
4. **Access Control**: Authorization checks can validate terminal access

## Testing

### Manual Testing

1. **Without Authentication:**
```bash
# Should work without auth (if not required)
curl http://localhost:11235/api/health
```

2. **With Invalid Token:**
```bash
# Should return 401
curl -H "Authorization: Bearer invalid-token" \
  http://localhost:11235/api/terminals
```

3. **With Valid Token:**
```bash
# Should work if user is authorized
export TOKEN=$(backstage-token-generator)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:11235/api/terminals
```

### Unit Tests

Tests should cover:
- [ ] JWKS fetching and caching
- [ ] Token validation (valid, expired, invalid signature)
- [ ] Entity reference parsing
- [ ] Authorization logic (allowed users/groups)
- [ ] Rate limiting
- [ ] Middleware integration

## Monitoring

### Audit Logs

Access recent audit logs:

```javascript
const { authManager } = authSystem;
const recentLogs = authManager.getAuditLogs(100);
console.log(recentLogs);
```

### JWKS Cache Stats

Check JWKS cache status:

```javascript
const stats = authManager.jwksManager.getCacheStats();
console.log({
  cached: stats.cached,
  keysCount: stats.keysCount,
  expiresAt: new Date(stats.expiresAt)
});
```

## Troubleshooting

### JWKS Fetch Failures

**Problem**: Unable to fetch JWKS from Backstage
**Solutions**:
- Verify `--backstage-url` is correct
- Check network connectivity to Backstage
- Verify JWKS endpoint path
- Check Backstage logs for errors

### Token Validation Failures

**Problem**: Valid tokens are rejected
**Solutions**:
- Verify `--backstage-issuer` matches token `iss` claim
- Verify `--backstage-audience` matches token `aud` claim
- Check token expiration
- Verify clock synchronization

### Authorization Failures

**Problem**: Authenticated users cannot access resources
**Solutions**:
- Verify user entity reference format
- Check `--backstage-allowed-users` configuration
- Check `--backstage-allowed-groups` configuration
- Verify user's group memberships in Backstage

### Rate Limiting Issues

**Problem**: Users hitting rate limits unexpectedly
**Solutions**:
- Increase `--backstage-rate-limit-max`
- Adjust `--backstage-rate-limit-window`
- Check for client retry loops
- Review audit logs for patterns

## Performance Considerations

### JWKS Caching

- JWKS are cached for 1 hour by default
- Reduces latency for token validation
- Automatic refresh on expiry
- No manual cache management needed

### Rate Limiting

- In-memory tracking (no database required)
- Automatic cleanup of expired entries
- Minimal performance impact

### Audit Logging

- Keeps last 10,000 events in memory
- No disk I/O during normal operation
- Consider external logging for production

## Security Best Practices

1. **Always use HTTPS** for Backstage URL
2. **Enable `requireAuth`** for production deployments
3. **Use specific allowed users/groups** instead of allowing all
4. **Monitor audit logs** for suspicious activity
5. **Rotate JWKS keys regularly** in Backstage
6. **Keep dependencies updated** (jsonwebtoken, jwks-rsa)
7. **Use environment variables** for sensitive configuration

## Future Enhancements

Potential improvements for future versions:

- [ ] Persistent audit logging (database or file)
- [ ] Metrics endpoint for monitoring
- [ ] Admin API for runtime configuration changes
- [ ] Multi-tenancy support
- [ ] Fine-grained permission system
- [ ] Session management and revocation
- [ ] OAuth2/OIDC flow support
- [ ] Integration tests with mock Backstage

## Dependencies

- **jsonwebtoken**: ^9.0.2 - JWT validation
- **jwks-rsa**: ^3.2.0 - JWKS client
- **node-fetch**: ^2.7.0 - HTTP requests

## Files Created

```
src/
  types/
    backstage-auth.ts          # TypeScript type definitions
    backstage-auth.js          # Compiled JavaScript types
  services/
    jwks-manager.ts            # JWKS fetching and caching
    jwks-manager.js            # Compiled JavaScript
    token-validator.ts         # JWT token validation
    token-validator.js         # Compiled JavaScript
    identity-resolver.ts       # Entity reference parsing
    identity-resolver.js       # Compiled JavaScript
    backstage-auth-integration.js  # Integration layer for unified-server.js
  middleware/
    authentication.ts          # Authentication middleware
    authentication.js          # Compiled JavaScript
    authorization.ts           # Authorization middleware
    authorization.js           # Compiled JavaScript
```

## Support

For issues or questions:
- Check this documentation
- Review audit logs for errors
- Check Backstage authentication documentation
- File an issue on GitHub

## License

Same license as claude-flow-ui project.
