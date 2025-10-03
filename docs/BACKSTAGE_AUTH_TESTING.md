# Testing Backstage Authentication

This guide shows how to test that Backstage authentication is properly enforcing access control.

## Testing Setup

### 1. Enable Authentication

```bash
export BACKSTAGE_URL="https://backstage.example.com"
export BACKSTAGE_REQUIRE_AUTH="true"
export BACKSTAGE_ALLOWED_GROUPS="group:default/platform-team"

npx claude-flow-ui
```

**Expected console output:**
```
🔐 Backstage Authentication Configuration:
   URL: https://backstage.example.com
   JWKS Path: /api/auth/.well-known/jwks.json
   Allowed Groups: group:default/platform-team
   Authentication Required: true
   Rate Limit: 100 requests per 15 minutes
🔒 Initializing Backstage authentication middleware...
✅ Backstage authentication middleware enabled
```

## Test Cases

### Test 1: Frontend Route Without Token (Should Fail)

```bash
curl -v http://localhost:8080/
```

**Expected Result:**
- HTTP 401 Unauthorized
- Response body:
```json
{
  "error": "Authentication required",
  "message": "Please provide a valid JWT token in the Authorization header"
}
```

### Test 2: API Route Without Token (Should Fail)

```bash
curl -v http://localhost:8080/api/health
```

**Expected Result:**
- HTTP 401 Unauthorized
- Response body:
```json
{
  "error": "Authentication required",
  "message": "Missing or invalid authorization header"
}
```

### Test 3: WebSocket Connection Without Token (Should Fail)

```javascript
// Using Socket.IO client
const socket = io('http://localhost:8080', {
  path: '/api/ws'
  // No auth token provided
});

socket.on('connect', () => {
  console.log('Connected'); // Should NOT reach here
});

socket.on('auth-error', (error) => {
  console.error('Auth error:', error);
  // Expected: { error: 'Authentication required', message: 'Please provide a valid JWT token' }
});

socket.on('disconnect', () => {
  console.log('Disconnected'); // Should reach here immediately
});
```

**Expected Result:**
- `auth-error` event emitted
- Socket immediately disconnected
- Console shows:
```
[WS Auth] Connection rejected - no token provided (socket: XXXXX)
```

### Test 4: Valid Token (Should Succeed)

First, get a valid JWT token from Backstage:
```bash
# Example - replace with your actual method of getting a token
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlZmF1bHQifQ..."
```

**Test API endpoint:**
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/health
```

**Expected Result:**
- HTTP 200 OK
- Response body:
```json
{
  "status": "ok",
  "timestamp": "2025-10-02T20:00:00.000Z",
  "services": {
    "api": "running",
    "websocket": "running",
    "terminal": "running"
  }
}
```

**Test frontend route:**
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/
```

**Expected Result:**
- HTTP 200 OK
- HTML content served

**Test WebSocket:**
```javascript
const socket = io('http://localhost:8080', {
  path: '/api/ws',
  auth: {
    token: 'YOUR_JWT_TOKEN_HERE'
  }
});

socket.on('connect', () => {
  console.log('Connected successfully!'); // Should reach here
});

socket.on('auth-error', (error) => {
  console.error('Should not reach here:', error);
});
```

**Expected Console Output:**
```
[WS Auth] Connection authenticated - user: user:default/jane.doe (socket: XXXXX)
```

### Test 5: Expired Token (Should Fail)

```bash
# Use an expired token
EXPIRED_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlZmF1bHQifQ..."

curl -H "Authorization: Bearer $EXPIRED_TOKEN" http://localhost:8080/api/health
```

**Expected Result:**
- HTTP 401 Unauthorized
- Response body:
```json
{
  "error": "EXPIRED_TOKEN",
  "message": "Token has expired"
}
```

### Test 6: Invalid Signature (Should Fail)

```bash
# Tamper with a valid token (change a few characters)
INVALID_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlZmF1bHQifQ.TAMPERED..."

curl -H "Authorization: Bearer $INVALID_TOKEN" http://localhost:8080/api/health
```

**Expected Result:**
- HTTP 401 Unauthorized
- Response body:
```json
{
  "error": "INVALID_TOKEN",
  "message": "Invalid token signature"
}
```

### Test 7: Unauthorized User (Valid Token, Wrong Group)

```bash
# Use a valid token for a user NOT in the allowed groups
TOKEN_WRONG_GROUP="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlZmF1bHQifQ..."

curl -H "Authorization: Bearer $TOKEN_WRONG_GROUP" http://localhost:8080/api/health
```

**Expected Result:**
- HTTP 403 Forbidden
- Response body:
```json
{
  "error": "AUTHORIZATION_FAILED",
  "message": "User not in allowed users or groups"
}
```

**Expected Console Output:**
```
[Audit] authentication_failure: user:default/unauthorized-user (IP: 127.0.0.1)
```

### Test 8: Static Assets Should Load (No Auth Required)

```bash
curl http://localhost:8080/_next/static/css/app.css
```

**Expected Result:**
- HTTP 200 OK (or 404 if file doesn't exist)
- Static assets should NOT require authentication

### Test 9: Rate Limiting

```bash
# Send 101 requests rapidly
for i in {1..101}; do
  curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/health
done
```

**Expected Result:**
- First 100 requests: HTTP 200 OK
- 101st request: HTTP 429 Too Many Requests
- Response body:
```json
{
  "error": "Rate limit exceeded",
  "message": "Too many requests, please try again later"
}
```

**Expected Console Output:**
```
[Audit] rate_limit_exceeded: user:default/jane.doe (IP: 127.0.0.1)
```

## Testing Without Authentication (BACKSTAGE_REQUIRE_AUTH=false)

```bash
export BACKSTAGE_URL="https://backstage.example.com"
export BACKSTAGE_REQUIRE_AUTH="false"
export BACKSTAGE_ALLOWED_GROUPS="group:default/platform-team"

npx claude-flow-ui
```

**Expected console output:**
```
ℹ️  Backstage authentication configured but not required (BACKSTAGE_REQUIRE_AUTH=false)
   Requests without authentication will be allowed
```

### Test Without Auth Disabled

```bash
# Should work WITHOUT token
curl http://localhost:8080/api/health
curl http://localhost:8080/
```

**Expected Result:**
- HTTP 200 OK for both
- No authentication required

## Debugging Authentication Issues

### Enable Debug Logging

```bash
export DEBUG=true
export DEBUG_TMUX=true
export BACKSTAGE_REQUIRE_AUTH=true
export BACKSTAGE_URL="https://backstage.example.com"

npx claude-flow-ui
```

### Check Audit Logs

The server maintains an audit log of authentication events. Failed authentication attempts are logged with:
- Event type (authentication_failure, rate_limit_exceeded, etc.)
- User reference (if token was parseable)
- IP address
- Timestamp
- Reason for failure

### Common Issues

**Issue**: "Failed to load authentication middleware"
- **Cause**: Missing dependencies
- **Solution**: Run `npm install` to install `jsonwebtoken`, `jwks-rsa`, `node-fetch`

**Issue**: "JWKS fetch failed"
- **Cause**: Cannot reach Backstage JWKS endpoint
- **Solution**: Verify `BACKSTAGE_URL` is correct and accessible from the server

**Issue**: "Invalid issuer"
- **Cause**: JWT issuer doesn't match configured issuer
- **Solution**: Set `BACKSTAGE_ISSUER` to match your Backstage instance's issuer claim

**Issue**: "User not in allowed groups"
- **Cause**: User's groups don't match any allowed groups
- **Solution**: Verify `BACKSTAGE_ALLOWED_GROUPS` includes the user's groups, or add specific users with `BACKSTAGE_ALLOWED_USERS`

## Security Testing Checklist

- [ ] Frontend routes return 401 without token when auth is required
- [ ] API routes return 401 without token when auth is required
- [ ] WebSocket connections reject connections without token
- [ ] Static assets load without authentication
- [ ] Valid tokens allow access
- [ ] Expired tokens are rejected
- [ ] Invalid signatures are rejected
- [ ] Unauthorized users (wrong groups) are rejected with 403
- [ ] Rate limiting works (101st request is blocked)
- [ ] Audit logs capture failed authentication attempts
- [ ] Authentication can be disabled with BACKSTAGE_REQUIRE_AUTH=false

## Production Checklist

Before deploying to production:

- [ ] Set `BACKSTAGE_REQUIRE_AUTH=true`
- [ ] Configure `BACKSTAGE_URL` to production Backstage instance
- [ ] Set `BACKSTAGE_ISSUER` and `BACKSTAGE_AUDIENCE` for additional security
- [ ] Configure `BACKSTAGE_ALLOWED_GROUPS` or `BACKSTAGE_ALLOWED_USERS`
- [ ] Test all authentication scenarios
- [ ] Verify HTTPS is used (not HTTP)
- [ ] Set appropriate rate limits
- [ ] Monitor audit logs for security events
- [ ] Set up alerts for repeated authentication failures

## Example Environment Variables for Production

```bash
# Production Authentication Configuration
export BACKSTAGE_URL="https://backstage.company.com"
export BACKSTAGE_REQUIRE_AUTH="true"
export BACKSTAGE_ISSUER="backstage"
export BACKSTAGE_AUDIENCE="claude-flow-ui"
export BACKSTAGE_ALLOWED_GROUPS="group:default/platform-team,group:default/sre"
export BACKSTAGE_RATE_LIMIT_MAX="200"
export BACKSTAGE_RATE_LIMIT_WINDOW="600000"
export NODE_ENV="production"

npx claude-flow-ui
```
