# Authentication Header and Rate Limit Fix

## Problems Fixed

### 1. Missing Authorization Headers in Frontend Requests

**Problem:** Frontend fetch requests to `/api/terminals`, `/api/terminals/spawn`, `/api/terminals/:id`, and `/api/terminal-config/:id` were not including the JWT token in the Authorization header, causing 401 errors when authentication was required.

**Root Cause:** Fetch calls were not using the `withAuthHeader` utility or manually adding the token from sessionStorage.

### 2. 429 Rate Limit Errors After Login

**Problem:** After successfully logging in, users immediately received 429 "Too many requests" errors.

**Root Cause:** The rate limiter was counting **all** authentication requests (both successful and failed) against the limit. After login with a valid token, the frequent polling and initial page load requests quickly exceeded the 100 requests per 15 minutes limit.

## Solutions Implemented

### Fix 1: Add Authorization Headers to All API Requests

Updated all frontend fetch calls to include the JWT token from sessionStorage:

#### Files Modified:

**1. `src/app/page.tsx`** (lines 63-71, 276-283)
```typescript
const response = await fetch('/api/terminals', {
  signal: controller.signal,
  headers: {
    'Cache-Control': 'no-cache',
    ...(typeof window !== 'undefined' && sessionStorage.getItem('backstage_jwt_token')
      ? { 'Authorization': `Bearer ${sessionStorage.getItem('backstage_jwt_token')}` }
      : {}),
  },
});
```

**2. `src/components/sidebar/TerminalSidebar.tsx`** (lines 45-53, 115-128, 158-166)
```typescript
// GET /api/terminals
const response = await fetch('/api/terminals', {
  headers: {
    'Cache-Control': 'no-cache',
    ...(typeof window !== 'undefined' && sessionStorage.getItem('backstage_jwt_token')
      ? { 'Authorization': `Bearer ${sessionStorage.getItem('backstage_jwt_token')}` }
      : {}),
  },
});

// POST /api/terminals/spawn
const response = await fetch('/api/terminals/spawn', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    ...(typeof window !== 'undefined' && sessionStorage.getItem('backstage_jwt_token')
      ? { 'Authorization': `Bearer ${sessionStorage.getItem('backstage_jwt_token')}` }
      : {}),
  },
});

// DELETE /api/terminals/:id
const response = await fetch(`/api/terminals/${id}`, {
  method: 'DELETE',
  headers: {
    ...(typeof window !== 'undefined' && sessionStorage.getItem('backstage_jwt_token')
      ? { 'Authorization': `Bearer ${sessionStorage.getItem('backstage_jwt_token')}` }
      : {}),
  },
});
```

**3. `src/services/terminal-config.ts`** (lines 121-131)
```typescript
const response = await fetch(url, {
  method: 'GET',
  headers: {
    'Content-Type': 'application/json',
    ...(typeof window !== 'undefined' && sessionStorage.getItem('backstage_jwt_token')
      ? { 'Authorization': `Bearer ${sessionStorage.getItem('backstage_jwt_token')}` }
      : {}),
  },
  signal: AbortSignal.timeout(5000),
});
```

### Fix 2: Rate Limit Only Failed Authentication Attempts

Modified the authentication middleware to only count failed authentication attempts against the rate limit, not successful ones.

**File:** `src/middleware/authentication.ts` (lines 156-202)

**Before:**
```typescript
// Check rate limit by IP (for ALL requests)
if (this.rateLimiter.checkLimit(ipAddress)) {
  throw new AuthenticationError('RATE_LIMIT_EXCEEDED', 'Too many requests', 429);
}

const authHeader = req.headers.authorization;
const user = await this.tokenValidator.validateAuthHeader(authHeader);

// Check rate limit by user (for ALL successful requests)
if (this.rateLimiter.checkLimit(userIdentifier)) {
  throw new AuthenticationError('RATE_LIMIT_EXCEEDED', 'Too many requests', 429);
}
```

**After:**
```typescript
const authHeader = req.headers.authorization;

// If auth not required and no token provided, skip
if (!this.config.requireAuth && !authHeader) {
  return next();
}

// Validate token
let user;
try {
  user = await this.tokenValidator.validateAuthHeader(authHeader);
} catch (authError) {
  // Only rate limit FAILED authentication attempts
  if (this.rateLimiter.checkLimit(ipAddress)) {
    this.auditLogger.log({
      event: 'rate_limit_exceeded',
      ipAddress,
      details: { path },
      success: false,
    });

    throw new AuthenticationError('RATE_LIMIT_EXCEEDED', 'Too many requests', 429);
  }

  // Re-throw the original auth error
  throw authError;
}

// Successful authentication - no rate limiting
req.user = user;
next();
```

**Why This is Better:**
- Rate limiting is designed to prevent **brute force attacks** (failed login attempts)
- Successful authenticated requests should not be rate limited
- Users with valid tokens can now make as many requests as needed
- Failed authentication attempts are still limited to 100 per 15 minutes per IP

## Rate Limiting Behavior

### Before Fix
- ❌ Both successful and failed requests counted
- ❌ Limit: 100 requests per 15 minutes total
- ❌ After login, polling + page loads = 429 errors

### After Fix
- ✅ Only failed authentication attempts counted
- ✅ Limit: 100 failed attempts per 15 minutes per IP
- ✅ Successful requests are unlimited
- ✅ Normal application usage never hits rate limit

## Configuration

Rate limiting can be configured via environment variables:

```bash
# Maximum failed attempts per window
BACKSTAGE_RATE_LIMIT_MAX=100

# Rate limit window in milliseconds (default: 900000 = 15 minutes)
BACKSTAGE_RATE_LIMIT_WINDOW=900000
```

## Testing

### Test 1: Successful Authentication
```bash
# Make 200 successful requests with valid token
for i in {1..200}; do
  curl -H "Authorization: Bearer $VALID_TOKEN" http://localhost:8080/api/terminals
done

# Expected: All requests succeed (no 429)
```

### Test 2: Failed Authentication
```bash
# Make 101 requests with invalid token
for i in {1..101}; do
  curl -H "Authorization: Bearer invalid" http://localhost:8080/api/terminals
done

# Expected: First 100 requests return 401, 101st returns 429
```

### Test 3: Login and Use Application
```bash
# Start server with auth
BACKSTAGE_URL=https://backstage.example.com \
BACKSTAGE_REQUIRE_AUTH=true \
npm start

# Login with valid token via UI
# Use application normally (multiple terminals, switching, polling)
# Expected: No 429 errors
```

## Security Impact

### No Security Degradation
- ✅ Failed authentication attempts are still rate limited
- ✅ Brute force attacks are still prevented
- ✅ 100 failed attempts per 15 minutes is still enforced
- ✅ Rate limiting is by IP address

### Improved Usability
- ✅ Authenticated users can use the application without artificial limits
- ✅ Polling and real-time updates work correctly
- ✅ No false positives for legitimate usage

## Related Files

- `src/app/page.tsx` - Main page with terminal list fetch
- `src/components/sidebar/TerminalSidebar.tsx` - Sidebar with polling
- `src/services/terminal-config.ts` - Terminal configuration service
- `src/middleware/authentication.ts` - Authentication middleware
- `src/middleware/authentication.js` - Compiled JavaScript (auto-generated)

## Related Documentation

- [Manual Token Login Guide](./MANUAL_TOKEN_LOGIN.md)
- [Authentication Login Dialog Fix](./AUTHENTICATION_LOGIN_DIALOG_FIX.md)
- [Backstage Authentication Configuration](./BACKSTAGE_AUTH_CONFIG.md)
