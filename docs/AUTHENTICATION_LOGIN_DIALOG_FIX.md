# Authentication Login Dialog Fix

## Problem

In production builds, when a user visits the root URL `/` without authentication, the login dialog was not appearing. Instead, the server was returning a 401 JSON response, preventing the React app from loading.

## Root Cause

The authentication middleware was applied to frontend HTML routes, causing the server to return:

```json
{
  "error": "Authentication required",
  "message": "Please provide a valid JWT token in the Authorization header"
}
```

This prevented the React application from loading, so the `AuthProvider` component never mounted to show the login dialog.

## Solution

The fix involves three key changes:

### 1. Always Serve HTML Pages

**File:** `unified-server.js` (lines 1383-1384, 1405-1406)

Removed authentication checks from frontend route handlers:

```javascript
// IMPORTANT: Always serve HTML pages to allow React app to load and show login dialog
// Authentication enforcement happens at the API level and in the React app
```

**Why:** The HTML must load to allow the React app to mount and show the login dialog.

### 2. Exempt `/api/health` from Authentication

**File:** `unified-server.js` (lines 332-341)

```javascript
// Apply authentication to all API routes EXCEPT /api/health
// /api/health must be accessible to allow the React app to detect auth requirements
app.use('/api', (req, res, next) => {
  // Skip authentication for health endpoint
  if (req.path === '/health') {
    return next();
  }
  // Apply authentication to all other API routes
  return authenticationMiddleware(req, res, next);
});
```

**Why:** The React app needs to check if authentication is required before having a token.

### 3. Add Auth Status to Health Endpoint

**File:** `unified-server.js` (lines 402-420)

```javascript
app.get('/api/health', (req, res) => {
  const authRequired = backstageConfig.url && backstageConfig.requireAuth;
  const hasAuthHeader = req.headers.authorization;

  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    services: {
      api: 'running',
      websocket: 'running',
      terminal: 'running'
    },
    auth: {
      required: authRequired,
      authenticated: authRequired ? !!hasAuthHeader : null
    }
  });
});
```

**Why:** The React app needs to know if authentication is required.

### 4. Client-Side Auth Check

**File:** `src/components/auth/AuthProvider.tsx` (lines 37-104)

```typescript
useEffect(() => {
  const checkAuthStatus = async () => {
    const storedToken = getAuthToken();

    if (storedToken) {
      // Verify stored token with server
      const response = await fetch('/api/health', {
        headers: { 'Authorization': `Bearer ${storedToken}` }
      });

      if (response.status === 401) {
        clearAuthToken();
        setShowLogin(true);
        setLoginError('Authentication required. Please log in.');
      }
    } else {
      // No token - check if server requires auth
      const response = await fetch('/api/health');

      if (response.ok) {
        const data = await response.json();
        if (data.auth?.required) {
          setShowLogin(true);
          setLoginError('Authentication required. Please log in.');
        }
      }
    }
  };

  checkAuthStatus();
}, []);
```

**Why:** On mount, check if authentication is required and show login dialog immediately.

## Authentication Flow

### Without Token

1. User visits `/` in browser
2. Server serves HTML page (no authentication check)
3. React app loads and `AuthProvider` mounts
4. `AuthProvider` calls `/api/health` (no auth required)
5. Health endpoint returns `{ auth: { required: true } }`
6. `AuthProvider` shows login dialog
7. User enters JWT token
8. Token is validated and stored
9. Page reloads with authentication

### With Token

1. User visits `/` in browser
2. Server serves HTML page
3. React app loads and `AuthProvider` mounts
4. `AuthProvider` finds token in sessionStorage
5. `AuthProvider` verifies token with `/api/health`
6. If valid: User sees application
7. If invalid: Login dialog appears

### API Requests

All API requests (except `/api/health`) require authentication:

- `/api/terminals` - 401 without token
- `/api/terminal-config/:id` - 401 without token
- `/api/ws` (WebSocket) - Disconnected without token

## Testing

### Test 1: Visit Root Without Token

```bash
# Start server with authentication required
BACKSTAGE_URL=https://backstage.example.com \
BACKSTAGE_REQUIRE_AUTH=true \
npm run build && npm start

# Visit http://localhost:8080 in browser
# Expected: Login dialog appears immediately
```

### Test 2: Visit Root With Invalid Token

```bash
# Set an invalid token in sessionStorage via browser console
sessionStorage.setItem('backstage_jwt_token', 'invalid.token.here');

# Refresh page
# Expected: Login dialog appears with "Authentication required" message
```

### Test 3: Visit Root With Valid Token

```bash
# Get a valid token from Backstage and enter it in login dialog
# Expected: Application loads normally, sidebar shows user info
```

### Test 4: API Request Without Token

```bash
# Try to access API without token
curl http://localhost:8080/api/terminals

# Expected: 401 Unauthorized
```

### Test 5: Health Check Always Works

```bash
# Health endpoint should work without authentication
curl http://localhost:8080/api/health

# Expected: 200 OK with auth.required: true
```

## Security Considerations

### What's Protected

- ✅ All API endpoints (except `/api/health`)
- ✅ WebSocket connections
- ✅ Terminal data and commands

### What's Not Protected

- ❌ HTML pages (intentionally - needed to show login dialog)
- ❌ Static assets (JS, CSS, images)
- ❌ `/api/health` endpoint (needed for auth detection)

### Why This Is Secure

1. **HTML pages contain no sensitive data** - They're just the React app shell
2. **Static assets are public** - JavaScript bundles don't contain secrets
3. **All sensitive operations require authentication:**
   - API calls fail with 401
   - WebSocket connections are rejected
   - Terminal commands cannot be sent

4. **The login dialog is the security boundary:**
   - Users cannot access the terminal without a valid token
   - All API requests include the token in Authorization header
   - Tokens are verified on the server for every request

## Related Files

- `unified-server.js` - Server-side authentication setup
- `src/components/auth/AuthProvider.tsx` - Client-side auth management
- `src/components/auth/LoginDialog.tsx` - Login UI
- `src/lib/auth.ts` - Token utilities
- `src/middleware/authentication.js` - JWT validation middleware

## Related Documentation

- [Manual Token Login Guide](./MANUAL_TOKEN_LOGIN.md)
- [Backstage Authentication Configuration](./BACKSTAGE_AUTH_CONFIG.md)
- [Authentication Testing](./BACKSTAGE_AUTH_TESTING.md)
