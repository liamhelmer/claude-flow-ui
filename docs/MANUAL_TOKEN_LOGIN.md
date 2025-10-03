# Manual Token Login

This document describes how to use the manual token login feature in Claude Flow UI when authentication is required.

## Overview

When Claude Flow UI is configured with Backstage JWT authentication enabled (`BACKSTAGE_REQUIRE_AUTH=true` and `BACKSTAGE_URL` is set), users must provide a valid JWT Bearer token to access the application.

If you encounter an authentication error or your session expires, the application will automatically present a login dialog where you can manually enter your JWT token.

## Getting Your JWT Token from Backstage

To obtain your JWT token from Backstage:

1. **Open your Backstage instance** in your browser
2. **Open Browser DevTools** (press F12 or right-click → Inspect)
3. **Navigate to the Application tab** (Chrome) or Storage tab (Firefox)
4. **Go to Local Storage** and select your Backstage domain
5. **Find the authentication token** - Look for a key containing "token" or "auth"
6. **Copy the token value** (it should be in the format: `eyJhbGciOiJSUzI1NiIsInR5cCI6...`)

## Using the Login Dialog

When the login dialog appears:

1. **Enter or paste your JWT token** into the text area
   - You can click the "Paste" button to paste from clipboard
   - Or manually paste using Ctrl+V / Cmd+V

2. **Click the "Login" button**
   - The application will validate your token against the backend
   - If valid, you'll be logged in and the page will reload
   - If invalid, an error message will be displayed

3. **If you see an error:**
   - Verify the token format (should have 3 parts separated by dots)
   - Ensure the token hasn't expired
   - Get a fresh token from Backstage if needed

## Token Storage

- Tokens are stored in **sessionStorage** (not localStorage)
- Tokens are **automatically cleared** when you close the browser tab
- Tokens are **cleared on logout** or when a 401/auth error occurs

## Token Validation

The login dialog performs several checks:

1. **Format validation** - Ensures the token has the correct JWT format (header.payload.signature)
2. **Expiration check** - Verifies the token hasn't expired (client-side only)
3. **Server validation** - Tests the token against the `/api/health` endpoint
4. **Permission check** - Verifies you have the required groups/permissions

## Authentication Flow

### HTTP Requests
All HTTP requests to `/api/*` endpoints automatically include the token in the Authorization header:
```
Authorization: Bearer <your-token>
```

### WebSocket Connections
WebSocket connections to `/api/ws` pass the token during the handshake:
```javascript
{
  auth: {
    token: '<your-token>'
  }
}
```

### Frontend Routes
HTML routes are protected and return 401 if authentication is required but no valid token is present.

## Logout

To log out:

1. **Click the logout button** in the sidebar (if visible)
   - Located at the bottom of the terminal list
   - Shows your username/email with a logout icon

2. **What happens on logout:**
   - Your token is cleared from sessionStorage
   - The page reloads
   - You'll see the login dialog again (if auth is required)

## Troubleshooting

### "Authentication required" error
- **Cause**: No token provided or token is missing
- **Solution**: Enter a valid JWT token from Backstage

### "Your session has expired"
- **Cause**: Token has expired (checked via `exp` claim)
- **Solution**: Get a fresh token from Backstage

### "Invalid token"
- **Cause**: Token format is incorrect or signature verification failed
- **Solution**: Verify you copied the complete token, including all three parts

### "You do not have permission"
- **Cause**: Your user/groups don't match the allowed users/groups configured in the server
- **Solution**: Contact your administrator to grant you access

### "WebSocket authentication failed"
- **Cause**: Token is invalid or expired when establishing WebSocket connection
- **Solution**: The login dialog will appear automatically - enter a fresh token

## Server Configuration

The manual token login works with these server configuration options:

- `BACKSTAGE_URL` - Backstage instance URL for JWKS validation
- `BACKSTAGE_REQUIRE_AUTH` - Set to `true` to require authentication
- `BACKSTAGE_ALLOWED_USERS` - Comma-separated list of allowed user IDs
- `BACKSTAGE_ALLOWED_GROUPS` - Comma-separated list of allowed groups
- `BACKSTAGE_JWT_ISSUER` - Expected issuer claim in the JWT
- `BACKSTAGE_JWT_AUDIENCE` - Expected audience claim in the JWT

See [BACKSTAGE_AUTH_CONFIG.md](./BACKSTAGE_AUTH_CONFIG.md) for complete server configuration details.

## Security Best Practices

1. **Never share your JWT token** - It provides full access to your account
2. **Don't store tokens in bookmarks or URLs** - They're stored securely in sessionStorage
3. **Log out when done** - Especially on shared computers
4. **Use HTTPS** - Ensures tokens are encrypted in transit
5. **Tokens expire** - Get fresh tokens periodically, don't reuse old ones

## API Reference

### Auth Context Provider

The `AuthProvider` component wraps the application and provides authentication context:

```tsx
import { useAuth } from '@/components/auth/AuthProvider';

const { isAuthenticated, token, userInfo, login, logout, showLoginDialog } = useAuth();
```

**Properties:**
- `isAuthenticated: boolean` - Whether user is currently authenticated
- `token: string | null` - Current JWT token
- `userInfo: object | null` - Parsed user info from token (name, email, sub)
- `login: (token: string) => Promise<void>` - Function to log in with a token
- `logout: () => void` - Function to log out and clear token
- `showLoginDialog: () => void` - Function to manually show the login dialog

### Auth Utilities

```tsx
import {
  getAuthToken,
  setAuthToken,
  clearAuthToken,
  isAuthenticated,
  isTokenExpired,
  getUserInfo,
  withAuthHeader,
  authenticatedFetch
} from '@/lib/auth';
```

## Examples

### Manually Show Login Dialog

```tsx
import { useAuth } from '@/components/auth/AuthProvider';

function MyComponent() {
  const { showLoginDialog } = useAuth();

  const handleNeedAuth = () => {
    showLoginDialog();
  };

  return <button onClick={handleNeedAuth}>Login</button>;
}
```

### Make Authenticated Request

```tsx
import { authenticatedFetch } from '@/lib/auth';

async function fetchData() {
  const response = await authenticatedFetch('/api/data');
  const data = await response.json();
  return data;
}
```

### Check Auth Status

```tsx
import { useAuth } from '@/components/auth/AuthProvider';

function MyComponent() {
  const { isAuthenticated, userInfo } = useAuth();

  if (!isAuthenticated) {
    return <div>Please log in</div>;
  }

  return <div>Welcome, {userInfo.name}!</div>;
}
```

## Related Documentation

- [Backstage Authentication Configuration](./BACKSTAGE_AUTH_CONFIG.md)
- [Backstage Authentication Quick Start](./BACKSTAGE_AUTH_QUICK_START.md)
- [Authentication Enforcement](./BACKSTAGE_AUTH_ENFORCEMENT.md)
- [Testing Guide](./BACKSTAGE_AUTH_TESTING.md)
